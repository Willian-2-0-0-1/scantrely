"""Ajustes vindos da análise de um scan real (15/10/2026): DNS curinga, httpx parcial,
gowitness, prazos internos dos módulos, falsos positivos e status da fila por domínio."""
import time
import types
from pathlib import Path

import pytest

import core.pipeline as P
import core.reconlib.base as base
import core.reconlib.dnsutil as dnsutil
import core.reconlib.infra as infra


# ── DNS curinga ──────────────────────────────────────────────────────────────
WILD = {"104.26.8.157", "104.26.9.157", "172.67.75.47"}


def _fake_dns(monkeypatch, real: dict[str, set[str]], wildcard_zones: dict[str, set[str]]):
    def resolve(name):
        if name in real:
            return real[name]
        parent = name.split(".", 1)[1]
        while parent:
            if parent in wildcard_zones:
                return wildcard_zones[parent]
            parent = parent.split(".", 1)[1] if "." in parent else ""
        return set()
    monkeypatch.setattr(dnsutil, "_resolve_ips", resolve)


def test_wildcard_hits_are_dropped_and_own_ip_hosts_kept(monkeypatch):
    _fake_dns(monkeypatch, real={"vpn.x.com": {"9.9.9.9"}}, wildcard_zones={"x.com": WILD})
    resolved = [{"host": "admin.x.com", "ip": "104.26.8.157"},
                {"host": "jenkins.x.com", "ip": ""},
                {"host": "vpn.x.com", "ip": "9.9.9.9"}]
    kept, zones = dnsutil.drop_wildcard_hits(resolved, "x.com")
    assert [r["host"] for r in kept] == ["vpn.x.com"]
    assert set(zones) == {"x.com"}


def test_no_wildcard_keeps_everything(monkeypatch):
    _fake_dns(monkeypatch, real={}, wildcard_zones={})
    resolved = [{"host": "a.x.com", "ip": "1.1.1.1"}, {"host": "b.x.com", "ip": "2.2.2.2"}]
    kept, zones = dnsutil.drop_wildcard_hits(resolved, "x.com")
    assert kept == resolved and zones == {}


def test_nested_wildcard_zone(monkeypatch):
    # *.internal.x.com é curinga, x.com não
    _fake_dns(monkeypatch, real={"internal.x.com": {"5.5.5.5"}}, wildcard_zones={"internal.x.com": {"7.7.7.7"}})
    resolved = [{"host": "cube.internal.x.com", "ip": "7.7.7.7"}, {"host": "api.x.com", "ip": "3.3.3.3"}]
    kept, zones = dnsutil.drop_wildcard_hits(resolved, "x.com")
    assert [r["host"] for r in kept] == ["api.x.com"]
    assert list(zones) == ["internal.x.com"]


# ── run_bounded ──────────────────────────────────────────────────────────────
def test_run_bounded_returns_partial_after_budget():
    out = []

    def work(i):
        if i == 0:
            time.sleep(2)
        out.append(i)

    t = time.time()
    complete = base.run_bounded(work, range(4), workers=4, budget=0.5, label="t")
    assert complete is False
    assert time.time() - t < 1.5
    assert sorted(out) == [1, 2, 3]


def test_run_bounded_swallows_item_errors():
    out = []

    def work(i):
        if i == 1:
            raise RuntimeError("boom")
        out.append(i)

    assert base.run_bounded(work, [0, 1, 2], workers=2, budget=5) is True
    assert sorted(out) == [0, 2]


# ── falsos positivos ────────────────────────────────────────────────────────
def test_waf_bypass_ignores_network_failures(monkeypatch):
    # baseline 403; todas as variações falham (status 0) → nada de "bypass"
    calls = iter([(403, b"blocked", {})] + [(0, b"", {})] * 20)
    monkeypatch.setattr(infra, "http_get", lambda *a, **k: next(calls))
    out = infra.run_waf_bypass_test([{"host": "a.x.com", "waf": "Cloudflare", "status_code": 403}])
    assert out["findings"] == []
    assert out["total_tested"] == 1


def test_waf_bypass_real_status_change_still_reported(monkeypatch):
    calls = iter([(403, b"blocked", {}), (200, b"ok" * 100, {})])
    monkeypatch.setattr(infra, "http_get", lambda *a, **k: next(calls))
    out = infra.run_waf_bypass_test([{"host": "a.x.com", "waf": "Cloudflare", "status_code": 403}])
    assert len(out["findings"]) == 1


def test_infra_exposure_reads_status_body_in_right_order(monkeypatch):
    class _Sock:
        def __init__(self, *a): pass
        def settimeout(self, t): pass
        def connect_ex(self, addr): return 0 if addr[1] == 2375 else 1
        def close(self): pass

    import socket
    monkeypatch.setattr(socket, "socket", _Sock)
    monkeypatch.setattr(infra, "http_get", lambda url, **k: (200, b'{"ApiVersion":"1.41"}', {}))
    out = infra.run_infra_exposure([{"host": "a.x.com", "ip": "10.0.0.5"}])
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["port"] == 2375 and f["open_paths"][0]["status"] == 200
    assert "ApiVersion" in f["open_paths"][0]["preview"]


def test_host_header_injection_gives_up_on_dead_host(monkeypatch):
    seen = []
    monkeypatch.setattr(infra, "http_get", lambda url, **k: seen.append(url) or (0, b"", {}))
    out = infra.run_host_header_injection([{"host": "a.x.com", "status_code": 200}])
    assert out["findings"] == [] and len(seen) == 2


# ── gowitness ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("host,expected", [
    ({"host": "a.x.com", "ports": ["443", "80"]}, "https://a.x.com:443"),
    ({"host": "a.x.com", "ports": ["80"]}, "http://a.x.com:80"),
    ({"host": "a.x.com", "ports": ["80"], "redirect_url": "https://a.x.com/"}, "https://a.x.com:443"),
    ({"host": "a.x.com", "ports": []}, "https://a.x.com:443"),
])
def test_gowitness_target_is_one_explicit_url(host, expected):
    assert P._gowitness_target(host) == expected


# ── httpx: resultado parcial em timeout ──────────────────────────────────────
def _runner(tmp_path, db=None):
    return P.ReconRunner(db=db, base_dir=tmp_path, get_settings=lambda: {}, load_hosts_fn=lambda cid: [],
                         recon_module=None, recon_available=False)


def test_httpx_timeout_keeps_partial_output(tmp_path, monkeypatch):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "httpx").write_text("")
    monkeypatch.setattr(P, "BIN_DIR", fake_bin)

    def fake_run(cmd, **kw):
        out = Path(cmd[cmd.index("-o") + 1])
        assert "-stream" in cmd
        out.write_text('{"input":"a.x.com","scheme":"https","status_code":200,"title":"A"}\n')
        raise P._subprocess_real.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(P.subprocess, "run", fake_run)
    r = _runner(tmp_path)
    monkeypatch.setattr(r, "_company_domains", lambda cid: [])
    live = r._probe_hosts_with_httpx(["a.x.com", "b.x.com"], "co")
    assert [h["host"] for h in live] == ["a.x.com"]
    assert live[0]["status_code"] == 200


# ── fila por domínio: status só fecha no último ──────────────────────────────
class _JobsDB:
    def __init__(self, active):
        self.active = set(active)

    def list_active_job_targets(self, *, company_id, job_type="pipeline"):
        return set(self.active)


def test_first_domain_to_finish_does_not_close_pipeline(tmp_path):
    db = _JobsDB({"a.example", "b.example"})
    r = _runner(tmp_path, db)
    assert r._other_queue_domains_pending("co", "a.example") == {"b.example"}
    # a.example ainda aparece como running no banco até run_pipeline voltar
    assert r._other_queue_domains_pending("co", "b.example") == set()


def test_domain_still_queued_keeps_pipeline_running(tmp_path):
    # 1 worker: b.example ainda pendente quando a.example termina
    r = _runner(tmp_path, _JobsDB({"a.example", "b.example"}))
    assert r._other_queue_domains_pending("co", "a.example") == {"b.example"}


def test_single_job_run_is_unaffected(tmp_path):
    r = _runner(tmp_path, _JobsDB({"other.com"}))
    assert r._other_queue_domains_pending("co", "") == set()


# ── curinga por resposta HTTP (canário) ──────────────────────────────────────
def _fp(status=404, title="404 Not Found", words=10, lines=8, md5=""):
    return {"status": status, "title": title, "words": words, "lines": lines, "md5": md5}


def test_same_response_tolerates_small_dynamic_changes():
    assert P._same_response(_fp(words=1000, lines=100), _fp(words=1010, lines=101))
    assert not P._same_response(_fp(words=1000), _fp(words=1200))
    assert not P._same_response(_fp(title="A"), _fp(title="B"))
    assert P._same_response(_fp(words=1, md5="h"), _fp(words=999, md5="h"))


def test_wildcard_match_uses_pool_from_all_ports_and_parent_zones():
    canary = {"x.com": [_fp(words=10)], "stg.x.com": [_fp(words=76, lines=14)]}
    # 443 bate com o curinga de x.com e 80 com o de stg.x.com: o balanceador alterna páginas
    assert P._matches_wildcard("mail.stg.x.com", {"443": _fp(words=10), "80": _fp(words=76, lines=14)}, canary)
    # uma resposta própria em qualquer porta mantém o host
    assert not P._matches_wildcard("app.stg.x.com", {"443": _fp(words=10), "8443": _fp(200, "App", 500, 40)}, canary)
    assert not P._matches_wildcard("a.other.com", {"443": _fp()}, canary)


def _fake_httpx(tmp_path, monkeypatch, by_stage):
    """by_stage: {'80,443': [linhas], 'extra': [linhas]}; registra os alvos de cada etapa."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    (fake_bin / "httpx").write_text("")
    monkeypatch.setattr(P, "BIN_DIR", fake_bin)
    seen = {}

    def fake_run(cmd, **kw):
        ports = cmd[cmd.index("-ports") + 1]
        stage = "80,443" if ports == "80,443" else "extra"
        seen[stage] = Path(cmd[cmd.index("-l") + 1]).read_text().split()
        rows = [r for r in by_stage.get(stage, []) if r["input"] in seen[stage]]
        Path(cmd[cmd.index("-o") + 1]).write_text("".join(__import__("json").dumps(r) + "\n" for r in rows))

    monkeypatch.setattr(P.subprocess, "run", fake_run)
    return seen


def test_extra_ports_only_off_cdn_and_real_port_recorded(tmp_path, monkeypatch):
    seen = _fake_httpx(tmp_path, monkeypatch, {
        "80,443": [{"input": "cdn.x.com", "port": "443", "status_code": 200, "cdn": True, "cdn_name": "cloudflare"},
                   {"input": "own.x.com", "port": "443", "status_code": 200}],
        "extra": [{"input": "own.x.com", "port": "8080", "status_code": 200}],
    })
    r = _runner(tmp_path)
    monkeypatch.setattr(r, "_wildcard_canaries", lambda names, cid: {})
    monkeypatch.setattr(r, "_company_domains", lambda cid: [])
    live = {h["host"]: h for h in r._probe_hosts_with_httpx(["cdn.x.com", "own.x.com", "dead.x.com"], "co")}
    assert seen["extra"] == ["own.x.com", "dead.x.com"]
    assert live["own.x.com"]["ports"] == ["443", "8080"]
    assert live["cdn.x.com"]["ports"] == ["443"]


def test_canary_drops_wildcard_pages_but_keeps_scope_and_real(tmp_path, monkeypatch):
    page = {"status_code": 404, "title": "404 Not Found", "words": 10, "lines": 8, "port": "443"}
    _fake_httpx(tmp_path, monkeypatch, {"80,443": [
        {"input": "sctw-1.x.com", **page},
        {"input": "junk.x.com", **page},
        {"input": "x.com", **page},
        {"input": "app.x.com", "status_code": 200, "title": "App", "words": 900, "lines": 50, "port": "443"},
    ]})
    r = _runner(tmp_path)
    monkeypatch.setattr(r, "_wildcard_canaries", lambda names, cid: {"sctw-1.x.com": "x.com"})
    monkeypatch.setattr(r, "_company_domains", lambda cid: ["x.com"])
    live = {h["host"] for h in r._probe_hosts_with_httpx(["junk.x.com", "x.com", "app.x.com"], "co")}
    assert live == {"x.com", "app.x.com"}


# ── cancelamento cooperativo ────────────────────────────────────────────────
def test_module_timeout_signals_cancel_to_the_abandoned_thread(tmp_path, monkeypatch):
    monkeypatch.setitem(P._MODULE_TIMEOUTS, "slow_mod", 1)
    seen = []

    def slow():
        time.sleep(1.5)
        seen.append(base.cancelled())
        seen.append(base.http_get("http://127.0.0.1:9/")[2].get("X-Cancelled"))

    out = _runner(tmp_path)._invoke_module("slow_mod", slow)
    assert out["status"] == "timeout"
    time.sleep(1)
    assert seen == [True, "1"]


def test_run_bounded_expiry_stops_in_flight_items():
    seen = []

    def work(i):
        time.sleep(0.6)
        seen.append(base.cancelled())

    assert base.run_bounded(work, [1], workers=1, budget=0.2) is False
    time.sleep(0.8)
    assert seen == [True]


# ── fontes passivas ─────────────────────────────────────────────────────────
def test_subfinder_uses_all_sources_without_crtsh_and_private_key_file():
    import os
    from utils.tools import registry
    t = registry.get("subfinder")
    cmd = t.command("x.com", {"settings": {"virustotal_key": "k"}})
    try:
        assert "-all" in cmd and cmd[cmd.index("-es") + 1] == "crtsh"
        assert oct(os.stat(t._tmp_cfg).st_mode & 0o777) == "0o600"
    finally:
        os.unlink(t._tmp_cfg)


def test_otx_key_comes_from_settings(monkeypatch):
    import contextlib, io
    from utils.tools import registry
    t = registry.get("alienvault_otx")
    sent = {}

    @contextlib.contextmanager
    def fake_open(url, headers=None, **kw):
        sent.update(headers or {})
        yield io.BytesIO(b'{"passive_dns": []}')

    monkeypatch.setattr(t, "_http_open", fake_open)
    t.run_api("x.com", {"settings": {"otx_key": "abc"}})
    assert sent["X-OTX-API-KEY"] == "abc"


# ── resolvedores do sistema (VPN com firewall estrito recusa 1.1.1.1/8.8.8.8) ──
def test_system_resolvers_read_resolv_conf(tmp_path):
    from utils.resolvers import system_resolvers
    conf = tmp_path / "resolv.conf"
    conf.write_text("# x\nnameserver 10.64.0.1\nnameserver 10.64.0.1\nsearch lan\n")
    assert system_resolvers(str(conf)) == ["10.64.0.1"]
    assert system_resolvers(str(tmp_path / "nao-existe")) == ["127.0.0.53"]


def test_tools_use_system_resolvers_not_public_lists():
    from utils.tools import registry
    from utils.resolvers import resolvers_file
    amass = registry.get("amass").command("x.com", {})
    assert amass[amass.index("-rf") + 1] == resolvers_file()
    assert str(registry.get("subjack")._ensure_resolvers()) == resolvers_file()
    dnsx = registry.get("dnsx").command("x.com", {})
    assert dnsx[dnsx.index("-r") + 1] == resolvers_file()


# ── takeover: crítico só com nome registrável ou assinatura ─────────────────
@pytest.mark.parametrize("cname,critical", [
    ("app-123.us-east-1.elb.amazonaws.com", False),   # ELB: ID aleatório, ninguém registra
    ("myapp.us-east-1.elasticbeanstalk.com", True),
    ("myapp.azurewebsites.net", True),
])
def test_dangling_cname_is_critical_only_when_claimable(monkeypatch, cname, critical):
    import core.reconlib.takeover as tk
    monkeypatch.setattr(tk, "_subp", lambda *a, **k: types.SimpleNamespace(stdout=cname + ".\n"))
    monkeypatch.setattr(tk, "_resolve_domain", lambda host: [])
    r = tk._check_takeover("old.x.com")
    assert r["takeover_possible"] is critical
    assert r["severity"] == ("critical" if critical else "info")


def test_takeover_scope_is_not_capped_by_active_hosts(tmp_path):
    hosts = [{"host": f"h{i}.x.com", "status_code": 200 if i < 5 else None} for i in range(100)]
    r = _runner(tmp_path)
    opts = {"profile": "bug_bounty", "active": True, "active_max_hosts": 40, "domains": ["x.com"]}
    assert len(r._filter_hosts_for_options(hosts, {"domains": ["x.com"]}, opts)) == 40
    assert len(r._filter_hosts_for_options(hosts, {"domains": ["x.com"]}, {**opts, "active_max_hosts": 0})) == 100


# ── param_mine (arjun) ───────────────────────────────────────────────────────
def test_param_mine_targets_first_live_200_host():
    hosts = [{"host": "edge.x.com", "status_code": 403, "ports": ["443"]},
             {"host": "app.x.com", "status_code": 200, "ports": ["443"]}]
    assert P._param_mine_target(hosts, "x.com") == "https://app.x.com:443"
    assert P._param_mine_target([{"host": "edge.x.com", "status_code": 403}], "x.com") == "x.com"


@pytest.mark.parametrize("payload", [
    {"http://a.x.com/": {"params": ["debug", "id"], "method": "GET", "headers": {}}},   # arjun 2.2.x
    {"results": [{"param": "debug"}, {"param": "id"}]},                                 # formato antigo
])
def test_arjun_parse_reads_current_and_old_format(tmp_path, payload):
    import json as _json
    from utils.tools import registry
    out = tmp_path / "a.json"
    out.write_text(_json.dumps(payload))
    names = [f.value for f in registry.get("arjun").parse("", "", "a.x.com", out=str(out))]
    assert names == ["debug", "id"]


def test_arjun_run_uses_private_output_and_bounded_command(monkeypatch):
    import json as _json
    import utils.tools as T
    seen = []

    def fake_run(cmd, **kw):
        out = cmd[cmd.index("-oJ") + 1]
        seen.append((cmd, out, kw.get("timeout")))
        Path(out).write_text(_json.dumps({"https://a.x.com/": {"params": ["debug"]}}))
        return types.SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(T.subprocess, "run", fake_run)
    tool = T.registry.get("arjun")
    r1, r2 = tool.run("a.x.com", {}), tool.run("b.x.com", {})
    (cmd, out1, timeout), (_, out2, _) = seen
    assert out1 != out2 and out1 != "/tmp/arjun_output.json"
    assert not Path(out1).exists()                       # limpo depois
    assert "--stable" not in cmd and cmd[cmd.index("-c") + 1] == "500"
    assert timeout < 180                                  # abaixo do módulo param_mine
    assert [f.value for f in r1.findings] == ["debug"] and [f.value for f in r2.findings] == ["debug"]


# ── api_discovery_extra ─────────────────────────────────────────────────────
def test_swagger_probe_reuses_scheme_and_skips_dead_hosts(monkeypatch):
    import core.reconlib.browser as br
    calls = []

    def fake_get(url, **kw):
        calls.append(url)
        if "dead.x.com" in url:
            return 0, b"", {}
        if url == "https://api.x.com/openapi.json":
            return 200, b'{"openapi": "3.0.0", "info": {"title": "API"}, "paths": {"/a": {}}}', {}
        return 404, b"", {}

    monkeypatch.setattr(br, "http_get", fake_get)
    found = br._run_kiterunner_on_hosts([{"host": "api.x.com"}, {"host": "dead.x.com"}])
    assert [(f["host"], f["url"], f["endpoints_count"]) for f in found] == [("api.x.com", "https://api.x.com/openapi.json", 1)]
    assert not any(u.startswith("http://api.x.com") for u in calls)        # esquema descoberto uma vez
    assert [u for u in calls if "dead.x.com" in u] == ["https://dead.x.com/swagger.json", "http://dead.x.com/swagger.json"]


# ── services ────────────────────────────────────────────────────────────────
def _services_get(routes):
    def fake_get(url, **kw):
        host, path = url.split("://", 1)[1].split("/", 1)
        return routes(host, "/" + path)
    return fake_get


def test_services_skips_dead_host_after_one_request(monkeypatch):
    import core.reconlib.services as sv
    calls = []
    monkeypatch.setattr(sv, "http_get", lambda url, **kw: calls.append(url) or (0, b"", {}))
    assert sv.run_services_recon("dead.x.com") == [] and len(calls) == 1


def test_services_ignores_catch_all_responses_but_keeps_real_ones(monkeypatch):
    import core.reconlib.services as sv
    spa = b"<html><div id=root></div></html>"

    def routes(host, path):
        if path == "/.env":
            return 200, b"DB_PASSWORD=x\nAPP_KEY=y\n", {"Content-Length": "24"}
        return 200, spa, {"Content-Length": str(len(spa))}   # SPA: 200 igual para tudo

    monkeypatch.setattr(sv, "http_get", _services_get(routes))
    out = sv.run_services_recon("app.x.com")
    assert [r["path"] for r in out] == ["/.env"]


# ── cors_scan ───────────────────────────────────────────────────────────────
def test_cors_gives_up_on_dead_host(monkeypatch):
    import core.reconlib.cors as cs
    calls = []
    monkeypatch.setattr(cs, "http_get", lambda url, **kw: calls.append(url) or (0, b"", {}))
    out = cs.run_cors_scan([{"host": "dead.x.com", "status_code": 200, "ports": ["443"]}])
    assert out["findings"] == [] and len(calls) == 2


def test_cors_reflection_still_reported(monkeypatch):
    import core.reconlib.cors as cs

    def fake_get(url, extra_headers=None, **kw):
        return 200, b"{}", {"Access-Control-Allow-Origin": extra_headers["Origin"], "Access-Control-Allow-Credentials": "true"}

    monkeypatch.setattr(cs, "http_get", fake_get)
    out = cs.run_cors_scan([{"host": "api.x.com", "status_code": 200, "ports": ["443"]}])
    assert len(out["findings"]) == 1 and out["findings"][0]["severity"] == "medium"


def test_services_baseline_tolerates_dynamic_bytes_only_on_large_pages():
    import core.reconlib.services as sv
    big = {"status": 200, "length": 20000, "snippet": "<html>a"}
    assert sv._same_as_baseline({"status": 200, "length": 20300, "snippet": "<html>b"}, big)
    assert not sv._same_as_baseline({"status": 200, "length": 24, "snippet": "DB_PASSWORD=x"},
                                    {"status": 200, "length": 32, "snippet": "<html><div id=root>"})
    assert not sv._same_as_baseline({"status": 403, "length": 20000, "snippet": "<html>a"}, big)


# ── item 5: histórico/alertas/notificações uma vez por scan da empresa ──────
def _wrap_runner(tmp_path, monkeypatch, active):
    r = _runner(tmp_path, _JobsDB(active))
    calls = []
    for name in ("_sync_module_status_from_results", "_save_pipeline_state"):
        monkeypatch.setattr(r, name, lambda *a, **k: None)
    monkeypatch.setattr(r, "_persist_pipeline_results", lambda *a, **k: calls.append("persist"))
    monkeypatch.setattr(r, "_pipeline_execution_summary", lambda cid, opts: ([], []))
    monkeypatch.setattr(r, "_finish_company_scan", lambda cid, co, log: calls.append("finish"))
    r.pipeline_state["co"] = {"status": "running", "log": []}
    return r, calls


def test_first_domain_persists_but_does_not_notify(tmp_path, monkeypatch):
    r, calls = _wrap_runner(tmp_path, monkeypatch, {"a.example", "b.example"})
    r._wrap_up_run("co", {}, {}, "a.example", lambda m: None)
    assert calls == ["persist"]
    assert r.pipeline_state["co"]["status"] == "running"


def test_last_domain_closes_scan_once(tmp_path, monkeypatch):
    r, calls = _wrap_runner(tmp_path, monkeypatch, {"a.example", "b.example"})
    r._wrap_up_run("co", {}, {}, "a.example", lambda m: None)
    r._wrap_up_run("co", {}, {}, "b.example", lambda m: None)
    assert calls == ["persist", "persist", "finish"]
    assert r.pipeline_state["co"]["status"] == "done"


def test_single_job_scan_closes_immediately(tmp_path, monkeypatch):
    r, calls = _wrap_runner(tmp_path, monkeypatch, set())
    r._wrap_up_run("co", {}, {}, "", lambda m: None)
    assert calls == ["persist", "finish"]


# ── item 6: polling bem-sucedido fora do log ────────────────────────────────
@pytest.mark.parametrize("msg,kept", [
    ('127.0.0.1 - - [x] "GET /api/recon/co/pipeline HTTP/1.1" 200 -', False),
    ('127.0.0.1 - - [x] "GET /api/recon/co/tool-logs HTTP/1.1" 200 -', False),
    ('127.0.0.1 - - [x] "GET /api/live-output/co?since=1.5 HTTP/1.1" 200 -', False),
    ('127.0.0.1 - - [x] "GET /api/jobs HTTP/1.1" 304 -', False),
    ('127.0.0.1 - - [x] "GET /api/recon/co/pipeline HTTP/1.1" 500 -', True),    # erro fica
    ('127.0.0.1 - - [x] "POST /api/recon/co/pipeline HTTP/1.1" 202 -', True),   # ação fica
    ('127.0.0.1 - - [x] "GET /api/data/company/co HTTP/1.1" 200 -', True),     # rota normal fica
])
def test_polling_filter(msg, kept):
    import logging
    from utils.log_filters import QuietPollingFilter
    rec = logging.LogRecord("werkzeug", logging.INFO, "", 0, msg, None, None)
    assert QuietPollingFilter().filter(rec) is kept


# ── módulo js: descoberta em paralelo e prazo único ─────────────────────────
def _js_env(monkeypatch, delay):
    import shutil as _sh
    import core.reconlib.jsrecon as jr
    monkeypatch.setattr(_sh, "which", lambda name: f"/bin/{name}")
    calls = []

    def fake_subp(cmd, **kw):
        tool = cmd[0].split("/")[-1]
        calls.append(tool)
        time.sleep(delay)
        return types.SimpleNamespace(stdout=f"https://app.x.com/{tool}.js\n", stderr="", returncode=0)

    monkeypatch.setattr(jr, "_subp", fake_subp)
    monkeypatch.setattr(jr, "_playwright_js_capture", lambda targets, timeout=25: {})
    monkeypatch.setattr(jr, "http_get", lambda url, **kw: (0, b"", {}))
    return jr, calls


def test_js_discovery_tools_run_in_parallel(monkeypatch):
    jr, calls = _js_env(monkeypatch, delay=1.0)
    t = time.time()
    out = jr.run_js_recon(["x.com"], [{"host": "app.x.com", "ports": ["443"], "status_code": 200}])
    assert time.time() - t < 2.5                      # em série seriam ≥ 6s (katana, subjs, getJS, gau×3)
    assert sorted(set(calls)) == ["gau", "getJS", "katana", "subjs"]
    assert out["js_files_found"] == 4


def test_js_recon_respects_module_budget(monkeypatch):
    jr, calls = _js_env(monkeypatch, delay=5.0)
    monkeypatch.setattr(jr, "JS_RECON_BUDGET_S", 3.0)
    monkeypatch.setattr(jr, "DISCOVERY_BUDGET_S", 1.0)
    t = time.time()
    out = jr.run_js_recon(["x.com"], [{"host": "app.x.com", "ports": ["443"], "status_code": 200}])
    assert time.time() - t < 4.5
    assert out["js_files_found"] == 0                 # nada chegou no prazo, mas o módulo devolveu


# ── item 3: vigilância contínua ─────────────────────────────────────────────
from core import watch as W


@pytest.fixture(autouse=True)
def _no_real_ct(monkeypatch):
    """A vigilância consulta CT (crt.sh/certspotter): nos testes, nada de rede."""
    monkeypatch.setattr(W, "_ct_names", lambda domains, budget=0: set())


def test_diff_surface_kinds():
    before = {"a.x.com": {"host": "a.x.com", "status_code": 200, "title": "A", "technologies": ["nginx"]},
              "b.x.com": {"host": "b.x.com", "status_code": None},
              "c.x.com": {"host": "c.x.com", "status_code": 200, "title": "C"},
              "d.x.com": {"host": "d.x.com", "status_code": 200, "title": "D"}}
    probed = {"a.x.com": {"status_code": 200, "title": "A2", "technologies": ["nginx", "PHP"]},
              "b.x.com": {"status_code": 200, "title": "B"},
              "d.x.com": {"status_code": 200, "title": "D", "ip": "9.9.9.9"},     # IP não conta
              "new.x.com": {"status_code": 200, "title": "N"}}
    out = {(c["kind"], c["host"]) for c in W.diff_surface(before, probed, {"quiet.x.com"}, set(before) | {"new.x.com"})}
    assert out == {("changed", "a.x.com"), ("came_alive", "b.x.com"), ("not_responding", "c.x.com"),
                   ("new_host_live", "new.x.com"), ("new_host", "quiet.x.com")}


class _WatchDB:
    def __init__(self, hosts):
        self.data = {"companies": [{"id": "co", "domains": ["x.com"], "hosts": hosts}]}
        self.alerts, self.history = [], []

    def load_asm_data(self):
        return __import__("copy").deepcopy(self.data)

    def save_asm_data(self, data):
        self.data = data

    def create_alert(self, cid, rule_type, title, desc, sev, data):
        self.alerts.append((rule_type, title, sev))

    def insert_subdomain_history(self, cid, host, event, *a, **k):
        self.history.append((host, event))

    def load_webhooks(self):
        return []


def _watch_runner(tmp_path, db, passive, live):
    r = types.SimpleNamespace(db=db, base=tmp_path, get_settings=lambda: {})
    r._active_scan_domains = lambda d: list(d)
    r._run_tool = lambda tool, d, **k: {"findings": [{"type": "subdomain", "value": n} for n in passive]}
    r._host_in_scope = lambda h, d: h.endswith(".x.com")
    r._load_hosts = lambda cid: db.load_asm_data()["companies"][0]["hosts"]
    r.probe_calls = []

    def probe(targets, cid, _expand_redirects=True, extra_ports=True, wildcard_out=None):
        r.probe_calls.append((sorted(targets), extra_ports))
        return [dict(h) for h in live]
    r._probe_hosts_with_httpx = probe
    return r


def test_run_watch_end_to_end(tmp_path):
    db = _WatchDB([{"host": "a.x.com", "status_code": 200, "title": "A"},
                   {"host": "gone.x.com", "status_code": 200, "title": "G"}])
    live = [{"host": "a.x.com", "status_code": 200, "title": "A"},
            {"host": "new.x.com", "status_code": 200, "title": "Novo"}]
    r = _watch_runner(tmp_path, db, ["new.x.com", "evil.com"], live)
    s1 = W.run_watch(r, "co", {"domains": ["x.com"], "name": "Co"})
    assert r.probe_calls[0] == (["a.x.com", "gone.x.com", "new.x.com"], False)   # só 80/443; fora do escopo saiu
    assert s1["counts"] == {"new_host_live": 1}                                    # gone: 1ª falha ainda não conta
    assert [a[0] for a in db.alerts] == ["surface_new_host_live"]
    assert db.history == [("new.x.com", "new")]
    assert (tmp_path / "scans" / "co" / "watch_last.json").exists()
    s2 = W.run_watch(r, "co", {"domains": ["x.com"], "name": "Co"})
    assert s2["counts"] == {"went_dead": 1}                                        # 2ª falha seguida
    hosts = {h["host"]: h for h in db.data["companies"][0]["hosts"]}
    assert hosts["gone.x.com"]["status_code"] is None and hosts["new.x.com"]["status_code"] == 200


def test_watch_job_and_optional_active_followup(tmp_path):
    from core.jobs import JobScheduler
    created = []

    class DB:
        def find_active_job(self, **k): return None
        def create_job(self, **k): created.append(k); return {"id": str(len(created)), **k}
        def finish_job(self, *a, **k): pass

    js = JobScheduler(db=DB(), load_companies=lambda: [{"id": "co", "domains": ["x.com"]}],
                      run_pipeline=lambda *a: None, pipeline_state={},
                      run_watch=lambda cid, co, opts: {"active_targets": ["new.x.com"]})
    js._execute({"id": "w1", "job_type": "watch", "company_id": "co", "options": {}})
    assert created == []                                       # padrão: só vigia
    js._execute({"id": "w2", "job_type": "watch", "company_id": "co", "options": {"active_on_change": True}})
    assert created[0]["job_type"] == "pipeline" and created[0]["options"]["active_hosts"] == ["new.x.com"]


def test_snapshot_diff_matches_alert_engine_format():
    from utils.alerting import AlertEngine
    d = P.snapshot_diff([{"host": "a.x.com", "status_code": 200}, "old.x.com"],
                        [{"host": "a.x.com", "status_code": 403, "technologies": ["PHP"]}, {"host": "new.x.com"}])
    assert d["diff"] == "ok"
    assert [h["host"] for h in d["new"]] == ["new.x.com"] and d["removed"] == [{"host": "old.x.com"}]
    assert d["changed"][0]["changes"]["status_code"] == {"old": 200, "new": 403}
    fired = []

    class Eng(AlertEngine):
        def _get_active_rules(self, cid):
            return [{"rule_type": t, "enabled": True} for t in ("new_host", "status_change", "new_tech")]

        def _fire(self, rule_type, cid, rules, data):
            fired.append(rule_type)
            return []

    Eng(None, Path("."), lambda: {}).process_scan_diff("co", d)
    assert sorted(fired) == ["new_host", "new_host", "new_tech", "status_change"]


def test_first_watch_of_new_domain_is_a_baseline(tmp_path):
    db = _WatchDB([{"host": "a.x.com", "status_code": 200, "title": "A"}])
    live = [{"host": "a.x.com", "status_code": 200, "title": "A"},
            {"host": "app.y.com", "status_code": 200, "title": "Y"},
            {"host": "new.x.com", "status_code": 200, "title": "Novo"}]
    r = _watch_runner(tmp_path, db, ["app.y.com", "old.y.com", "new.x.com"], live)
    r._host_in_scope = lambda h, d: h.endswith((".x.com", ".y.com"))
    s = W.run_watch(r, "co", {"domains": ["x.com", "y.com"], "name": "Co"})
    assert s["baseline_domains"] == ["y.com"]
    assert sorted(a[0] for a in db.alerts) == ["surface_baseline", "surface_new_host_live"]   # y.com: 1 alerta só
    assert s["active_targets"] == ["new.x.com"]                                            # linha de base não vira scan ativo
    hosts = {h["host"] for h in db.data["companies"][0]["hosts"]}
    assert {"app.y.com", "old.y.com"} <= hosts                                              # mas fica gravado


def test_wildcard_match_is_not_reported_as_dead():
    before = {"admin.x.com": {"host": "admin.x.com", "status_code": 200, "title": "Wild"}}
    out = W.diff_surface(before, {}, set(), {"admin.x.com"}, wildcard={"admin.x.com"})
    assert out == []
    assert [c["kind"] for c in W.diff_surface(before, {}, set(), {"admin.x.com"})] == ["not_responding"]


def test_antibot_challenge_flap_is_not_a_change():
    before = {"a.x.com": {"host": "a.x.com", "status_code": 403, "title": "Just a moment..."}}
    probed = {"a.x.com": {"status_code": 301, "title": ""}}
    assert W.diff_surface(before, probed, set(), {"a.x.com"}) == []
    real = {"a.x.com": {"status_code": 200, "title": "Admin"}}
    before2 = {"a.x.com": {"host": "a.x.com", "status_code": 404, "title": "Not found"}}
    assert [c["kind"] for c in W.diff_surface(before2, real, set(), {"a.x.com"})] == ["changed"]


def test_identical_error_pages_in_wildcard_zone_are_clustered():
    fp404 = {"443": {"status": 404, "title": "404 Not Found", "words": 76, "lines": 14}}
    host_data = {f"h{i}.x.com": {} for i in range(6)}
    host_data["real.x.com"] = {}
    host_fp = {h: fp404 for h in host_data}
    host_fp["real.x.com"] = {"443": {"status": 404, "title": "API", "words": 12, "lines": 3}}
    canary = {"x.com": [{"status": 404, "title": "404 Not Found", "words": 10, "lines": 8}]}
    hits = P._clustered_error_pages(host_data, host_fp, canary, protected={"x.com"}, already=set())
    assert sorted(hits) == [f"h{i}.x.com" for i in range(6)]
    # grupo pequeno não basta; e zona sem curinga não entra
    few = {h: host_data[h] for h in list(host_data)[:3]}
    assert P._clustered_error_pages(few, host_fp, canary, set(), set()) == []
    assert P._clustered_error_pages(host_data, host_fp, {}, set(), set()) == []


def test_watch_severity_depends_on_response():
    assert W._severity({"kind": "came_alive", "status_code": 200}) == "medium"
    assert W._severity({"kind": "came_alive", "status_code": 404}) == "low"
    assert W._severity({"kind": "went_dead"}) == "info"


# ── aba Alertas: get_alerts/acknowledge_alert não existiam (aba sempre vazia) ──
def test_alerts_listing_and_ack(tmp_path):
    from core.database import ASMDatabase
    db = ASMDatabase(tmp_path / "t.db")
    db.initialize()
    a1 = db.create_alert("co", "surface_new_host_live", "Novo host", "HTTP 200", "medium", {"host": "a.x.com"})
    db.create_alert("other", "surface_new_host", "Outro", "", "low", {})
    out = db.get_alerts("co")
    assert [a["id"] for a in out] == [a1] and out[0]["data"] == {"host": "a.x.com"} and out[0]["acknowledged"] is False
    assert db.acknowledge_alert("co", a1) is True
    assert db.get_alerts("co")[0]["acknowledged"] is True
    assert db.acknowledge_alert("other", a1) is False          # não marca alerta de outra empresa


# ── vazamento de conexões SQLite (15/10: ~500 conexões abertas → 1024 descritores → servidor travado) ──
def test_db_operations_do_not_leak_file_descriptors(tmp_path):
    import os
    from core.database import ASMDatabase
    db = ASMDatabase(tmp_path / "t.db")
    db.initialize()
    db.create_alert("co", "x", "t", "", "info", {})
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(300):
        db.get_alerts("co")
        db.load_asm_data()
    assert len(os.listdir("/proc/self/fd")) - before < 5


def test_db_connection_still_commits_and_rolls_back(tmp_path):
    from core.database import ASMDatabase
    db = ASMDatabase(tmp_path / "t.db")
    db.initialize()
    with db._connect() as conn:
        conn.execute("INSERT INTO alerts (id, company_id, rule_type, title, created_at) VALUES ('a', 'co', 'x', 't', 'now')")
    try:
        with db._connect() as conn:
            conn.execute("INSERT INTO alerts (id, company_id, rule_type, title, created_at) VALUES ('b', 'co', 'x', 't', 'now')")
            raise RuntimeError("falha no meio")
    except RuntimeError:
        pass
    assert [a["id"] for a in db.get_alerts("co")] == ["a"]


# ── item 4: fora do escopo, listas para ferramentas e leitura de escopo colado ──
from core import scope as S


def test_exclusion_patterns():
    pats, bad = S.normalize_exclusions(["Status.X.com", "https://blog.x.com/a?b=1", "*.legacy.x.com", "não é host", "#comentário"])
    assert pats == ["status.x.com", "blog.x.com", "*.legacy.x.com"] and bad == ["não é host"]
    assert S.is_excluded("status.x.com", pats) and S.is_excluded("a.b.legacy.x.com", pats)
    assert not S.is_excluded("legacy.x.com", pats)            # *.legacy.x.com não inclui o próprio
    assert not S.is_excluded("www.x.com", pats)


def test_parse_scope_text_from_program_page():
    ins = "Domain *.example.com Critical\nhttps://app.example.org/login\nAndroid: com.example.mobile\n10.0.0.0/8"
    assert S.parse_scope_text(ins) == (["example.com", "app.example.org"], ["com.example.mobile", "10.0.0.0/8"])
    assert S.parse_scope_text("*.legacy.example.com\nstatus.example.com", out_of_scope=True)[0] == \
        ["*.legacy.example.com", "status.example.com"]


def test_excluded_hosts_never_reach_active_modules(tmp_path):
    hosts = [{"host": h, "status_code": 200} for h in ("a.x.com", "status.x.com", "v1.legacy.x.com")]
    r = _runner(tmp_path)
    co = {"domains": ["x.com"], "out_of_scope": ["status.x.com", "*.legacy.x.com"]}
    out = r._filter_hosts_for_options(hosts, co, {"profile": "bug_bounty", "active": True, "domains": ["x.com"]})
    assert [h["host"] for h in out] == ["a.x.com"]


def test_excluded_hosts_are_not_probed(tmp_path, monkeypatch):
    seen = _fake_httpx(tmp_path, monkeypatch, {"80,443": []})
    r = _runner(tmp_path)
    monkeypatch.setattr(r, "_company_exclusions", lambda cid: ["status.x.com"])
    monkeypatch.setattr(r, "_wildcard_canaries", lambda names, cid: {})
    monkeypatch.setattr(r, "_company_domains", lambda cid: [])
    r._probe_hosts_with_httpx(["a.x.com", "status.x.com"], "co")
    assert seen["80,443"] == ["a.x.com"]


def test_tool_lists():
    from core import tool_lists as T
    rows = [{"host": "a.x.com", "ports": ["443", "8080"]}, {"host": "out.x.com", "ports": ["443"]},
            {"host": "evil.com", "ports": ["80"]}]
    eps = [{"url": "https://a.x.com/api?id=1"}, {"url": "/login", "host": "a.x.com"}, {"url": "https://out.x.com/?q=1"}]
    args = (rows, eps, ["x.com"], ["out.x.com"])
    assert T.build_list("hosts", *args) == ["a.x.com"]
    assert T.build_list("urls", *args) == ["http://a.x.com:8080", "https://a.x.com"]
    assert T.build_list("endpoints", *args) == ["https://a.x.com/api?id=1", "https://a.x.com/login"]
    assert T.build_list("params", *args) == ["https://a.x.com/api?id=1"]


def test_burp_feed_counts_http_errors_as_delivered():
    import urllib.error
    from core import burp_feed

    class Op:
        def open(self, req, timeout=0):
            if "boom" in req.full_url:
                raise OSError("conexão recusada")
            raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)

    out = burp_feed.feed(["https://a.x.com/", "https://boom.x.com/"], opener=Op())
    assert out["ok"] == 1 and out["failed"] == 1


def test_browser_modules_run_one_at_a_time():
    import threading
    order = []

    def mod(n):
        def f():
            order.append(("in", n)); time.sleep(0.2); order.append(("out", n))
        return f
    ts = [threading.Thread(target=P._one_browser, args=(mod(i),)) for i in range(3)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert all(order[i][0] != order[i + 1][0] for i in range(0, len(order) - 1, 2))   # in, out, in, out…
    assert [k for k, _ in order] == ["in", "out"] * 3


# ── pausa do watchdog ≠ parado (antes: job rodando na pausa virava "cancelled" e nunca voltava) ──
def test_paused_run_is_not_finished_nor_closed(tmp_path, monkeypatch):
    r, calls = _wrap_runner(tmp_path, monkeypatch, set())
    r.pipeline_state["co"]["status"] = "paused"
    r._wrap_up_run("co", {}, {}, "", lambda m: None)
    assert calls == ["persist"]                                    # salva progresso, sem fechar a empresa
    assert r.pipeline_state["co"]["status"] == "paused"


def test_worker_leaves_paused_job_for_release():
    from core.jobs import JobScheduler
    finished = []

    class DB:
        def finish_job(self, job_id, **k): finished.append((job_id, k.get("status")))

    state = {}

    def run_pipeline(cid, co, opts):
        state[cid]["status"] = "paused"

    js = JobScheduler(db=DB(), load_companies=lambda: [{"id": "co", "domains": ["x.com"]}],
                      run_pipeline=run_pipeline, pipeline_state=state)
    state["co"] = {}
    js._execute({"id": "j1", "job_type": "pipeline", "company_id": "co", "options": {}})
    assert finished == []                                          # fica "paused" no banco para voltar à fila


def test_paused_jobs_from_before_restart_are_released(tmp_path):
    from core.database import ASMDatabase
    db = ASMDatabase(tmp_path / "t.db")
    db.initialize()
    j = db.create_job(job_type="pipeline", company_id="co", target="x.com")
    db.safety_hold_jobs(reason="SAFETY-WATCHDOG: load 20 > 13")
    assert db.count_paused_jobs() == 1
    assert db.release_safety_hold() == 1 and db.get_job(j["id"])["status"] == "pending"


# ── git_leaks: "ref:" in bytes dava TypeError engolido → nunca detectava .git exposto ──
def test_git_head_detection_requires_real_content():
    from core.reconlib.extra_tools import _looks_like_git_head
    assert _looks_like_git_head(b"ref: refs/heads/main\n")
    assert _looks_like_git_head(b"3f2a" * 10 + b"\n")                  # HEAD destacado (sha)
    assert not _looks_like_git_head(b"<!doctype html><div id=root>ref: x</div>")   # SPA soft-200
    assert not _looks_like_git_head(b"")


def test_git_leaks_finds_exposed_git_and_skips_dead_hosts(monkeypatch):
    import core.reconlib.extra_tools as ex
    calls = []

    def fake_get(url, **k):
        calls.append(url)
        if "dead" in url:
            return 0, b"", {}
        if "spa" in url:
            return 200, b"<html>app</html>", {}
        return 200, b"ref: refs/heads/main\n", {}

    monkeypatch.setattr(ex, "http_get", fake_get)
    monkeypatch.setattr(ex.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=1, stdout="", stderr=""))
    out = ex.run_git_leaks([{"host": "git.x.com"}, {"host": "spa.x.com"}, {"host": "dead.x.com"}], ["x.com"])
    assert out["exposed_git"] == ["https://git.x.com/.git/"]
    assert [u for u in calls if "spa" in u] == ["https://spa.x.com/.git/HEAD"]   # respondeu em https: não tenta http
    assert len([u for u in calls if "dead" in u]) == 2


def test_watch_includes_ct_names_in_scope(tmp_path, monkeypatch):
    db = _WatchDB([{"host": "a.x.com", "status_code": 200, "title": "A"}])
    r = _watch_runner(tmp_path, db, [], [{"host": "a.x.com", "status_code": 200, "title": "A"}])
    monkeypatch.setattr(W, "_ct_names", lambda domains, budget=0: {"new-cert.x.com", "x.evil.com", "status.x.com"})
    s = W.run_watch(r, "co", {"domains": ["x.com"], "name": "Co", "out_of_scope": ["status.x.com"]})
    assert s["counts"] == {"new_host": 1} and s["changes"][0]["host"] == "new-cert.x.com"


def test_ct_names_respects_budget(monkeypatch):
    import core.recon as R

    def slow(domain, limit=500):
        time.sleep(3)
        return [{"names": ["late.x.com"]}]
    monkeypatch.setattr(R, "get_ct_certs", slow)
    import importlib
    real = importlib.reload(W)._ct_names          # a versão real (o fixture troca a do módulo)
    t = time.time()
    assert real(["x.com"], budget=0.5) == set()
    assert time.time() - t < 2


def test_queue_total_comes_from_jobs_of_same_trigger(tmp_path):
    from core.database import ASMDatabase
    db = ASMDatabase(tmp_path / "t.db")
    db.initialize()
    for d in ("a.example", "b.example", "c.example"):
        db.create_job(job_type="pipeline", company_id="co", target=d, options={"trace_id": "T1", "queue_domain": d})
    db.create_job(job_type="pipeline", company_id="co", target="x.example", options={"trace_id": "OUTRO"})
    assert db.count_jobs_with_trace("co", "T1") == 3


def test_gate_try_slot_gives_up_in_time():
    import threading
    from utils.tool_gate import ToolGate
    g = ToolGate("t", 1)
    held, release = threading.Event(), threading.Event()

    def holder():
        with g.slot():
            held.set()
            release.wait(2)
    threading.Thread(target=holder).start()
    held.wait(1)
    t = time.time()
    with g.try_slot(0.2) as got:
        assert got is False
    assert time.time() - t < 1
    release.set()
    time.sleep(0.1)
    with g.try_slot(1) as got:
        assert got is True
    assert g.active == 0


def test_infra_exposure_ignores_cdn_pages_on_open_ports(monkeypatch):
    """15/10: Cloudflare aceita conexão na 8080 e devolve página própria → 9 "Kubernetes API" falsos."""
    class _Sock:
        def __init__(self, *a): pass
        def settimeout(self, t): pass
        def connect_ex(self, addr): return 0 if addr[1] == 8080 else 1
        def close(self): pass

    import socket
    monkeypatch.setattr(socket, "socket", _Sock)
    monkeypatch.setattr(infra, "http_get", lambda url, **k: (403, b"<!DOCTYPE html><title>Attention Required! | Cloudflare</title>", {}))
    assert infra.run_infra_exposure([{"host": "a.x.com", "ip": "104.26.9.157"}])["findings"] == []
    monkeypatch.setattr(infra, "http_get", lambda url, **k: (200, b'{"major":"1","gitVersion":"v1.29.3"}', {}))
    out = infra.run_infra_exposure([{"host": "k8s.x.com", "ip": "10.0.0.9"}])
    assert len(out["findings"]) == 1 and out["findings"][0]["category"] == "Kubernetes"


def test_hygiene_dismisses_stored_infra_findings_without_signature():
    from core.finding_hygiene import dismiss_false_positives
    fake = {"type": "infra_exposure", "key": "k1", "category": "Kubernetes", "host": "a.x.com",
            "open_paths": [{"path": "/version", "status": 403, "preview": "<!DOCTYPE html><title>Attention Required! | Cloudflare"}]}
    real = {"type": "infra_exposure", "key": "k2", "category": "Kubernetes", "host": "k8s.x.com",
            "open_paths": [{"path": "/version", "status": 200, "preview": '{"major":"1","gitVersion":"v1.29.3"}'}]}
    co = {}
    assert [f["key"] for f in dismiss_false_positives([fake, real], co)] == ["k2"]
    assert co["auto_dismissed"][0]["key"] == "k1"


def test_css_module_class_is_not_a_password():
    from core.asset_matrix import fp_js_secret
    from core.finding_hygiene import dismiss_false_positives
    assert fp_js_secret("password", 'Password="_forgetPassword_ejzvx_198"')
    assert not fp_js_secret("password", 'password="Sup3r$ecret!"')
    stored = {"type": "secret", "module": "js_secrets", "key": "s1", "value": 'Password="_forgetPassword_ejzvx_198"',
              "metadata": {"secret_type": "password"}}
    assert dismiss_false_positives([stored], {}) == []


def test_brand_domain_for_sale_is_info_but_active_stays():
    from core.finding_hygiene import tidy_findings
    sale = {"type": "brand_domain_exposure", "key": "b1", "severity": "medium", "desc": "`x.tech` está à venda em broker. IP: 1.2.3.4"}
    live = {"type": "brand_domain_exposure", "key": "b2", "severity": "medium", "desc": "`x-login.com` ativo. IP: 5.6.7.8", "metadata": {"status": "active"}}
    out = {f["key"]: f["severity"] for f in tidy_findings([sale, live], {})}
    assert out == {"b1": "info", "b2": "medium"}


# ── borda (WAF/CDN) e validação por conteúdo ────────────────────────────────
def test_edge_classify_separates_proxy_from_enforcement():
    from core.reconlib.edge import classify, APPLICATION, EDGE_BLOCKED, EDGE_THROTTLED
    assert classify(200, {"cf-ray": "1", "Server": "cloudflare"}, b"<html>Bem-vindo</html>").origin == APPLICATION
    assert classify(403, {"cf-ray": "1"}, b"forbidden").origin == APPLICATION          # 403 comum de autorização
    v = classify(403, {"cf-mitigated": "challenge"}, b"")
    assert v.origin == EDGE_BLOCKED and v.vendor == "Cloudflare"
    assert classify(403, {}, b"<h1>Access Denied</h1> Reference #18.2").origin == EDGE_BLOCKED
    assert classify(429, {}, b"").origin == EDGE_THROTTLED
    assert classify(200, {}, b"too many requests, says the blog post").origin == APPLICATION


def test_edge_coverage_flags_meaningless_negatives():
    from core.reconlib.edge import Coverage, classify
    cov = Coverage()
    blocked = classify(403, {"x-amzn-waf-action": "block"}, b"")
    for _ in range(3):
        cov.add(blocked)
    cov.add(classify(200, {}, b"ok"))
    assert cov.blocked == 3 and not cov.meaningful and "AWS WAF" in cov.as_dict()["vendors"]


def test_services_drops_edge_blocked_host_and_html_env(monkeypatch):
    import core.reconlib.services as sv
    monkeypatch.setattr(sv, "http_get", lambda url, **kw: (403, b"Attention Required! | Cloudflare", {}))
    assert sv.run_services_recon("blocked.x.com") == []

    def routes(host, path):
        if path == "/.env":
            return 200, b"<html><body>app</body></html>", {"Content-Length": "40"}
        if path == "/.git/config":
            return 200, b"[core]\n\trepositoryformatversion = 0\n", {"Content-Length": "34"}
        return 404, b"nf", {}
    monkeypatch.setattr(sv, "http_get", _services_get(routes))
    assert [r["path"] for r in sv.run_services_recon("app.x.com")] == ["/.git/config"]


def test_sensitive_content_rules_cover_new_types():
    from core.verification import looks_like_sensitive_file as ok
    assert ok("/terraform.tfstate", b'{"version":4,"terraform_version":"1.5","resources":[]}')
    assert not ok("/terraform.tfstate", b"<html>x</html>")
    assert ok("/backup.zip", b"PK\x03\x04rest") and not ok("/backup.zip", b"<html>nope</html>")
    assert ok("/actuator/env", b'{"activeProfiles":[],"propertySources":[]}')
    assert not ok("/actuator/env", b"Not found")


def test_graphql_detects_playground_and_skips_catch_all(monkeypatch):
    import core.reconlib.graphql as gq
    spa = b"<html>introspection altair</html>"

    def fake(url, **kw):
        if "/sctw-" in url:
            return 404, b"nf", {}
        if url.endswith("/graphiql"):
            return 200, b"<html>GraphiQL</html>", {}
        return 404, b"nf", {}
    monkeypatch.setattr(gq, "http_get", fake)
    out = gq.run_graphql_discovery([{"host": "api.x.com", "ports": ["443"]}], [])
    assert out["total_found"] == 1 and out["findings"][0]["playground"]

    monkeypatch.setattr(gq, "http_get", lambda url, **kw: (200, spa, {"Content-Length": "33"}))
    assert gq.run_graphql_discovery([{"host": "spa.x.com", "ports": ["443"]}], [])["total_found"] == 0


def test_edge_summarize_warns_when_most_probes_never_reached_the_app():
    from core.reconlib.edge import summarize
    ok = summarize({"services": {"total": 10, "reached_application": 9, "edge_blocked": 1, "edge_throttled": 0, "vendors": []}})
    assert ok["negatives_meaningful"] and "NÃO" not in ok["summary"]
    bad = summarize({"services": {"total": 10, "reached_application": 2, "edge_blocked": 8, "edge_throttled": 0, "vendors": ["Cloudflare"]},
                     "graphql": {}})
    assert not bad["negatives_meaningful"] and "NÃO" in bad["summary"] and "Cloudflare" in bad["summary"]
    assert list(bad["by_module"]) == ["services"]


def test_services_and_leaks_record_coverage(monkeypatch):
    import core.reconlib.services as sv
    from core.reconlib import leaks
    from core.reconlib.edge import Coverage
    cov = Coverage()
    monkeypatch.setattr(sv, "http_get", lambda url, **kw: (403, b"Attention Required! | Cloudflare", {}))
    sv.run_services_recon("b.x.com", coverage=cov)
    assert cov.blocked == 1 and cov.reached == 0

    cov2 = Coverage()
    monkeypatch.setattr(leaks, "http_get", lambda url, **k: (200, b"<html>", {}))
    leaks.check_exposed_git([{"host": "a.x.com", "ports": ["443"]}], cov2)
    assert cov2.total == 2 and cov2.reached == 2


def test_report_html_includes_coverage_section():
    from routes.reporting import _render_report_html
    co = {"name": "X", "stats": {}, "hosts": [], "edge_coverage": {
        "total": 10, "reached_application": 2, "edge_blocked": 8, "edge_throttled": 0, "negatives_meaningful": False,
        "summary": "2/10 sondagens", "by_module": {"services": {"total": 10, "reached_application": 2, "edge_blocked": 8, "edge_throttled": 0}}}}
    risk = {"score": 1, "label": "Low", "breakdown": {"critical_findings": 0, "high_findings": 0, "medium_findings": 0, "low_findings": 0}}
    html = _render_report_html(co, [], risk)
    assert "Cobertura dos testes" in html and "2/10" in html and "não prova" in html
    co["edge_coverage"] = {}
    assert "Cobertura dos testes" not in _render_report_html(co, [], risk)
