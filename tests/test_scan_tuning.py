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
