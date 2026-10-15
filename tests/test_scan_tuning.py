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
