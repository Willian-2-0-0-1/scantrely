"""Monitor contínuo de CertStream: mensagens, escopo, alertas, reconexão e integração com o snapshot."""
import json
import time

import pytest

from core import certmonitor as cm


class FakeDB:
    def __init__(self, companies, hosts=()):
        self.companies = companies
        self.hosts = list(hosts)
        self.alerts, self.history = [], []

    def load_companies(self):
        return self.companies

    def load_asm_data(self):
        return {"companies": [{"id": c["id"], "hosts": [{"host": h} for h in self.hosts]} for c in self.companies]}

    def create_alert(self, cid, rule, title, desc, sev, data):
        self.alerts.append({"cid": cid, "rule": rule, "title": title, "sev": sev, "data": data})

    def insert_subdomain_history(self, cid, host, event, first, last, alive=0, source=""):
        self.history.append((cid, host, source))

    def load_webhooks(self):
        return []


CO = [{"id": "co", "name": "Acme", "domains": ["acme.com"], "out_of_scope": ["*.legacy.acme.com"]}]


def _cert(*names, issuer="Let's Encrypt"):
    return {"message_type": "certificate_update",
            "data": {"leaf_cert": {"all_domains": list(names), "issuer": {"O": issuer},
                                   "not_before": 1, "not_after": 2}, "source": {"name": "argon"}}}


def _mon(db=None, **kw):
    return cm.CertStreamMonitor(db or FakeDB(CO), lambda: {}, **kw)


def test_extract_names_both_formats():
    names, meta = cm.extract_names(_cert("a.acme.com", "*.b.acme.com"))
    assert names == ["a.acme.com", "*.b.acme.com"] and meta["issuer"] == "Let's Encrypt" and meta["log"] == "argon"
    assert cm.extract_names({"message_type": "dns_entries", "data": ["x.acme.com"]})[0] == ["x.acme.com"]
    assert cm.extract_names({"message_type": "heartbeat"}) == ([], {})
    assert cm.extract_names("lixo") == ([], {})


def test_resolve_urls():
    assert cm.resolve_urls({}) == [cm.PUBLIC_URL]
    assert cm.resolve_urls({"certstream_url": "ws://127.0.0.1:8080/, ws://x:1/ ftp://no"}) == [
        "ws://127.0.0.1:8080/", "ws://x:1/", cm.PUBLIC_URL]
    assert cm.resolve_urls({"certstream_url": "ws://h/", "certstream_public_fallback": "0"}) == ["ws://h/"]
    assert cm.resolve_urls({"certstream_public_fallback": "0"}) == [cm.PUBLIC_URL]     # sem nada configurado, nunca fica sem servidor


def test_is_enabled(monkeypatch):
    monkeypatch.delenv("ASM_CERTSTREAM", raising=False)
    assert not cm.is_enabled({}) and cm.is_enabled({"certstream_enabled": "1"})
    monkeypatch.setenv("ASM_CERTSTREAM", "1")
    assert cm.is_enabled({})


def test_scope_match_suffix_only():
    s = cm._Scope([{"id": "a", "domains": ["acme.com"]}, {"id": "b", "domains": ["sub.acme.com"]}])
    assert sorted(s.match("x.sub.acme.com")) == [("a", "acme.com"), ("b", "sub.acme.com")]
    assert s.match("notacme.com") == [] and s.match("acme.com.evil.io") == []


def test_handle_and_flush_alerts():
    db = FakeDB(CO, hosts=["known.acme.com"])
    m = _mon(db)
    m._handle(_cert("new.acme.com", "known.acme.com", "acme.com", "*.wild.acme.com", "x.legacy.acme.com", "outro.org"))
    m._handle(_cert("new.acme.com"))                                      # repetido: um alerta só
    m._flush()
    got = {a["data"]["host"]: a["sev"] for a in db.alerts}
    assert got == {"new.acme.com": "medium", "wild.acme.com": "low"}      # conhecido, apex, fora de escopo e alheio ficam de fora
    assert {h[1] for h in db.history} == {"new.acme.com", "wild.acme.com"} and db.history[0][2] == "certstream"
    m._handle(_cert("new.acme.com"))
    m._flush()
    assert len(db.alerts) == 2                                            # já visto: não realerta
    assert [r["host"] for r in m.recent_for(["acme.com"])].count("new.acme.com") == 3


def test_flush_caps_alerts_and_summarises():
    db = FakeDB(CO)
    m = _mon(db)
    m._handle(_cert(*[f"h{i}.acme.com" for i in range(cm.MAX_ALERTS_PER_FLUSH + 5)]))
    m._flush()
    assert sum(a["rule"] == "certstream_new_host" for a in db.alerts) == cm.MAX_ALERTS_PER_FLUSH
    assert [a["rule"] for a in db.alerts][-1] == "certstream_summary"


class FakeWS:
    def __init__(self, msgs, then=None):
        self.msgs, self.then, self.closed = list(msgs), then, False

    def recv(self):
        if self.msgs:
            return json.dumps(self.msgs.pop(0))
        raise self.then or ConnectionError("fim")

    def close(self):
        self.closed = True


def test_session_processes_and_reports_health():
    db = FakeDB(CO)
    ws = FakeWS([_cert("a.acme.com"), _cert("b.acme.com")])
    m = _mon(db, connect=lambda url: ws)
    assert m._session("ws://x/") is True                                  # serviu mensagens e depois caiu
    assert m.stats["received"] == 2 and ws.closed
    m._flush()
    assert {a["data"]["host"] for a in db.alerts} == {"a.acme.com", "b.acme.com"}


def test_session_silent_server_raises():
    m = _mon(connect=lambda url: FakeWS([]))
    with pytest.raises(ConnectionError):
        m._session("ws://x/")


def test_run_rotates_to_next_url_and_stops(monkeypatch):
    monkeypatch.setattr(cm, "SETTINGS_POLL_S", 0.05)
    tried = []

    def connect(url):
        tried.append(url)
        if url == "ws://bad/":
            raise OSError("recusou")
        return FakeWS([_cert("z.acme.com")])

    db = FakeDB(CO)
    m = cm.CertStreamMonitor(db, lambda: {"certstream_enabled": "1", "certstream_url": "ws://bad/, ws://good/"}, connect=connect)
    monkeypatch.setattr(cm.random, "uniform", lambda a, b: 0)
    # backoff curto para o teste não demorar
    orig_wait = m._stop.wait
    m._stop.wait = lambda t=None: orig_wait(0.01)
    m.start()
    deadline = time.time() + 5
    while time.time() < deadline and not any(a["data"]["host"] == "z.acme.com" for a in db.alerts):
        time.sleep(0.02)
    m.stop()
    assert tried[:2] == ["ws://bad/", "ws://good/"]
    assert any(a["data"]["host"] == "z.acme.com" for a in db.alerts)
    assert "recusou" in m.stats["last_error"] or m.stats["reconnects"] >= 1


def test_disabled_monitor_never_connects():
    called = []
    m = cm.CertStreamMonitor(FakeDB(CO), lambda: {}, connect=lambda u: called.append(u))
    m.start()
    time.sleep(0.2)
    m.stop()
    assert not called and m.stats["state"] == "stopped"


def test_snapshot_uses_connected_monitor(monkeypatch):
    from core.reconlib import certstream as cs
    db = FakeDB(CO)
    m = _mon(db)
    m._handle(_cert("api.acme.com"))
    m.stats["state"] = "connected"
    cm.set_monitor(m)
    monkeypatch.setattr(cs, "_listen", lambda *a, **k: pytest.fail("não devia escutar de novo"))
    try:
        out = cs.run_certstream_snapshot(["acme.com"], duration_sec=1)
    finally:
        cm.set_monitor(None)
    assert [c["domain"] for c in out["new_certs"]] == ["api.acme.com"]
    assert out["new_certs"][0]["source"] == "certstream-monitor"


def test_snapshot_listens_when_no_monitor(monkeypatch):
    from core.reconlib import certstream as cs
    cm.set_monitor(None)
    monkeypatch.setattr(cs, "_listen", lambda urls, dur, matches: ([{"domain": "q.acme.com", "cn": "q.acme.com", "issuer": "", "not_before": "", "not_after": "", "source": "certstream"}], None))
    out = cs.run_certstream_snapshot(["acme.com"], duration_sec=1)
    assert out["total"] == 1 and out["new_certs"][0]["domain"] == "q.acme.com"


def test_session_idle_timeout(monkeypatch):
    monkeypatch.setattr(cm, "RECV_TIMEOUT_S", 0.05)
    quiet = lambda: FakeWS([], then=TimeoutError("recv"))
    with pytest.raises(ConnectionError):                                  # nunca falou: erro, para rodar para o próximo servidor
        _mon(connect=lambda u: quiet())._session("ws://x/")
    class Slow(FakeWS):
        def recv(self):
            if self.msgs:
                return super().recv()
            time.sleep(0.02)
            raise TimeoutError("recv")
    db = FakeDB(CO)
    m = _mon(db, connect=lambda u: Slow([_cert("t.acme.com")]))
    assert m._session("ws://x/") is True                                  # falou e depois calou: reconecta
    m._flush()
    assert [a["data"]["host"] for a in db.alerts] == ["t.acme.com"]
