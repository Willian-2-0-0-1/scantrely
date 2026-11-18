"""Proxy residencial (Webshare e compatíveis): rotação de sessão e escalonamento
automático no motor HTTP quando um bloqueio de WAF é detectado.
Ver utils/proxy_rotator.py, core/reconlib/base.py (http_get) e
core/pipeline.py (_check_blocked_and_rotate)."""
import urllib.error
import urllib.request

import pytest

from utils import proxy_rotator as pr
from core.reconlib import base


WEBSHARE_URL = "http://demo-GB-1:secret@p.webshare.io:80/"


# ── utils/proxy_rotator.py — funções puras ─────────────────────────────────

def test_is_enabled_requires_flag_and_url():
    assert pr.is_enabled({"proxy_enabled": "1", "proxy_url": WEBSHARE_URL})
    assert not pr.is_enabled({"proxy_enabled": "0", "proxy_url": WEBSHARE_URL})
    assert not pr.is_enabled({"proxy_enabled": "1", "proxy_url": ""})
    assert not pr.is_enabled({})
    assert not pr.is_enabled(None)


def test_rotate_changes_only_the_session_number():
    from urllib.parse import urlsplit

    rotated = pr.rotate(WEBSHARE_URL)
    assert rotated != WEBSHARE_URL
    before, after = urlsplit(WEBSHARE_URL), urlsplit(rotated)
    assert before.password == after.password
    assert before.hostname == after.hostname and before.port == after.port
    before_base, before_session = before.username.rsplit("-", 1)
    after_base, after_session = after.username.rsplit("-", 1)
    assert before_base == after_base
    assert before_session != after_session
    assert after_session.isdigit()


def test_rotate_twice_gives_different_sessions_with_high_probability():
    r1 = pr.rotate(WEBSHARE_URL)
    r2 = pr.rotate(r1)
    assert r1 != r2  # sorteio num espaço de ~1M valores — colisão improvável


def test_rotate_without_session_suffix_is_a_noop():
    url = "http://plainuser:pw@proxy.example.com:8080/"
    assert pr.rotate(url) == url


def test_rotate_empty_or_none_is_safe():
    assert pr.rotate("") == ""
    assert pr.rotate(None) is None


def test_redact_hides_password_but_keeps_everything_else():
    redacted = pr.redact(WEBSHARE_URL)
    assert "secret" not in redacted
    assert "demo-GB-1" in redacted
    assert "p.webshare.io:80" in redacted


def test_redact_without_password_is_unchanged():
    url = "http://p.webshare.io:80/"
    assert pr.redact(url) == url


# ── core/reconlib/base.py — thread-locals de configuração ─────────────────

def test_proxy_available_and_forced_roundtrip():
    try:
        base.set_proxy_available("http://a:b@proxy1:80")
        assert base.get_proxy_available() == "http://a:b@proxy1:80"
        base.set_proxy_forced("http://a:b@proxy2:80")
        assert base.get_proxy_forced() == "http://a:b@proxy2:80"
    finally:
        base.set_proxy_available(None)
        base.set_proxy_forced(None)


def test_proxy_forced_defaults_to_none():
    base.set_proxy_forced(None)
    assert base.get_proxy_forced() is None
    base.set_proxy_available(None)
    assert base.get_proxy_available() is None


# ── http_get: escalona para o proxy só depois de um bloqueio real ─────────

class _FakeResponse:
    def __init__(self, status, body, headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture(autouse=True)
def _fast_and_isolated(monkeypatch):
    """Sem curl_cffi (ambiente de CI não o instala) para exercitar o fallback urllib,
    sem dormir de verdade nos backoffs, e sem vazar estado de domínio entre testes."""
    monkeypatch.setattr(base, "_CFFI_AVAILABLE", False)
    monkeypatch.setattr(base.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(base, "_rate_wait", lambda *_a, **_k: None)
    base._domain_state.clear()
    base.set_proxy_available(None)
    base.set_proxy_forced(None)
    yield
    base._domain_state.clear()
    base.set_proxy_available(None)
    base.set_proxy_forced(None)


def test_http_get_escalates_to_proxy_after_block_then_succeeds(monkeypatch):
    domain = "blocked-waf.example.com"
    url = f"https://{domain}/"
    block_body = b"Attention Required! | Cloudflare - access denied"
    opened_via = []

    def fake_urlopen(req, timeout=None):
        opened_via.append(("direct", req.full_url))
        return _FakeResponse(403, block_body)

    class FakeOpener:
        def __init__(self, proxy_handler):
            self._handler = proxy_handler

        def open(self, req, timeout=None):
            opened_via.append(("proxy", self._handler.proxies))
            return _FakeResponse(200, b"ok")

    def fake_build_opener(handler):
        return FakeOpener(handler)

    class _FakeHandler:
        def __init__(self, proxies):
            self.proxies = proxies

    def fake_proxy_handler(proxies):
        return _FakeHandler(proxies)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    monkeypatch.setattr(urllib.request, "ProxyHandler", fake_proxy_handler)

    base.set_proxy_available("http://demo-GB-1:secret@p.webshare.io:80/")

    status, body, _headers = base.http_get(url, timeout=1, retries=2)

    assert status == 200
    assert body == b"ok"
    # 1a tentativa foi direta (sem proxy) e bateu no bloqueio; a 2a já foi pelo proxy.
    assert opened_via[0][0] == "direct"
    assert opened_via[1][0] == "proxy"
    assert opened_via[1][1]["http"] == "http://demo-GB-1:secret@p.webshare.io:80/"
    # o domínio fica marcado para usar proxy nas próximas chamadas (não só nesta).
    assert base._get_domain_state(domain)["proxy_url"]


def test_http_get_rotates_session_when_still_blocked_through_proxy(monkeypatch):
    domain = "still-blocked.example.com"
    url = f"https://{domain}/"
    block_body = b"Request blocked - security policy"
    seen_proxies = []

    def fake_urlopen(req, timeout=None):
        return _FakeResponse(403, block_body)

    class FakeOpener:
        def __init__(self, proxy_handler):
            self._handler = proxy_handler

        def open(self, req, timeout=None):
            seen_proxies.append(self._handler.proxies["http"])
            return _FakeResponse(403, block_body)

    def fake_build_opener(handler):
        return FakeOpener(handler)

    class _FakeHandler:
        def __init__(self, proxies):
            self.proxies = proxies

    def fake_proxy_handler(proxies):
        return _FakeHandler(proxies)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    monkeypatch.setattr(urllib.request, "ProxyHandler", fake_proxy_handler)

    base.set_proxy_available("http://demo-GB-1:secret@p.webshare.io:80/")

    status, _body, _headers = base.http_get(url, timeout=1, retries=3)

    assert status == 0  # esgotou as tentativas, ainda bloqueado — mas chegou a rotacionar
    assert len(seen_proxies) >= 2
    assert seen_proxies[0] != seen_proxies[1]  # sessão rotacionada entre as tentativas via proxy


def test_http_get_without_configured_proxy_never_touches_proxy_apis(monkeypatch):
    """Sem proxy habilitado nas settings, bloqueio só gera backoff — comportamento
    de antes da feature, sem regressão."""
    domain = "no-proxy.example.com"
    url = f"https://{domain}/"
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        return _FakeResponse(403, b"access denied")

    def fail_build_opener(*_a, **_k):
        raise AssertionError("não deveria tentar usar proxy sem configuração")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(urllib.request, "build_opener", fail_build_opener)

    status, _body, _headers = base.http_get(url, timeout=1, retries=2)

    assert status == 0
    assert len(calls) == 2
    assert base._get_domain_state(domain)["proxy_url"] is None
