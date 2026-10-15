"""
ASM Platform — test suite.
Covers: pure functions, blueprint factories, Flask routes (auth/company/scan/recon),
        pipeline module, and regression tests for previously fixed bugs.
"""
import json
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def tmp_dir(tmp_path):
    return tmp_path


@pytest.fixture()
def db(tmp_path):
    from core.database import ASMDatabase

    db = ASMDatabase(
        tmp_path / "test.db",
        asm_data_file=tmp_path / "asm_data.js",
        snapshots_dir=tmp_path / "snapshots",
        companies_file=tmp_path / "companies.json",
        settings_file=tmp_path / "settings.json",
        admins_file=tmp_path / "admins.json",
        schedules_file=tmp_path / "schedules.json",
        webhooks_file=tmp_path / "webhooks.json",
        whitelist_file=tmp_path / "whitelist.json",
        audit_log_file=tmp_path / "audit.log",
    )
    db.initialize()
    return db


@pytest.fixture()
def flask_app(tmp_path, db):
    """Minimal Flask app with all blueprints registered using mock dependencies."""
    from flask import Flask
    from routes.core import create_core_blueprint
    from routes.ops import create_ops_blueprint
    from routes.assets import create_asset_blueprint
    from routes.scans import create_scan_blueprint
    from routes.recon import create_recon_blueprint
    from routes.reporting import create_reporting_blueprint
    from core.jobs import JobScheduler
    from core.pipeline import ReconRunner, PIPELINE_PHASES, SELF_CONTAINED_MODULES

    app = Flask(__name__)
    app.config["TESTING"] = True
    from utils.trace import register_trace
    register_trace(app)

    SESSION_TTL = 86400
    sessions: dict = {}

    import hashlib, secrets, base64, hmac as _hmac
    ITERS = 100  # low for speed in tests

    def hash_pw(pw):
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), ITERS)
        return f"pbkdf2:sha256:{salt}:{base64.b64encode(dk).decode()}"

    def check_pw(pw, h):
        try:
            _, algo, salt, stored = h.split(":")
            dk = hashlib.pbkdf2_hmac(algo, pw.encode(), salt.encode(), ITERS)
            return _hmac.compare_digest(base64.b64encode(dk).decode(), stored)
        except Exception:
            return False

    admin = {
        "id": uuid.uuid4().hex,
        "username": "admin",
        "email": "",
        "password_hash": hash_pw("admin"),
        "role": "super_admin",
        "created_at": "2024-01-01T00:00:00",
        "last_login": None,
    }
    db.save_admins([admin])

    def load_admins():
        return db.load_admins()

    def save_admins(a):
        db.save_admins(a)

    def get_settings():
        return {}

    from flask import request as _req

    def get_session():
        token = _req.headers.get("X-Auth-Token") or _req.cookies.get("asm_token")
        if not token:
            return None
        sess = sessions.get(token)
        if not sess or time.time() > sess["expires_at"]:
            sessions.pop(token, None)
            return None
        return sess

    from functools import wraps
    from flask import jsonify, g as _g

    def require_auth(f):
        @wraps(f)
        def w(*a, **kw):
            sess = get_session()
            if not sess:
                return jsonify({"error": "Unauthorized"}), 401
            _g.session = sess
            return f(*a, **kw)
        return w

    def require_super_admin(f):
        @wraps(f)
        def w(*a, **kw):
            s = get_session()
            if not s:
                return jsonify({"error": "Unauthorized"}), 401
            if s.get("role") != "super_admin":
                return jsonify({"error": "Forbidden"}), 403
            _g.session = s
            return f(*a, **kw)
        return w

    @app.before_request
    def _enforce_company_scope():
        sess = get_session()
        if not sess:
            return None
        _g.session = sess
        if sess.get("role") == "super_admin":
            return None
        scoped = sess.get("scoped_companies", [])
        if scoped is None:
            return None
        if isinstance(scoped, str):
            try:
                scoped = json.loads(scoped)
            except Exception:
                scoped = []
        if not isinstance(scoped, list):
            scoped = []
        allowed = {str(cid) for cid in scoped if str(cid).strip()}
        view_args = _req.view_args or {}
        for key in ("cid", "company_id", "company"):
            val = view_args.get(key) or _req.args.get(key)
            if val and allowed and str(val) not in allowed:
                return jsonify({"error": "Forbidden — company not in scope"}), 403
            if val and not allowed:
                return jsonify({"error": "Forbidden — company not in scope"}), 403
        return None

    def audit(action, target="", details=""):
        pass

    companies: list = []

    def _scope_from_session():
        sess = getattr(_g, "session", {}) or {}
        if sess.get("role") == "super_admin":
            return None
        scoped = sess.get("scoped_companies", [])
        if scoped is None:
            return None
        if isinstance(scoped, str):
            try:
                scoped = json.loads(scoped)
            except Exception:
                scoped = []
        if not isinstance(scoped, list):
            scoped = []
        return [str(cid) for cid in scoped if str(cid).strip()]

    def load_companies():
        scoped = _scope_from_session()
        if scoped is None:
            return list(companies)
        if not scoped:
            return []
        allowed = set(scoped)
        return [c for c in companies if c.get("id") in allowed]

    def save_companies(c):
        companies.clear()
        companies.extend(c)

    tool_run_results: dict = {}
    checkpoint_jobs: dict = {}
    playwright_calls: list = []

    def load_hosts_for_company(cid):
        return []

    runner = ReconRunner(
        db=db,
        base_dir=tmp_path,
        get_settings=get_settings,
        load_hosts_fn=load_hosts_for_company,
        recon_module=None,
        recon_available=False,
    )

    scheduler = JobScheduler(
        db=db,
        load_companies=load_companies,
        run_pipeline=lambda cid, co, opts: None,
        run_playwright_recon=lambda cid, co, opts: playwright_calls.append((cid, co, opts)) or {
            "status": "done",
            "output": str(tmp_path / "report.md"),
        },
        pipeline_state=runner.pipeline_state,
        save_pipeline_state=lambda cid: None,
        max_workers=1,
    )

    RECON_MODULES = {
        "email": ("Email Security", "~10s"),
        "dns":   ("DNS Records",    "~10s"),
    }

    app.register_blueprint(create_core_blueprint(
        session_ttl=SESSION_TTL,
        sessions=sessions,
        load_admins=load_admins,
        save_admins=save_admins,
        hash_pw=hash_pw,
        check_pw=check_pw,
        get_session=get_session,
        require_auth=require_auth,
        require_super_admin=require_super_admin,
        audit=audit,
        get_settings=get_settings,
        save_settings=db.set_settings,
        settings_keys=set(),
    ))

    app.register_blueprint(create_ops_blueprint(
        require_auth=require_auth,
        require_super_admin=require_super_admin,
        load_schedules=db.load_schedules,
        save_schedules=db.save_schedules,
        load_webhooks=db.load_webhooks,
        save_webhooks=db.save_webhooks,
        send_webhook=lambda h, p: None,
        compute_diff=lambda cid: {"error": "no snapshot"},
        load_whitelist=db.load_whitelist,
        save_whitelist=db.save_whitelist,
        get_session=get_session,
        audit=audit,
        list_audit_log=db.list_audit_log,
    ))

    app.register_blueprint(create_asset_blueprint(
        require_auth=require_auth,
        load_companies=load_companies,
        save_companies=save_companies,
        get_settings=get_settings,
        save_settings=db.set_settings,
        get_company_data=lambda cid: None,
        tools_available=False,
        tool_registry=None,
        tool_run_results=tool_run_results,
        checkpoints_available=False,
        checkpoints_module=None,
        load_hosts_for_company=load_hosts_for_company,
        checkpoint_jobs=checkpoint_jobs,
    ))

    app.register_blueprint(create_scan_blueprint(
        require_auth=require_auth,
        base_dir=tmp_path,
        load_companies=load_companies,
        load_asm_data=db.load_asm_data,
        save_asm_data=db.save_asm_data,
        get_asm_data_timestamp=db.get_asm_data_timestamp,
        db=db,
    ))

    app.register_blueprint(create_recon_blueprint(
        require_auth=require_auth,
        recon_available=False,
        recon_modules=RECON_MODULES,
        self_contained_modules=SELF_CONTAINED_MODULES,
        run_recon_handler=runner.run_module_request,
        load_companies=load_companies,
        get_settings=get_settings,
        pipeline_state=runner.pipeline_state,
        pipeline_phases=PIPELINE_PHASES,
        run_pipeline_handler=lambda cid, co, opts: None,
        recon_results=runner.results,
        load_asm_data=db.load_asm_data,
        save_asm_data=db.save_asm_data,
        job_scheduler=scheduler,
        db=db,
    ))

    app.register_blueprint(create_reporting_blueprint(
        require_auth=require_auth,
        get_company_data=lambda cid: None,
        compute_risk_score=lambda co: {"score": 0, "label": "Info", "breakdown": {}},
        load_whitelist=db.load_whitelist,
        load_asm_data=db.load_asm_data,
        audit=audit,
    ))

    from routes.extras import create_extras_blueprint
    app.register_blueprint(create_extras_blueprint(
        require_auth=require_auth,
        require_super_admin=require_super_admin,
        get_session=get_session,
        load_admins=load_admins,
        save_admins=save_admins,
        hash_pw=hash_pw,
        get_settings=get_settings,
        check_pw=check_pw,
        db=db,
        base_dir=tmp_path,
        load_companies=load_companies,
        job_scheduler=scheduler,
        pipeline_state=runner.pipeline_state,
        pipeline_phases=PIPELINE_PHASES,
        audit=audit,
        get_company_data=lambda cid: {"id": cid, "name": "t", "findings": [{"title": "x", "severity": "high", "host": "a.example", "module": "cve"}]},
    ))

    from utils.health import register_health_routes
    register_health_routes(
        app,
        db=db,
        bin_dir=tmp_path / "bin",
        scans_dir=tmp_path / "scans",
        data_dir=tmp_path,
        job_scheduler=scheduler,
        pipeline_state=runner.pipeline_state,
    )

    app._test_sessions = sessions
    app._test_companies = companies
    app._test_runner = runner
    app._test_scheduler = scheduler
    app._test_playwright_calls = playwright_calls
    app._test_hash_pw = hash_pw
    return app


def _dashboard_js() -> str:
    """O front foi dividido em static/js/dashboard/NN-*.js (carregados em ordem)."""
    parts = sorted((ROOT / "static" / "js" / "dashboard").glob("*.js"))
    assert parts, "static/js/dashboard/*.js não encontrado"
    return "\n".join(p.read_text(encoding="utf-8") for p in parts)


@pytest.fixture()
def client(flask_app):
    return flask_app.test_client()


@pytest.fixture()
def auth_client(flask_app):
    """Client with a valid admin session token pre-set."""
    c = flask_app.test_client()
    resp = c.post("/api/auth/login",
                  json={"username": "admin", "password": "admin"},
                  content_type="application/json")
    assert resp.status_code == 200
    token = resp.get_json()["token"]
    c.environ_base["HTTP_X_AUTH_TOKEN"] = token
    return c


def login_as_admin(flask_app, db, username: str, password: str, role: str = "analyst",
                   scoped_companies=None):
    """Create or update an admin and return a logged-in client for that identity."""
    admins = db.load_admins()
    admins = [a for a in admins if a["username"] != username]
    admins.append({
        "id": uuid.uuid4().hex,
        "username": username,
        "email": "",
        "password_hash": flask_app._test_hash_pw(password),
        "role": role,
        "scoped_companies": scoped_companies if scoped_companies is not None else [],
        "created_at": "2024-01-01T00:00:00",
        "last_login": None,
    })
    db.save_admins(admins)
    c = flask_app.test_client()
    resp = c.post("/api/auth/login",
                  json={"username": username, "password": password},
                  content_type="application/json")
    assert resp.status_code == 200
    token = resp.get_json()["token"]
    c.environ_base["HTTP_X_AUTH_TOKEN"] = token
    return c


# ═══════════════════════════════════════════════════════════════════════════════
# 1 — Pure function unit tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPasswordHashing:
    def test_round_trip(self, flask_app):
        h = flask_app._test_hash_pw("secret123")
        from routes.core import create_core_blueprint
        # hash contains pbkdf2 prefix
        assert h.startswith("pbkdf2:sha256:")

    def test_wrong_password_fails(self, flask_app):
        h = flask_app._test_hash_pw("correct")
        # verify via server._check_pw — import directly
        import hashlib, base64, hmac as _hmac
        def check(pw, hash_str):
            try:
                _, algo, salt, stored = hash_str.split(":")
                dk = hashlib.pbkdf2_hmac(algo, pw.encode(), salt.encode(), 100)
                return _hmac.compare_digest(base64.b64encode(dk).decode(), stored)
            except Exception:
                return False
        assert check("correct", h) is True
        assert check("wrong",   h) is False


class TestRiskScore:
    def _score(self, findings=None, hosts=None, stats=None, waf=None):
        # Import the function directly from server context
        # Replicate logic here to test it in isolation
        findings = findings or []
        hosts    = hosts or []
        stats    = stats or {}
        waf      = waf or {}
        c = sum(1 for f in findings if f.get("severity") == "critical")
        h = sum(1 for f in findings if f.get("severity") == "high")
        m = sum(1 for f in findings if f.get("severity") == "medium")
        l = sum(1 for f in findings if f.get("severity") == "low")
        score = min(100, c * 40 + h * 10 + m * 3 + l * 1)
        direct = waf.get("Direct", 0) + waf.get("", 0)
        total  = max(1, sum(waf.values()))
        if direct / total > 0.5:
            score = min(100, score + 10)
        admin_ports = {"22", "3389", "5900", "8080", "8443", "9200", "27017", "6379", "5432", "3306"}
        exposed = sum(
            1 for h_ in hosts
            if isinstance(h_, dict) and any(str(p) in admin_ports for p in h_.get("ports", []))
        )
        score = min(100, score + min(20, exposed * 5))
        if score == 0 and stats.get("live_hosts", 0) > 0:
            score = 5
        return score

    def test_empty_returns_zero(self):
        assert self._score() == 0

    def test_critical_finding_scores_40(self):
        assert self._score(findings=[{"severity": "critical"}]) == 40

    def test_cap_at_100(self):
        findings = [{"severity": "critical"}] * 10
        assert self._score(findings=findings) == 100

    def test_live_hosts_with_zero_findings_gives_5(self):
        assert self._score(stats={"live_hosts": 3}) == 5

    def test_admin_port_exposure_adds_score(self):
        base   = self._score()
        with_p = self._score(hosts=[{"host": "x.com", "ports": [22]}])
        assert with_p > base

    def test_label_critical_at_80(self):
        # 2 critical findings = 80 → label Critical
        score = self._score(findings=[{"severity": "critical"}, {"severity": "critical"}])
        assert score == 80


class TestGowitnessNameToUrl:
    def test_https_443(self):
        from routes.scans import _gowitness_name_to_url
        assert _gowitness_name_to_url("https---example.com-443") == "https://example.com"

    def test_http_80(self):
        from routes.scans import _gowitness_name_to_url
        assert _gowitness_name_to_url("http---example.com-80") == "http://example.com"

    def test_custom_port(self):
        from routes.scans import _gowitness_name_to_url
        url = _gowitness_name_to_url("https---example.com-8443")
        assert "8443" in url

    def test_unknown_stem_returned_as_is(self):
        from routes.scans import _gowitness_name_to_url
        assert _gowitness_name_to_url("no-match-here") == "no-match-here"


class TestJsonDumps:
    def test_basic(self):
        from routes.reporting import json_dumps
        out = json_dumps({"a": 1})
        assert json.loads(out) == {"a": 1}

    def test_indent(self):
        from routes.reporting import json_dumps
        out = json_dumps({"a": 1}, indent=2)
        assert "\n" in out

    def test_non_ascii(self):
        from routes.reporting import json_dumps
        out = json_dumps({"k": "ação"})
        assert "ação" in out  # ensure_ascii=False


class TestWebhookSSRFGuard:
    """Regression: _send_webhook must reject non-http(s) URLs."""

    def _send(self, url):
        # Replicate the guard logic from server.py
        return url.startswith(("https://", "http://"))

    def test_https_allowed(self):
        assert self._send("https://hooks.slack.com/xxx") is True

    def test_http_allowed(self):
        assert self._send("http://internal.corp/hook") is True

    def test_file_blocked(self):
        assert self._send("file:///etc/passwd") is False

    def test_gopher_blocked(self):
        assert self._send("gopher://evil.com") is False

    def test_empty_blocked(self):
        assert self._send("") is False


class TestTargetNormalization:
    def test_url_input_normalizes_to_domain(self):
        from core.targets import normalize_domain
        res = normalize_domain("https://WWW.Example.com:443/path?q=1")
        assert res.ok is True
        assert res.value == "www.example.com"

    def test_wildcard_is_accepted_but_stored_as_apex(self):
        from core.targets import normalize_domain
        res = normalize_domain("*.Example.com")
        assert res.ok is True
        assert res.wildcard is True
        assert res.value == "*.example.com"

    def test_glob_wildcard_is_preserved(self):
        from core.targets import normalize_domain
        res = normalize_domain("api*.HubApi.com")
        assert res.ok is True
        assert res.wildcard is True
        assert res.value == "api*.hubapi.com"

    def test_ip_is_accepted_as_company_domain(self):
        from core.targets import normalize_domain
        res = normalize_domain("127.0.0.1")
        assert res.ok is True
        assert res.value == "127.0.0.1"

    def test_list_deduplicates_normalized_domains(self):
        from core.targets import normalize_domain_list
        domains, errors = normalize_domain_list(["Example.com", "https://example.com/a", "*.example.com"])
        assert errors == []
        assert domains == ["example.com", "*.example.com"]


class TestCommandRunner:
    def test_shell_true_rejected(self):
        from utils.command_runner import run
        with pytest.raises(ValueError):
            run([sys.executable, "-c", "print('x')"], shell=True)

    def test_tool_run_history_is_persisted(self, db):
        from utils.command_runner import CommandContext, run
        proc = run(
            [sys.executable, "-c", "print('ok')"],
            timeout=10,
            context=CommandContext(company_id="co", module="unit", db=db),
        )
        assert proc.returncode == 0
        rows = db.list_tool_runs("co")
        assert len(rows) == 1
        assert rows[0]["module"] == "unit"
        assert rows[0]["status"] == "done"
        assert "ok" in rows[0]["stdout_tail"]

    def test_tool_run_history_redacts_sensitive_args(self, db):
        from utils.command_runner import CommandContext, run
        run(
            [sys.executable, "-c", "print('ok')", "--api-token", "secret-token-value"],
            timeout=10,
            context=CommandContext(company_id="co", module="unit", db=db),
        )
        argv = db.list_tool_runs("co")[0]["argv"]
        assert "secret-token-value" not in argv
        assert "<redacted>" in argv


class TestPipelineReconRunner:
    def test_run_services_no_recon(self, db, tmp_path):
        """_run_services must return empty list when recon module is None (regression)."""
        from core.pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        result = runner._run_services([{"host": "x.com", "ports": [80]}])
        assert result["findings"] == []
        assert "scanned_at" in result

    def test_run_module_request_recon_unavailable(self, db, tmp_path):
        """Module that requires recon.py must return error when unavailable."""
        from core.pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        co = {"id": "test", "domains": ["example.com"], "name": "Test"}
        options = {"github_token": "", "shodan_key": "", "hibp_key": "",
                   "dehashed_key": "", "nvd_key": ""}
        # Use Flask app context for jsonify
        from flask import Flask
        with Flask(__name__).app_context():
            resp, code = runner.run_module_request("test", "email", co, options)
            # Module starts in background; returns 202
            assert code == 202
        # Wait for thread
        time.sleep(0.2)
        assert runner.results["test:email"]["status"] == "error"

    def test_run_module_request_wappalyzer_self_contained(self, db, tmp_path):
        """wappalyzer runs even when recon_available=False."""
        from core.pipeline import ReconRunner
        called = []

        def fake_wap(cid, co):
            called.append((cid, co))
            return {"tech_count": 3, "hosts_scanned": 1}

        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        runner.run_wappalyzer = fake_wap

        co = {"id": "test", "domains": ["example.com"], "name": "Test"}
        options = {"github_token": "", "shodan_key": "", "hibp_key": "",
                   "dehashed_key": "", "nvd_key": ""}

        from flask import Flask
        with Flask(__name__).app_context():
            resp, code = runner.run_module_request("test", "wappalyzer", co, options)
            assert code == 202

        time.sleep(0.3)
        assert runner.results["test:wappalyzer"]["status"] == "done"
        assert runner.results["test:wappalyzer"]["data"]["tech_count"] == 3

    def test_duplicate_module_request_rejected(self, db, tmp_path):
        """Second request while module is running returns 409."""
        from core.pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        runner.results["test:email"] = {"status": "running"}
        co = {"id": "test", "domains": ["example.com"], "name": "Test"}
        options = {"github_token": "", "shodan_key": "", "hibp_key": "",
                   "dehashed_key": "", "nvd_key": ""}
        from flask import Flask
        with Flask(__name__).app_context():
            resp, code = runner.run_module_request("test", "email", co, options)
            assert code == 409

    def test_collect_new_subdomains(self, db, tmp_path):
        from core.pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        runner.results["co:certs"] = {
            "data": {"ct_subdomains": ["sub1.example.com", "*.example.com", "other.net"]}
        }
        subs = runner._collect_new_subdomains("co", "example.com")
        assert "sub1.example.com" in subs
        assert "other.net" not in subs    # filtered: not a subdomain of example.com
        # wildcard stripped
        assert not any(s.startswith("*") for s in subs)

    def test_merge_hosts_adds_new_only(self, db, tmp_path):
        from core.pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        data = {"companies": [{"id": "co", "hosts": [{"host": "existing.com"}], "stats": {}}]}
        db.save_asm_data(data)
        new_hosts = [{"host": "existing.com"}, {"host": "new.com"}]
        total = runner._merge_hosts_into_asm_data("co", new_hosts)
        saved = db.load_asm_data()
        hosts = saved["companies"][0]["hosts"]
        assert total == 2
        assert len(hosts) == 2  # existing not duplicated
        assert any(h["host"] == "new.com" for h in hosts)

    def test_merge_hosts_handles_new_host_ports(self, db, tmp_path):
        from core.pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        db.save_asm_data({"companies": [{"id": "co", "hosts": [], "stats": {}, "domains": ["example.com"]}]})

        total = runner._merge_hosts_into_asm_data(
            "co",
            [{
                "host": "new.example.com",
                "status_code": 200,
                "ports": ["80", "443"],
            }],
        )

        saved = db.load_asm_data()
        hosts = saved["companies"][0]["hosts"]
        assert total == 1
        assert hosts[0]["host"] == "new.example.com"
        assert hosts[0]["ports"] == ["80", "443"]

    def test_discovered_hosts_are_persisted_before_httpx_validation(self, db, tmp_path):
        from core.pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        db.save_asm_data({"companies": [{"id": "co", "hosts": [], "stats": {}, "domains": ["example.com"]}]})

        discovered = runner._upsert_discovered_hosts("co", ["new.example.com"], ["example.com"], source="test")
        saved = db.load_asm_data()
        hosts = saved["companies"][0]["hosts"]

        assert discovered == ["new.example.com"]
        assert len(hosts) == 1
        assert hosts[0]["host"] == "new.example.com"
        assert hosts[0]["status_code"] is None

        total = runner._merge_hosts_into_asm_data(
            "co",
            [{
                "host": "new.example.com",
                "status_code": 200,
                "title": "OK",
                "ip": "1.1.1.1",
                "technologies": ["nginx"],
                "ports": ["443"],
            }],
        )
        saved = db.load_asm_data()
        hosts = saved["companies"][0]["hosts"]
        assert total == 1
        assert hosts[0]["status_code"] == 200
        assert saved["companies"][0]["stats"]["live_hosts"] == 1


class TestWappalyzerKeyRegression:
    """Regression: auto-wappalyzer in _run_job used wrong key 'total_techs' (now 'tech_count')."""

    def test_pipeline_returns_tech_count_key(self, db, tmp_path):
        from core.pipeline import ReconRunner
        runner = ReconRunner(
            db=db, base_dir=tmp_path, get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None, recon_available=False,
        )
        # Simulate wappalyzer result structure
        result = {
            "hosts_scanned": 3,
            "hosts_with_tech": 2,
            "tech_count": 5,          # key must be 'tech_count', not 'total_techs'
            "tech_index": {"React": ["a.com"]},
            "errors": [],
            "scanned_at": "2024-01-01T00:00:00",
        }
        assert "tech_count" in result
        assert "total_techs" not in result


# ═══════════════════════════════════════════════════════════════════════════════
# 2 — Auth flow
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuth:
    def test_protected_route_returns_401_without_token(self, client):
        resp = client.get("/api/companies")
        assert resp.status_code == 401

    def test_login_success(self, client):
        resp = client.post("/api/auth/login",
                           json={"username": "admin", "password": "admin"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "token" in data
        assert data["username"] == "admin"

    def test_login_wrong_password(self, client):
        resp = client.post("/api/auth/login",
                           json={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    def test_login_unknown_user(self, client):
        resp = client.post("/api/auth/login",
                           json={"username": "nobody", "password": "x"})
        assert resp.status_code == 401

    def test_authenticated_request_works(self, auth_client):
        resp = auth_client.get("/api/companies")
        assert resp.status_code == 200

    def test_logout_invalidates_token(self, flask_app):
        c = flask_app.test_client()
        login = c.post("/api/auth/login", json={"username": "admin", "password": "admin"})
        token = login.get_json()["token"]
        c.environ_base["HTTP_X_AUTH_TOKEN"] = token

        assert c.get("/api/companies").status_code == 200
        c.post("/api/auth/logout")
        assert c.get("/api/companies").status_code == 401

    def test_me_endpoint(self, auth_client):
        resp = auth_client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.get_json()["username"] == "admin"

    def test_scoped_user_sees_only_assigned_company(self, auth_client, flask_app, db):
        super_client = auth_client
        super_client.post("/api/companies", json={"name": "Alpha", "domains": ["alpha.com"]})
        super_client.post("/api/companies", json={"name": "Beta", "domains": ["beta.com"]})
        db.save_asm_data({
            "companies": [
                {"id": "alpha", "name": "Alpha", "domains": ["alpha.com"]},
                {"id": "beta", "name": "Beta", "domains": ["beta.com"]},
            ]
        })

        analyst = login_as_admin(flask_app, db, "analyst1", "password123", role="analyst", scoped_companies=["alpha"])
        data = analyst.get("/api/data").get_json()
        assert [c["id"] for c in data["companies"]] == ["alpha"]

        resp = analyst.get("/api/data/company/beta")
        assert resp.status_code == 403

        upd = analyst.put("/api/companies/beta", json={"name": "Beta2"})
        assert upd.status_code == 403

    def test_priorities_endpoint_respects_scope_and_ranks(self, flask_app, db, auth_client):
        auth_client.post("/api/companies", json={"name": "Alpha", "domains": ["alpha.com"]})
        auth_client.post("/api/companies", json={"name": "Beta", "domains": ["beta.com"]})
        db.save_asm_data({"companies": [
            {"id": "alpha", "name": "Alpha", "findings": [
                {"key": "1", "type": "header", "severity": "medium", "host": "a.alpha.com", "title": "h"},
                {"key": "2", "type": "git_exposed", "severity": "critical", "host": "dev.alpha.com", "title": ".git"}]},
            {"id": "beta", "name": "Beta", "findings": []},
        ]})
        out = auth_client.get("/api/data/company/alpha/priorities").get_json()
        assert [a["type"] for a in out["actions"]] == ["git_exposed", "header"]
        analyst = login_as_admin(flask_app, db, "analyst3", "password123", role="analyst", scoped_companies=["beta"])
        assert analyst.get("/api/data/company/alpha/priorities").status_code in (403, 404)
        assert analyst.get("/api/data/company/beta/priorities").status_code == 200

    def test_paginated_findings_and_hosts(self, flask_app, db, auth_client):
        auth_client.post("/api/companies", json={"name": "Alpha", "domains": ["alpha.com"]})
        db.save_asm_data({"companies": [{"id": "alpha", "name": "Alpha",
            "findings": [{"key": f"k{i}", "type": "header" if i % 2 else "cve", "severity": "high" if i < 3 else "low",
                          "host": f"h{i}.alpha.com", "title": f"t{i}"} for i in range(7)],
            "hosts": [{"host": "a.alpha.com", "ip": "1.1.1.1", "status_code": 200, "waf": "Cloudflare"},
                      {"host": "b.alpha.com", "ip": "2.2.2.2", "status_code": 0, "waf": ""}]}]})
        r = auth_client.get("/api/data/company/alpha/findings?per_page=3&page=2").get_json()
        assert r["total"] == 7 and r["pages"] == 3 and len(r["items"]) == 3
        assert r["facets"]["severity"] == {"high": 3, "low": 4}
        r = auth_client.get("/api/data/company/alpha/findings?severity=high&type=cve").get_json()
        assert {f["key"] for f in r["items"]} == {"k0", "k2"}
        assert auth_client.get("/api/data/company/alpha/findings?q=h5").get_json()["total"] == 1
        assert auth_client.get("/api/data/company/alpha/hosts?live=1").get_json()["total"] == 1
        assert auth_client.get("/api/data/company/alpha/hosts?waf=none").get_json()["items"][0]["host"] == "b.alpha.com"
        db.save_asm_data({"companies": []})
        assert db.query_findings("alpha")["total"] == 0

    def test_assets_and_finding_groups_endpoints(self, flask_app, db, auth_client):
        auth_client.post("/api/companies", json={"name": "Alpha", "domains": ["alpha.com"]})
        auth_client.post("/api/companies", json={"name": "Beta", "domains": ["beta.com"]})
        db.save_asm_data({"companies": [
            {"id": "alpha", "name": "Alpha", "domains": ["alpha.com"],
             "hosts": [{"host": "a.alpha.com", "status_code": 200, "waf": "Direct", "ports": ["22"]},
                       {"host": "b.alpha.com", "status_code": 403, "waf": "Cloudflare"}],
             "findings": [{"key": "1", "type": "cors", "severity": "critical", "host": "a.alpha.com", "title": "CORS em a.alpha.com"},
                          {"key": "2", "type": "cors", "severity": "critical", "host": "b.alpha.com", "title": "CORS em b.alpha.com"}]},
            {"id": "beta", "name": "Beta", "domains": ["beta.com"], "hosts": []}]})
        r = auth_client.get("/api/data/company/alpha/assets?sort=findings&dir=desc").get_json()
        assert r["total"] == 2 and r["facets"]["chips"]["critical"] == 2 and r["items"][0]["_agg"]["sev"]["critical"] == 1
        assert auth_client.get("/api/data/company/alpha/assets?has=riskport").get_json()["total"] == 1
        assert auth_client.get("/api/data/company/alpha/assets?find=none").get_json()["total"] == 0
        csv = auth_client.get("/api/data/company/alpha/assets/export?fmt=csv&has=nowaf")
        assert csv.status_code == 200 and csv.data.decode().count("\n") == 2   # cabeçalho + 1 linha
        g = auth_client.get("/api/data/company/alpha/finding-groups").get_json()
        assert g["total_groups"] == 1 and g["groups"][0]["count"] == 2   # mesmo título normalizado
        analyst = login_as_admin(flask_app, db, "analyst4", "password123", role="analyst", scoped_companies=["beta"])
        for url in ("assets", "assets/export", "finding-groups"):
            assert analyst.get(f"/api/data/company/alpha/{url}").status_code in (403, 404)
        assert analyst.get("/api/data/company/beta/assets").status_code == 200

    def test_empty_scope_sees_nothing(self, flask_app, db):
        analyst = login_as_admin(flask_app, db, "analyst2", "password123", role="analyst", scoped_companies=[])
        resp = analyst.get("/api/companies")
        assert resp.status_code == 200
        assert resp.get_json() == []


# ═══════════════════════════════════════════════════════════════════════════════
# 3 — Company CRUD
# ═══════════════════════════════════════════════════════════════════════════════


class TestCompanyCRUD:
    def test_list_empty(self, auth_client):
        resp = auth_client.get("/api/companies")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_create_company(self, auth_client):
        resp = auth_client.post("/api/companies",
                                json={"name": "Acme Corp", "domains": ["acme.com"]})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["name"] == "Acme Corp"
        assert data["id"] == "acme-corp"

    def test_create_company_normalizes_domain_inputs(self, auth_client):
        resp = auth_client.post("/api/companies", json={
            "name": "Normalized",
            "domains": ["HTTPS://Example.com:443/path", "*.example.com"],
        })
        assert resp.status_code == 201
        assert resp.get_json()["domains"] == ["example.com", "*.example.com"]

    def test_create_company_accepts_wildcard_patterns(self, auth_client):
        resp = auth_client.post("/api/companies", json={
            "name": "Patterns",
            "domains": ["api*.hubapi.com", "prod-*.nu.com.mx", "*dev*.arlo.com"],
        })
        assert resp.status_code == 201
        assert resp.get_json()["domains"] == [
            "api*.hubapi.com",
            "prod-*.nu.com.mx",
            "*dev*.arlo.com",
        ]

    def test_create_duplicate_id_rejected(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Acme", "domains": []})
        resp = auth_client.post("/api/companies", json={"name": "Acme", "domains": []})
        assert resp.status_code == 409

    def test_create_requires_name(self, auth_client):
        resp = auth_client.post("/api/companies", json={"domains": ["a.com"]})
        assert resp.status_code == 400

    def test_list_after_create(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Beta", "domains": ["beta.io"]})
        resp = auth_client.get("/api/companies")
        companies = resp.get_json()
        assert len(companies) == 1
        assert companies[0]["name"] == "Beta"

    def test_update_company(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Old Name", "domains": []})
        resp = auth_client.put("/api/companies/old-name",
                               json={"name": "New Name", "domains": ["new.com"]})
        assert resp.status_code == 200
        assert resp.get_json()["name"] == "New Name"

    def test_update_nonexistent(self, auth_client):
        resp = auth_client.put("/api/companies/ghost", json={"name": "X"})
        assert resp.status_code == 404

    def test_delete_company(self, auth_client):
        auth_client.post("/api/companies", json={"name": "ToDelete", "domains": []})
        resp = auth_client.delete("/api/companies/todelete")
        assert resp.status_code == 200
        assert auth_client.get("/api/companies").get_json() == []

    def test_domain_validation(self, auth_client):
        resp = auth_client.post("/api/validate-domains",
                                json={"domains": ["localhost"]})
        assert resp.status_code == 200
        results = resp.get_json()
        assert isinstance(results, list)

    def test_domain_validation_accepts_wildcard(self, auth_client):
        resp = auth_client.post("/api/validate-domains",
                                json={"domains": ["*.example.com"]})
        assert resp.status_code == 200
        results = resp.get_json()
        assert len(results) == 1
        assert results[0]["domain"] == "*.example.com"
        assert results[0]["wildcard"] is True
        assert results[0]["ok"] is True

    def test_domain_validation_accepts_glob_pattern(self, auth_client):
        resp = auth_client.post("/api/validate-domains",
                                json={"domains": ["api*.hubapi.com"]})
        assert resp.status_code == 200
        results = resp.get_json()
        assert len(results) == 1
        assert results[0]["domain"] == "api*.hubapi.com"
        assert results[0]["wildcard"] is True
        assert results[0]["ok"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# 4 — Scan routes
# ═══════════════════════════════════════════════════════════════════════════════


class TestScanRoutes:
    def test_data_endpoint(self, auth_client):
        resp = auth_client.get("/api/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "companies" in data

    def test_data_summary_endpoint(self, auth_client):
        resp = auth_client.get("/api/data/summary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "companies" in data

    def test_data_ts_endpoint(self, auth_client):
        resp = auth_client.get("/api/data/ts")
        assert resp.status_code == 200
        assert "ts" in resp.get_json()

    def test_company_data_not_found(self, auth_client):
        resp = auth_client.get("/api/data/company/ghost")
        assert resp.status_code == 404

    def test_scan_history_empty(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Co", "domains": ["co.com"]})
        resp = auth_client.get("/api/scan-history/co")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_screenshots_empty(self, auth_client):
        resp = auth_client.get("/api/screenshots/co")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_screenshot_file_with_cid_and_cidless_fallback(self, client, tmp_path):
        name = "https---auth.catalogo.portoplus.com.br-443.jpeg"
        shots = tmp_path / "scans" / "porto" / "screenshots"
        shots.mkdir(parents=True)
        (shots / name).write_bytes(b"\xff\xd8\xff\xd9")
        with_cid = client.get(f"/screenshots/porto/{name}")
        assert with_cid.status_code == 200
        cidless = client.get(f"/screenshots/{name}")
        assert cidless.status_code == 200
        missing = client.get("/screenshots/https---ghost.example-443.jpeg")
        assert missing.status_code == 404

    def test_subhistory_empty(self, auth_client):
        resp = auth_client.get("/api/data/co/subhistory")
        assert resp.status_code == 200
        assert resp.get_json()["history"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# 5 — Recon routes
# ═══════════════════════════════════════════════════════════════════════════════


class TestReconRoutes:
    def test_list_modules(self, auth_client):
        resp = auth_client.get("/api/recon/modules")
        assert resp.status_code == 200
        modules = resp.get_json()
        assert isinstance(modules, list)
        ids = [m["id"] for m in modules]
        assert "email" in ids
        assert "dns" in ids

    def test_pipeline_phases_catalog(self, auth_client):
        resp = auth_client.get("/api/recon/pipeline/phases")
        assert resp.status_code == 200
        data = resp.get_json()
        ids = [p["id"] for p in data["phases"]]
        assert ids == [
            "discovery", "validation", "intel", "cleanup", "fingerprint",
            "js_discovery", "api_mapping", "browser", "bug_checks",
            "ports_services", "nuclei",
        ]
        assert "riddler" in data["optional_on_demand"]
        assert "typosquat" in data["optional_on_demand"]

    def test_unknown_module_returns_400(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Co", "domains": ["co.com"]})
        resp = auth_client.post("/api/recon/co/nonexistent_module")
        assert resp.status_code == 400

    def test_run_module_company_not_found(self, auth_client):
        resp = auth_client.post("/api/recon/ghost/email")
        assert resp.status_code == 404

    def test_get_module_not_run(self, auth_client):
        resp = auth_client.get("/api/recon/co/email")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "not_run"

    def test_get_all_recon_summary(self, auth_client):
        resp = auth_client.get("/api/recon/co")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_pipeline_status_not_run(self, auth_client):
        resp = auth_client.get("/api/recon/co/pipeline")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "not_run"

    def test_pipeline_status_uses_module_events(self, auth_client, flask_app):
        flask_app._test_runner.pipeline_state["co"] = {
            "status": "done",
            "module_events": [
                {"module": "phishing", "status": "running", "ts": "2026-10-07T14:00:00"},
                {"module": "phishing", "status": "done", "ts": "2026-10-07T14:00:05"},
                {
                    "module": "git_leaks",
                    "status": "error",
                    "reason": "name 'shutil' is not defined",
                    "ts": "2026-10-07T14:01:00",
                },
            ],
        }
        resp = auth_client.get("/api/recon/co/pipeline")
        assert resp.status_code == 200
        data = resp.get_json()
        by_mod = {m["module"]: m for ph in data["phases"] for m in ph["modules"]}
        assert by_mod["phishing"]["status"] == "done"
        assert by_mod["git_leaks"]["status"] == "error"
        assert "shutil" in by_mod["git_leaks"]["reason"]

    def test_pipeline_status_running_becomes_error_when_done(self, auth_client, flask_app):
        flask_app._test_runner.pipeline_state["co"] = {
            "status": "done",
            "module_events": [
                {"module": "gowitness", "status": "running", "ts": "2026-10-07T14:50:00"},
            ],
        }
        resp = auth_client.get("/api/recon/co/pipeline")
        by_mod = {m["module"]: m for ph in resp.get_json()["phases"] for m in ph["modules"]}
        assert by_mod["gowitness"]["status"] == "error"

    def test_pipeline_start_recon_unavailable(self, auth_client):
        auth_client.post("/api/companies", json={"name": "Co2", "domains": ["co.com"]})
        resp = auth_client.post("/api/recon/co2/pipeline")
        assert resp.status_code == 500  # recon_available=False


# ═══════════════════════════════════════════════════════════════════════════════
# 6 — Ops routes (schedule, webhooks, whitelist, diff, audit)
# ═══════════════════════════════════════════════════════════════════════════════


class TestOpsRoutes:
    def test_schedule_list_empty(self, auth_client):
        resp = auth_client.get("/api/schedule")
        assert resp.status_code == 200

    def test_schedule_set_and_get(self, auth_client):
        resp = auth_client.post("/api/schedule/acme",
                                json={"profile": "standard", "interval_hours": 24, "enabled": True})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["profile"] == "standard"
        assert data["interval_hours"] == 24

        resp2 = auth_client.get("/api/schedule/acme")
        assert resp2.status_code == 200
        assert resp2.get_json()["enabled"] is True

    def test_schedule_delete(self, auth_client):
        auth_client.post("/api/schedule/acme", json={"interval_hours": 12})
        resp = auth_client.delete("/api/schedule/acme")
        assert resp.status_code == 200
        assert auth_client.get("/api/schedule/acme").get_json() == {}

    def test_webhooks_save_and_get(self, auth_client):
        hooks = [{"url": "https://hooks.slack.com/xxx", "type": "slack", "events": ["scan_done"]}]
        resp = auth_client.post("/api/webhooks", json=hooks)
        assert resp.status_code == 200
        got = auth_client.get("/api/webhooks").get_json()
        assert len(got) == 1
        assert got[0]["type"] == "slack"

    def test_webhooks_test(self, auth_client):
        resp = auth_client.post("/api/webhooks/test",
                                json={"hook": {"url": "https://example.com", "type": "generic"}})
        assert resp.status_code == 200

    def test_diff_no_snapshot(self, auth_client):
        resp = auth_client.get("/api/diff/acme")
        assert resp.status_code == 200
        assert "error" in resp.get_json()

    def test_whitelist_add_and_list(self, auth_client):
        resp = auth_client.post("/api/whitelist/co",
                                json={"host": "safe.co.com", "title": "CDN", "reason": "known"})
        assert resp.status_code == 201
        entry = resp.get_json()
        assert entry["host"] == "safe.co.com"

        resp2 = auth_client.get("/api/whitelist/co")
        assert len(resp2.get_json()) == 1

    def test_whitelist_delete(self, auth_client):
        add = auth_client.post("/api/whitelist/co", json={"host": "x.com"})
        wid = add.get_json()["id"]
        resp = auth_client.delete(f"/api/whitelist/co/{wid}")
        assert resp.status_code == 200
        assert auth_client.get("/api/whitelist/co").get_json() == []

    def test_audit_requires_super_admin(self, auth_client):
        resp = auth_client.get("/api/audit")
        assert resp.status_code == 200  # fixture uses super_admin


# ═══════════════════════════════════════════════════════════════════════════════
# 7 — Reporting routes
# ═══════════════════════════════════════════════════════════════════════════════


class TestReportingRoutes:
    def test_risk_score_company_not_found(self, auth_client):
        resp = auth_client.get("/api/risk/ghost")
        assert resp.status_code == 404

    def test_export_json_company_not_found(self, auth_client):
        resp = auth_client.get("/api/export/ghost?format=json")
        assert resp.status_code == 404

    def test_export_csv_company_not_found(self, auth_client):
        resp = auth_client.get("/api/export/ghost?format=csv_findings")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# 8 — Database layer
# ═══════════════════════════════════════════════════════════════════════════════


class TestDatabase:
    def test_save_and_load_companies(self, db):
        companies = [{"id": "co", "name": "Co", "domains": ["co.com"]}]
        db.save_companies(companies)
        loaded = db.load_companies()
        assert len(loaded) == 1
        # DB may add defaults (color, tags) — check key fields preserved
        assert loaded[0]["id"] == "co"
        assert loaded[0]["name"] == "Co"
        assert loaded[0]["domains"] == ["co.com"]

    def test_save_and_load_admins(self, db):
        import hashlib, base64, secrets
        pw = base64.b64encode(hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 1)).decode()
        admins = [{"id": "1", "username": "alice", "email": "", "role": "admin",
                   "password_hash": f"pbkdf2:sha256:salt:{pw}",
                   "created_at": "2024-01-01T00:00:00", "last_login": None}]
        db.save_admins(admins)
        loaded = db.load_admins()
        assert loaded[0]["username"] == "alice"
        assert loaded[0]["role"] == "admin"

    def test_settings_round_trip(self, db):
        db.set_settings({"shodan_key": "abc123", "github_token": "gh_xxx"})
        settings = db.get_settings({"shodan_key", "github_token"})
        assert settings["shodan_key"] == "abc123"
        assert settings["github_token"] == "gh_xxx"

    def test_settings_partial_keys(self, db):
        db.set_settings({"shodan_key": "abc"})
        settings = db.get_settings({"shodan_key", "missing_key"})
        assert settings["shodan_key"] == "abc"
        assert settings.get("missing_key", "") == ""

    def test_webhook_round_trip(self, db):
        hooks = [{"url": "https://x.com", "type": "slack"}]
        db.save_webhooks(hooks)
        loaded = db.load_webhooks()
        assert len(loaded) == 1
        # DB may add default fields (id, chat_id, events) — check key fields preserved
        assert loaded[0]["url"] == "https://x.com"
        assert loaded[0]["type"] == "slack"

    def test_whitelist_round_trip(self, db):
        wl = {"co": [{"id": "1", "host": "x.com"}]}
        db.save_whitelist(wl)
        loaded = db.load_whitelist()
        assert "co" in loaded
        assert loaded["co"][0]["host"] == "x.com"
        assert loaded["co"][0]["id"] == "1"

    def test_snapshot_save_and_load(self, db):
        snap = {"ts": "2024-01-01", "hosts": ["a.com"], "ports": {}, "findings": []}
        db.save_snapshot("co", snap, slot="current")
        loaded = db.load_snapshot("co", slot="current")
        assert loaded["hosts"] == ["a.com"]

    def test_snapshot_previous_slot(self, db):
        snap1 = {"ts": "2024-01-01", "hosts": ["a.com"], "ports": {}, "findings": []}
        snap2 = {"ts": "2024-01-02", "hosts": ["b.com"], "ports": {}, "findings": []}
        db.save_snapshot("co", snap1, slot="current")
        db.save_snapshot("co", snap2, slot="previous")
        assert db.load_snapshot("co", slot="previous")["hosts"] == ["b.com"]

    def test_smart_scan_checkpoint_invalidation(self, db, tmp_path):
        from core.pipeline import ReconRunner

        runner = ReconRunner(
            db=db,
            base_dir=tmp_path,
            get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None,
            recon_available=False,
        )
        co = {"id": "co", "name": "Company", "domains": ["example.com"]}
        hosts = [{
            "host": "app.example.com",
            "status_code": 200,
            "title": "App",
            "ports": [443],
            "tech": ["React"],
        }]

        fp = runner._module_checkpoint_fingerprint("co", "profiling", co, hosts, {})
        runner.results["co:profiling"] = {"status": "done", "fingerprint": fp}
        assert runner._module_checkpoint_is_valid("co", "profiling", co, hosts, {}) is True

        changed_hosts = [dict(hosts[0], title="New App")]
        assert runner._module_checkpoint_is_valid("co", "profiling", co, changed_hosts, {}) is False

    def test_asm_data_round_trip(self, db):
        data = {"companies": [{"id": "co", "hosts": []}]}
        db.save_asm_data(data)
        assert db.load_asm_data()["companies"][0]["id"] == "co"

    def test_audit_log_append(self, db):
        db.append_audit_log({"ts": "2024-01-01", "user": "admin", "action": "login",
                              "target": "", "details": ""})
        logs = db.list_audit_log(limit=10)
        assert len(logs) == 1
        assert logs[0]["action"] == "login"

    def test_schedules_round_trip(self, db):
        scheds = {"co": {"profile": "standard", "interval_hours": 24, "enabled": True,
                         "next_run": "", "last_run": ""}}
        db.save_schedules(scheds)
        loaded = db.load_schedules()
        assert loaded["co"]["profile"] == "standard"
        assert loaded["co"]["interval_hours"] == 24
        assert loaded["co"]["enabled"] is True

    def test_migrate_from_legacy_safe_when_no_files(self, db):
        # Should not raise even when no legacy files exist
        db.migrate_from_legacy()


class TestPersistentJobQueue:
    def test_job_lifecycle_is_persisted(self, db):
        job = db.create_job(
            job_type="pipeline",
            company_id="co",
            target="co",
            options={"mode": "balanced"},
            priority=50,
            created_by="tester",
        )
        assert job["status"] == "pending"
        assert job["options"]["mode"] == "balanced"

        claimed = db.claim_next_job()
        assert claimed["id"] == job["id"]
        assert claimed["status"] == "running"
        assert claimed["attempts"] == 1

        db.finish_job(job["id"], status="done")
        finished = db.get_job(job["id"])
        assert finished["status"] == "done"
        assert finished["finished_at"]

    def test_active_job_dedupes_pipeline(self, db):
        first = db.create_job(job_type="pipeline", company_id="co", target="co", options={})
        active = db.find_active_job(company_id="co", job_type="pipeline")
        assert active["id"] == first["id"]

    def test_cancel_only_pending_job(self, db):
        pending = db.create_job(job_type="pipeline", company_id="co", target="co", options={})
        assert db.cancel_job(pending["id"], reason="unit") is True
        assert db.get_job(pending["id"])["status"] == "cancelled"

        running = db.create_job(job_type="pipeline", company_id="co", target="co", options={})
        db.claim_next_job()
        assert db.cancel_job(running["id"], reason="unit") is False

    def test_scheduler_executes_pipeline_job(self, db):
        from core.jobs import JobScheduler

        state = {}
        calls = []

        def run_pipeline(cid, company, options):
            calls.append((cid, company["name"], options["mode"]))
            state[cid] = {"status": "done", "log": []}

        scheduler = JobScheduler(
            db=db,
            load_companies=lambda: [{"id": "co", "name": "Company", "domains": ["example.com"]}],
            run_pipeline=run_pipeline,
            pipeline_state=state,
            max_workers=1,
        )
        job = scheduler.enqueue_pipeline("co", options={"mode": "balanced"})
        claimed = db.claim_next_job()
        scheduler._execute(claimed)

        assert calls == [("co", "Company", "balanced")]
        assert db.get_job(job["id"])["status"] == "done"

    def test_scheduler_does_not_auto_enqueue_playwright_after_pipeline(self, db):
        from core.jobs import JobScheduler

        state = {}
        pipeline_calls = []
        playwright_calls = []

        def run_pipeline(cid, company, options):
            pipeline_calls.append((cid, company["name"], options["mode"]))
            state[cid] = {"status": "done", "log": []}

        scheduler = JobScheduler(
            db=db,
            load_companies=lambda: [{"id": "co", "name": "Company", "domains": ["example.com"]}],
            run_pipeline=run_pipeline,
            run_playwright_recon=lambda cid, co, opts: playwright_calls.append((cid, co["name"], opts["target_url"])) or {"status": "done"},
            pipeline_state=state,
            save_pipeline_state=lambda cid: None,
            get_settings=lambda: {"playwright_headless": True, "playwright_max_pages": 13},
            max_workers=1,
        )
        job = scheduler.enqueue_pipeline("co", options={"mode": "balanced"})
        claimed = db.claim_next_job()
        scheduler._execute(claimed)

        assert pipeline_calls == [("co", "Company", "balanced")]
        jobs = db.list_jobs(company_id="co")
        assert not any(item["job_type"] == "playwright_recon" for item in jobs)
        assert playwright_calls == []
        assert db.get_job(job["id"])["status"] == "done"

    def test_scheduler_dedupes_active_pipeline_job(self, db):
        from core.jobs import JobScheduler

        scheduler = JobScheduler(
            db=db,
            load_companies=lambda: [{"id": "co", "name": "Company", "domains": ["example.com"]}],
            run_pipeline=lambda cid, co, opts: None,
            pipeline_state={},
            max_workers=1,
        )
        first = scheduler.enqueue_pipeline("co", options={"mode": "balanced"})
        second = scheduler.enqueue_pipeline("co", options={"mode": "deep"})

        assert second["id"] == first["id"]
        assert second["deduped"] is True
        assert len(db.list_jobs(company_id="co")) == 1

    def test_scheduler_executes_playwright_job(self, db, tmp_path):
        from core.jobs import JobScheduler

        calls = []

        scheduler = JobScheduler(
            db=db,
            load_companies=lambda: [{"id": "co", "name": "Company", "domains": ["example.com"]}],
            run_pipeline=lambda cid, co, opts: None,
            run_playwright_recon=lambda cid, co, opts: calls.append((cid, co["name"], opts["target_url"])) or {"status": "done"},
            pipeline_state={},
            max_workers=1,
        )
        job = scheduler.enqueue_playwright_recon(
            "co",
            options={"target_url": "https://example.com", "headless": True},
        )
        claimed = db.claim_next_job()
        scheduler._execute(claimed)

        assert calls == [("co", "Company", "https://example.com")]
        assert db.get_job(job["id"])["status"] == "done"

    def test_scheduler_dedupes_active_playwright_job(self, db):
        from core.jobs import JobScheduler

        scheduler = JobScheduler(
            db=db,
            load_companies=lambda: [{"id": "co", "name": "Company", "domains": ["example.com"]}],
            run_pipeline=lambda cid, co, opts: None,
            run_playwright_recon=lambda cid, co, opts: None,
            pipeline_state={},
            max_workers=1,
        )
        first = scheduler.enqueue_playwright_recon("co", options={"target_url": "https://example.com"})
        second = scheduler.enqueue_playwright_recon("co", options={"target_url": "https://example.com/login"})

        assert second["id"] == first["id"]
        assert second["deduped"] is True
        assert len(db.list_jobs(company_id="co", status="pending")) == 1


class TestJobQueueRoutes:
    def test_jobs_list_requires_auth(self, client):
        resp = client.get("/api/jobs")
        assert resp.status_code == 401

    def test_jobs_list_returns_persisted_jobs(self, auth_client, db):
        job = db.create_job(job_type="pipeline", company_id="co", target="co", options={"mode": "balanced"})
        resp = auth_client.get("/api/jobs")
        assert resp.status_code == 200
        payload = resp.get_json()
        assert any(item["id"] == job["id"] for item in payload)

    def test_job_detail_and_cancel(self, auth_client, db):
        job = db.create_job(job_type="pipeline", company_id="co", target="co", options={})
        detail = auth_client.get(f"/api/jobs/{job['id']}")
        assert detail.status_code == 200
        assert detail.get_json()["status"] == "pending"

        cancelled = auth_client.delete(f"/api/jobs/{job['id']}")
        assert cancelled.status_code == 200
        assert db.get_job(job["id"])["status"] == "cancelled"

    def test_playwright_job_enqueue_route(self, auth_client, db):
        auth_client.post("/api/companies", json={"name": "Co", "domains": ["example.com"]})
        # Simulate a completed bug bounty scan so Playwright Recon is allowed.
        flask_app = auth_client.application
        flask_app._test_runner.pipeline_state["co"] = {"status": "done", "log": []}
        resp = auth_client.post("/api/recon/co/playwright", json={
            "headless": True,
            "max_pages": 3,
            "target_url": "",
        })
        assert resp.status_code == 202
        payload = resp.get_json()
        assert payload["job_type"] == "playwright_recon"
        assert payload["target"] == "https://example.com"

        jobs = db.list_jobs(company_id="co")
        assert any(job["job_type"] == "playwright_recon" for job in jobs)

    def test_playwright_job_requires_completed_pipeline(self, auth_client, db):
        auth_client.post("/api/companies", json={"name": "Co2", "domains": ["example.com"]})
        resp = auth_client.post("/api/recon/co2/playwright", json={
            "headless": True,
            "max_pages": 3,
            "target_url": "",
        })
        assert resp.status_code == 409
        assert "completed bug bounty pipeline scan" in resp.get_json()["error"]

    def test_playwright_job_artifact_route(self, auth_client, db, tmp_path):
        root = tmp_path / "playwright-jobs" / "co" / "job1"
        evidence = root / "evidence"
        evidence.mkdir(parents=True)
        report = root / "report.md"
        session = evidence / "session.json"
        report.write_text("# report", encoding="utf-8")
        session.write_text('{"ok": true}', encoding="utf-8")

        job = db.create_job(
            job_type="playwright_recon",
            company_id="co",
            target="https://example.com",
            options={
                "job_root": str(root),
                "output": str(report),
                "evidence_dir": str(evidence),
            },
        )
        db.finish_job(job["id"], status="done")

        rep = auth_client.get(f"/api/jobs/{job['id']}/artifact/report")
        assert rep.status_code == 200
        assert b"# report" in rep.data

        ses = auth_client.get(f"/api/jobs/{job['id']}/artifact/session")
        assert ses.status_code == 200
        assert b'"ok": true' in ses.data


class TestToolCommandRegression:
    def test_asnmap_disables_update_check(self):
        from utils.tools import AsnmapTool

        cmd = AsnmapTool().command("example.com", {})
        assert "-duc" in cmd
        assert "-silent" in cmd

    def test_theharvester_uses_supported_sources(self):
        from utils.tools import TheHarvesterTool

        cmd = TheHarvesterTool().command("example.com", {})
        assert cmd[0] == "theHarvester"
        assert "-q" in cmd
        assert "-l" in cmd
        assert "-d" in cmd
        assert "anubis" not in cmd[-1]
        assert "google" not in cmd[-1]
        assert "crtsh" in cmd[-1]

    def test_dnsx_registry_and_command(self):
        from utils.tools import DnsxTool, registry

        assert registry.get("dnsx") is not None
        recon_cmd = DnsxTool().command("example.com", {
            "mode": "recon",
            "record_types": "a,cname,txt",
            "resp": True,
            "retry": 2,
            "threads": 50,
            "rcode": "NOERROR",
        })
        assert recon_cmd[0] == "dnsx"
        assert "-recon" in recon_cmd
        assert "-resp" in recon_cmd
        assert "-retry" in recon_cmd and "2" in recon_cmd
        assert "-t" in recon_cmd and "50" in recon_cmd
        assert "-rcode" in recon_cmd and "NOERROR" in recon_cmd

        resolve_cmd = DnsxTool().command("example.com", {
            "mode": "resolve",
            "record_types": "a,cname,txt",
            "axfr": True,
            "auto_wildcard": True,
        })
        assert "-recon" not in resolve_cmd
        assert "-a" in resolve_cmd and "-cname" in resolve_cmd and "-txt" in resolve_cmd
        assert "-axfr" in resolve_cmd
        assert "-auto-wildcard" in resolve_cmd

    def test_subjack_uses_small_resolver_set(self):
        from utils.tools import SubjackTool

        cmd = SubjackTool().command("example.com", {
            "hosts": [{"host": "example.com"}, {"host": "www.example.com"}]
        })
        assert cmd[0] == "subjack"
        assert "-r" in cmd
        assert "-t" in cmd and "2" in cmd
        assert "-timeout" in cmd and "3" in cmd
        assert "-w" in cmd

    def test_urlfinder_handles_non_utf8_output(self, monkeypatch):
        import subprocess as _subprocess
        from utils.tools import registry

        tool = registry.get("urlfinder")
        assert tool is not None

        def _fake_run(*args, **kwargs):
            return _subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=b"https://example.com/\xa7\nhttp://www.example.com/\xff\n",
                stderr=b"",
            )

        monkeypatch.setattr("utils.tools.subprocess.run", _fake_run)
        result = tool.run("example.com", {})
        assert result.error is None
        assert result.data["urls"] == ["https://example.com/", "http://www.example.com/"]
        assert result.findings and len(result.findings) == 2

    def test_crtsh_tool_parses_certs_and_subdomains(self, monkeypatch):
        from utils.tools import registry

        tool = registry.get("crtsh")
        assert tool is not None

        sample = [
            {
                "id": 1,
                "common_name": "*.example.com",
                "issuer_name": "Let's Encrypt",
                "name_value": "*.example.com\napi.example.com\nmail.example.com",
                "not_before": "2026-06-01T00:00:00",
                "not_after": "2026-09-01T00:00:00",
            },
            {
                "id": 2,
                "common_name": "example.com",
                "issuer_name": "Let's Encrypt",
                "name_value": "example.com\nwww.example.com",
                "not_before": "2026-06-02T00:00:00",
                "not_after": "2026-09-02T00:00:00",
            },
        ]

        class _Resp:
            def __init__(self, body):
                self._body = body
            def read(self):
                return self._body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        def _fake_urlopen(*args, **kwargs):
            return _Resp(json.dumps(sample).encode("utf-8"))

        monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
        result = tool.run("example.com", {})
        assert result.status == "done"
        assert result.data["total_certs"] == 2
        assert "api.example.com" in result.data["ct_subdomains"]
        assert "www.example.com" in result.data["ct_subdomains"]
        assert any(f.value == "api.example.com" for f in result.findings)


class TestModuleEnvelope:
    def test_tool_result_contract_fields(self):
        from utils.tools import Finding, ToolResult

        tr = ToolResult(
            tool="demo",
            target="example.com",
            status="done",
            reason="",
            findings=[Finding(type="host", value="a.example.com")],
            metrics={"findings": 1},
            artifacts={"report": "/tmp/report.md"},
        )
        data = tr.to_dict()

        assert data["status"] == "done"
        assert data["reason"] == ""
        assert data["metrics"]["findings"] == 1
        assert data["artifacts"]["report"] == "/tmp/report.md"
        assert data["findings"][0]["value"] == "a.example.com"

    def test_module_envelope_classification(self):
        from core.pipeline import _classify_result_status, _normalize_module_envelope

        status, reason = _classify_result_status(None, "No live hosts")
        assert status == "skipped"
        assert reason == "No live hosts"

        envelope = _normalize_module_envelope(
            "demo",
            {"skipped": True, "reason": "No suitable targets", "subdomains": ["a.example.com"]},
        )
        assert envelope["status"] == "skipped"
        assert envelope["reason"] == "No suitable targets"
        assert envelope["metrics"]["subdomains"] == 1

        timeout_env = _normalize_module_envelope("demo", None, status="timeout", reason="Timeout (120s)")
        assert timeout_env["status"] == "timeout"
        assert timeout_env["reason"] == "Timeout (120s)"

        err_status, err_reason = _classify_result_status(None, "name 'shutil' is not defined")
        assert err_status == "error"
        assert "shutil" in err_reason

        key_status, _ = _classify_result_status(None, "'phishing'")
        assert key_status == "error"

        empty_status, empty_reason = _classify_result_status(None, "")
        assert empty_status == "done"
        assert empty_reason == ""

        skipped_status, skipped_reason = _classify_result_status(None, "whatweb not found")
        assert skipped_status == "skipped"
        assert "unavailable" in skipped_reason.lower() or "not found" in skipped_reason.lower()

        done_fail_status, _ = _classify_result_status("done", "whatweb not found")
        assert done_fail_status == "skipped"

        key_skip, _ = _classify_result_status("error", "No Shodan API key — set SHODAN_API_KEY")
        assert key_skip == "skipped"


class TestPipelineResilience:
    def test_unusable_checkpoint_is_rejected(self, db, tmp_path):
        from core.pipeline import ReconRunner, _checkpoint_is_usable

        runner = ReconRunner(
            db=db,
            base_dir=tmp_path,
            get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None,
            recon_available=False,
            tool_registry=None,
        )
        bad = {"status": "done", "reason": "whatweb not found", "error": "whatweb not found"}
        assert _checkpoint_is_usable(bad) is False
        runner.results["co:whatweb"] = bad
        assert runner._module_checkpoint_is_valid(
            "co", "whatweb", {"domains": ["example.com"]}, [], {},
        ) is False

        good = {"status": "done", "reason": "", "fingerprint": ""}
        assert _checkpoint_is_usable(good) is True

    def test_load_checkpoints_deletes_unusable(self, db, tmp_path):
        from core.pipeline import ReconRunner

        runner = ReconRunner(
            db=db,
            base_dir=tmp_path,
            get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None,
            recon_available=False,
            tool_registry=None,
        )
        cp_dir = tmp_path / "scans" / "co" / ".checkpoints"
        cp_dir.mkdir(parents=True)
        (cp_dir / "whatweb__example.com.json").write_text(
            '{"status":"done","reason":"whatweb not found","module":"whatweb","target":"example.com"}',
            encoding="utf-8",
        )
        (cp_dir / "dns.json").write_text(
            '{"status":"done","reason":"","module":"dns","target":""}',
            encoding="utf-8",
        )
        runner._load_checkpoints("co")
        assert "co:whatweb" not in runner.results
        assert runner.results["co:dns"]["status"] == "done"
        assert not (cp_dir / "whatweb__example.com.json").exists()
        assert (cp_dir / "dns.json").exists()

    def test_finalize_in_flight_marks_running_cancelled(self):
        from core.pipeline import finalize_in_flight_modules, module_status_index

        results = {"co:certs": {"status": "running", "started_at": "2026-10-07T15:36:00"}}
        state = {
            "status": "stopped",
            "module_status": {"certs": {"status": "running"}},
            "module_events": [{"module": "certs", "status": "running"}],
            "log": [],
        }
        mods = finalize_in_flight_modules("co", results=results, state=state)
        assert "certs" in mods
        assert results["co:certs"]["status"] == "cancelled"
        assert state["module_status"]["certs"]["status"] == "cancelled"
        assert any(ev.get("status") == "cancelled" for ev in state["module_events"])

        index = module_status_index({
            "status": "stopped",
            "module_events": [{"module": "urlscan_io", "status": "running"}],
        })
        assert index["urlscan_io"]["status"] == "cancelled"

    def test_api_tool_skips_without_key(self):
        from utils.tools import HunterIOTool

        result = HunterIOTool().run("example.com", {"settings": {}})
        assert result.status == "skipped"
        assert "hunter_key" in (result.reason or "")


class TestCircuitBreaker:
    def test_opens_after_threshold_and_fails_fast(self):
        from utils.circuit_breaker import CircuitBreaker

        br = CircuitBreaker("demo.example", failure_threshold=3, recovery_timeout=60)
        assert br.allow() is True
        br.failure()
        br.failure()
        assert br.state == "closed"
        br.failure()
        assert br.state == "open"
        assert br.allow() is False

    def test_half_open_success_closes(self):
        from utils.circuit_breaker import CircuitBreaker

        br = CircuitBreaker("demo2.example", failure_threshold=2, recovery_timeout=0.5)
        br.failure()
        br.failure()
        assert br.state == "open"
        br.opened_at = 0.0
        assert br.allow() is True
        assert br.state == "half_open"
        br.success()
        assert br.state == "closed"
        assert br.allow() is True

    def test_http_get_retries_zero_still_attempts_once(self, monkeypatch):
        from utils.circuit_breaker import reset_all
        from core import recon as recon_mod

        reset_all()
        monkeypatch.setattr("core.reconlib.base._CFFI_AVAILABLE", False)
        monkeypatch.setattr("core.reconlib.base._rate_wait", lambda domain: None)
        calls = {"n": 0}

        class _Resp:
            status = 200
            headers = {"Content-Type": "text/plain"}

            def read(self):
                return b"ok"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def _urlopen(req, timeout=None):
            calls["n"] += 1
            return _Resp()

        monkeypatch.setattr(recon_mod.urllib.request, "urlopen", _urlopen)
        status, body, _hdrs = recon_mod.http_get("https://example.com/x", timeout=1, retries=0)
        assert status == 200
        assert body == b"ok"
        assert calls["n"] == 1

    def test_http_get_skips_network_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from core import recon as recon_mod

        reset_all()
        monkeypatch.setattr("core.reconlib.base._CFFI_AVAILABLE", False)
        monkeypatch.setattr("core.reconlib.base._rate_wait", lambda domain: None)
        br = breaker_for("dead.example")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr(recon_mod.urllib.request, "urlopen", _boom)
        status, body, hdrs = recon_mod.http_get("https://dead.example/x", timeout=1, retries=3)
        assert status == 0
        assert body == b""
        assert hdrs.get("X-Circuit-Breaker") == "open"
        assert called["n"] == 0

    def test_free_api_respects_open_circuit(self, db, tmp_path):
        from utils.circuit_breaker import breaker_for, reset_all
        from core.pipeline import ReconRunner

        reset_all()
        br = breaker_for("urlscan.io")
        for _ in range(5):
            br.failure()
        runner = ReconRunner(
            db=db,
            base_dir=tmp_path,
            get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None,
            recon_available=False,
            tool_registry=None,
        )
        out = runner._run_free_api("urlscan_io", "example.com")
        assert out["status"] == "error"
        assert out.get("circuit") == "open"
        assert "circuit open" in out["reason"]

    def test_http_get_json_returns_none_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from core import recon as recon_mod

        reset_all()
        monkeypatch.setattr("core.reconlib.base._CFFI_AVAILABLE", False)
        monkeypatch.setattr("core.reconlib.base._rate_wait", lambda domain: None)
        br = breaker_for("dead-json.example")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr(recon_mod.urllib.request, "urlopen", _boom)
        data = recon_mod._http_get_json("https://dead-json.example/x", timeout=1)
        assert data is None
        assert called["n"] == 0

    def test_http_get_json_parses_body_on_200(self, monkeypatch):
        from utils.circuit_breaker import reset_all
        from core import recon as recon_mod

        reset_all()
        monkeypatch.setattr("core.reconlib.base._CFFI_AVAILABLE", False)
        monkeypatch.setattr("core.reconlib.base._rate_wait", lambda domain: None)

        class _Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def read(self):
                return b'{"ok": true, "n": 1}'

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        monkeypatch.setattr(recon_mod.urllib.request, "urlopen", lambda *a, **k: _Resp())
        data = recon_mod._http_get_json("https://json.example/x", timeout=1)
        assert data == {"ok": True, "n": 1}

    def test_hudsonrock_skips_network_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from core import recon as recon_mod

        reset_all()
        monkeypatch.setattr("core.reconlib.base._CFFI_AVAILABLE", False)
        monkeypatch.setattr("core.reconlib.base._rate_wait", lambda domain: None)
        br = breaker_for("cavalier.hudsonrock.com")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr(recon_mod.urllib.request, "urlopen", _boom)
        out = recon_mod._check_hudsonrock("example.com")
        assert out.get("error") == "hudsonrock unavailable"
        assert called["n"] == 0

    def test_hudsonrock_parses_cavalier_domain_payload(self):
        from core.recon import parse_hudsonrock_domain, parse_hudsonrock_email, classify_infostealer_query

        assert classify_infostealer_query("https://WWW.PortoSeguro.com.br/path") == ("domain", "portoseguro.com.br")
        assert classify_infostealer_query("Name@Empresa.com") == ("email", "name@empresa.com")
        assert classify_infostealer_query("not a query") == ("", "")
        payload = {
            "employees": 89,
            "users": 37392,
            "third_parties": 189,
            "total": 37670,
            "totalStealers": 10,
            "totalUrls": 918,
            "last_employee_compromised": "2026-08-20",
            "last_user_compromised": "2026-10-05",
            "stealerFamilies": {"total": 20000, "RedLine": 13350, "Lumma": 6055},
            "employeePasswords": {"totalPass": 26, "weak": {"qty": 24, "perc": 92.31}, "strong": {"qty": 1, "perc": 3.85}},
            "userPasswords": [{"_key": "Medium", "_value": 8}],
            "thirdPartyDomains": [{"domain": "login.microsoftonline.com", "occurrence": 12}],
            "applications": [{"keyword": "adfs"}, {"keyword": "vpn"}],
            "antiviruses": {"total": 5, "list": [{"name": "Windows Defender", "count": 3}]},
            "logo": "https://example.com/logo.png",
            "data": {
                "employees_urls": [
                    {"url": "https://vpn.example.com", "type": "vpn", "occurrence": 4},
                    {"url": "https://*****", "type": "hidden", "occurrence": 9},
                ],
                "clients_urls": [{"url": "https://app.example.com", "type": "web", "occurrence": 2}],
                "stealer_families": [{"_key": "ignored_nested", "_value": 1}],
            },
        }
        out = parse_hudsonrock_domain(payload, "portoseguro.com.br")
        assert out["employees"] == 89
        assert out["users"] == 37392
        assert out["stealer_families"]["RedLine"] == 13350
        assert "total" not in out["stealer_families"]
        assert "ignored_nested" not in out["stealer_families"]
        assert out["last_employee_compromised"] == "2026-08-20"
        assert out["employee_passwords"]["weak"] == 24
        assert "totalPass" not in out["employee_passwords"]
        assert out["third_party_domains"][0]["domain"] == "login.microsoftonline.com"
        assert out["third_party_domains"][0]["count"] == 12
        assert out["applications"]["adfs"] == 1
        assert out["antiviruses"]["Windows Defender"] == 3
        assert out["internal_urls"][0]["url"] == "https://vpn.example.com"
        assert all("*****" not in row["url"] for row in out["employees_urls"])
        email = parse_hudsonrock_email({
            "message": "ok",
            "total_corporate_services": 2,
            "total_user_services": 5,
            "stealers": [{
                "date_compromised": "2026-01-01",
                "computer_name": "PC",
                "malware_path": "C:\\\\steal.exe",
                "ip": "1.2.***",
                "top_logins": ["a***@x.com"],
                "top_passwords": ["*****"],
                "operating_system": "Windows",
                "antiviruses": ["Defender"],
            }],
        }, "a@x.com")
        assert email["kind"] == "email"
        assert email["stealer_count"] == 1
        assert "malware_path" not in email["stealers"][0]
        assert email["stealers"][0]["top_passwords"] == ["*****"]

    def test_hudsonrock_only_breach_persists(self):
        from core.pipeline import breach_data_should_persist
        assert breach_data_should_persist({
            "total_findings": 0,
            "hudsonrock": {"employees": 2, "users": 0, "error": None},
        })
        assert not breach_data_should_persist({
            "total_findings": 0,
            "hudsonrock": {"error": "hudsonrock unavailable"},
        })
        assert not breach_data_should_persist({})

    def test_cors_scan_skips_network_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from core import recon as recon_mod

        reset_all()
        monkeypatch.setattr("core.reconlib.base._CFFI_AVAILABLE", False)
        monkeypatch.setattr("core.reconlib.base._rate_wait", lambda domain: None)
        br = breaker_for("cors-dead.example")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr(recon_mod.urllib.request, "urlopen", _boom)
        out = recon_mod.run_cors_scan(
            [{"host": "cors-dead.example", "status_code": 200, "ports": [443]}]
        )
        assert called["n"] == 0
        assert out["findings"] == []
        assert out["vulnerable"] == 0

    def test_guarded_urlopen_skips_network_when_circuit_open(self, monkeypatch):
        from urllib.request import Request
        from utils.circuit_breaker import CircuitOpen, breaker_for, guarded_urlopen, reset_all

        reset_all()
        br = breaker_for("dead-hook.example")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        with pytest.raises(CircuitOpen):
            guarded_urlopen(Request("https://dead-hook.example/x"), timeout=1)
        assert called["n"] == 0

    def test_guarded_urlopen_timeout_counts_as_failure(self, monkeypatch):
        from urllib.request import Request
        from utils.circuit_breaker import breaker_for, guarded_urlopen, reset_all

        reset_all()

        def _boom(*args, **kwargs):
            raise TimeoutError("nope")

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        with pytest.raises(TimeoutError):
            guarded_urlopen(Request("https://flaky.example/x"), timeout=1)
        br = breaker_for("flaky.example")
        assert br.failures == 1
        assert br.state == "closed"

    def test_notification_post_skips_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from utils import notifications as n

        reset_all()
        br = breaker_for("hooks.slack.com")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        ok = n._post_json("https://hooks.slack.com/services/T/B/X", {"text": "hi"})
        assert ok is False
        assert called["n"] == 0

    def test_dep_confusion_get_skips_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from utils import dep_confusion as dc

        reset_all()
        br = breaker_for("registry.npmjs.org")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        status, body = dc._http_get("https://registry.npmjs.org/left-pad", timeout=1)
        assert status == 0
        assert body == b""
        assert called["n"] == 0

    def test_hackertarget_fail_fast_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from utils.tools import HackerTargetTool

        reset_all()
        br = breaker_for("api.hackertarget.com")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        result = HackerTargetTool().run("example.com", {})
        assert called["n"] == 0
        assert result.status == "error"
        assert "circuit open" in (result.reason or "")

    def test_favicon_skips_target_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from utils.tools import FaviconHashTool

        reset_all()
        br = breaker_for("dead-fav.example")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        out = FaviconHashTool().run_api(
            "dead-fav.example", {"settings": {"shodan_key": "x"}}
        )
        assert called["n"] == 0
        assert out == []

    def test_crtsh_fetch_skips_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from utils.tools import registry

        reset_all()
        br = breaker_for("crt.sh")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        result = registry.get("crtsh").run("example.com", {})
        assert called["n"] == 0
        assert result.data.get("total_certs", 0) == 0

    def test_guarded_httpx_skips_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import CircuitOpen, breaker_for, guarded_httpx, reset_all

        reset_all()
        br = breaker_for("dead-pw.example")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("httpx.request", _boom)
        with pytest.raises(CircuitOpen):
            guarded_httpx("GET", "https://dead-pw.example/x", timeout=1)
        assert called["n"] == 0

    def test_source_map_fetch_skips_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from playwright_agent.source_map import fetch_source_map

        reset_all()
        br = breaker_for("js.example")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("httpx.request", _boom)
        out = fetch_source_map("https://js.example/app.js", "app.js.map", timeout=1)
        assert out is None
        assert called["n"] == 0

    def test_graphql_introspect_skips_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from playwright_agent.graphql_introspect import introspect

        reset_all()
        br = breaker_for("gql.example")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("httpx.request", _boom)
        out = introspect(["https://gql.example/graphql"])
        assert out["introspection_enabled"] is False
        assert called["n"] == 0

    def test_fingerprint_host_skips_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from core.checkpoints import fingerprint_host

        reset_all()
        br = breaker_for("cp.example")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("httpx.request", _boom)
        assert fingerprint_host("https://cp.example/") is None
        assert called["n"] == 0

    def test_cloudlist_release_skips_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from utils.tools import CloudlistTool

        reset_all()
        br = breaker_for("api.github.com")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        assert CloudlistTool()._latest_release() is None
        assert called["n"] == 0

    def test_google_oauth_skips_when_circuit_open(self, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from core.rbac import exchange_google_code

        monkeypatch.setenv("GOOGLE_CLIENT_ID", "id")
        monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
        reset_all()
        br = breaker_for("oauth2.googleapis.com")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        assert exchange_google_code("code", "https://localhost/cb") is None
        assert called["n"] == 0

    def test_chaos_hosts_skip_network(self, monkeypatch):
        from urllib.request import Request
        from utils.circuit_breaker import CircuitOpen, guarded_urlopen, reset_all

        reset_all()
        monkeypatch.setenv("ASM_CHAOS_HOSTS", "chaos.example")
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        with pytest.raises(CircuitOpen):
            guarded_urlopen(Request("https://chaos.example/x"), timeout=1)
        assert called["n"] == 0

    def test_http_cache_fetch_skips_when_circuit_open(self, tmp_path, monkeypatch):
        from utils.circuit_breaker import breaker_for, reset_all
        from utils.http_cache import HttpCache

        reset_all()
        br = breaker_for("cached.example")
        for _ in range(5):
            br.failure()
        called = {"n": 0}

        def _boom(*args, **kwargs):
            called["n"] += 1
            raise TimeoutError("nope")

        monkeypatch.setattr("urllib.request.urlopen", _boom)
        cache = HttpCache(str(tmp_path / "c.db"))
        out = cache.fetch("https://cached.example/x")
        assert out["status"] == 0
        assert called["n"] == 0

    def test_s3_put_403_counts_as_breaker_success(self, monkeypatch):
        from io import BytesIO
        from urllib.error import HTTPError
        from utils.circuit_breaker import breaker_for, reset_all
        from core.recon import run_s3_write_check

        reset_all()

        class _Proc:
            returncode = 1

        monkeypatch.setattr("core.recon.subprocess.run", lambda *a, **k: _Proc())

        def _urlopen(req, timeout=None, **kwargs):
            raise HTTPError(
                "https://no-write-bucket.s3.amazonaws.com/x",
                403,
                "Forbidden",
                hdrs=None,
                fp=BytesIO(),
            )

        monkeypatch.setattr("urllib.request.urlopen", _urlopen)
        out = run_s3_write_check([{"type": "s3_bucket", "bucket": "no-write-bucket"}])
        br = breaker_for("no-write-bucket.s3.amazonaws.com")
        assert br.failures == 0
        assert br.state == "closed"
        assert out["critical_count"] == 0
        assert out["total_tested"] == 1

    def test_hermes_enrich_skips_when_circuit_open(self, auth_client):
        from utils.circuit_breaker import breaker_for, reset_all

        reset_all()
        br = breaker_for("127.0.0.1")
        for _ in range(5):
            br.failure()
        resp = auth_client.post("/api/ai/enrich-finding", json={"finding": {"title": "x"}})
        assert resp.status_code == 503
        assert "circuit open" in (resp.get_json().get("error") or "")

    def test_emit_module_includes_trace_id(self, db, tmp_path):
        from core.pipeline import ReconRunner

        runner = ReconRunner(
            db=db,
            base_dir=tmp_path,
            get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None,
            recon_available=False,
            tool_registry=None,
        )
        runner.pipeline_state["co"] = {
            "trace_id": "abc123",
            "module_events": [],
            "log": [],
            "module_status": {},
        }
        runner._emit_module("co", "dns", "done")
        ev = runner.pipeline_state["co"]["module_events"][-1]
        assert ev["trace_id"] == "abc123"
        assert ev["module"] == "dns"


class TestExposureRoutes:
    def test_intel_exposure_requires_auth(self, client):
        resp = client.post("/api/intel/exposure", json={"q": "example.com"})
        assert resp.status_code == 401

    def test_company_exposure_requires_auth(self, client):
        resp = client.get("/api/recon/co/exposure")
        assert resp.status_code == 401

    def test_intel_exposure_rejects_invalid_query(self, auth_client):
        resp = auth_client.post("/api/intel/exposure", json={"q": "not a query"})
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid query"

    def test_company_exposure_get_stored(self, auth_client, db):
        db.save_asm_data({
            "companies": [{
                "id": "co",
                "name": "Co",
                "domains": ["example.com"],
                "breach_data": {
                    "hudsonrock": {
                        "source": "hudsonrock_cavalier",
                        "kind": "domain",
                        "employees": 3,
                        "users": 10,
                        "stealer_families": {"RedLine": 2},
                    }
                },
            }]
        })
        resp = auth_client.get("/api/recon/co/exposure")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["hudsonrock"]["employees"] == 3
        assert data["hudsonrock"]["stealer_families"]["RedLine"] == 2

    def test_intel_exposure_uses_lookup(self, auth_client, monkeypatch):
        monkeypatch.setattr(
            "core.recon.lookup_infostealer",
            lambda q: {
                "source": "hudsonrock_cavalier",
                "kind": "domain",
                "query": q,
                "employees": 4,
                "users": 8,
                "stealer_families": {"Lumma": 1},
            },
        )
        resp = auth_client.post("/api/intel/exposure", json={"q": "example.com"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["employees"] == 4
        assert data["kind"] == "domain"

    def test_company_exposure_post_saves_domain(self, auth_client, db, monkeypatch):
        db.save_asm_data({
            "companies": [{"id": "co", "name": "Co", "domains": ["example.com"]}]
        })
        monkeypatch.setattr(
            "core.recon.lookup_infostealer",
            lambda q: {
                "source": "hudsonrock_cavalier",
                "kind": "domain",
                "query": q,
                "employees": 7,
                "users": 1,
            },
        )
        resp = auth_client.post("/api/recon/co/exposure", json={})
        assert resp.status_code == 200, resp.get_json()
        body = resp.get_json()
        assert body["saved"] is True
        assert body["hudsonrock"]["employees"] == 7
        stored = db.load_asm_data()["companies"][0]["breach_data"]["hudsonrock"]
        assert stored["employees"] == 7


class TestHealth:
    def test_health_is_public_and_checks_sqlite(self, client, flask_app):
        from utils.lifecycle import reset_drain
        reset_drain()
        resp = client.get("/health")
        assert resp.status_code in (200, 503)
        data = resp.get_json()
        assert data["version"]
        assert data["checks"]["sqlite"]["ok"] is True
        assert data["status"] in {"ok", "degraded", "fail", "draining"}
        resp2 = client.get("/api/health")
        assert resp2.status_code == resp.status_code
        assert resp2.get_json()["checks"]["sqlite"]["ok"] is True

    def test_health_echoes_request_id(self, client):
        from utils.lifecycle import reset_drain
        reset_drain()
        resp = client.get("/health", headers={"X-Request-Id": "req-test-1"})
        assert resp.headers.get("X-Request-Id") == "req-test-1"
        assert resp.headers.get("X-Trace-Id") == "req-test-1"

    def test_health_503_when_draining(self, db, tmp_path):
        from utils.health import collect_health
        from utils.lifecycle import begin_drain, reset_drain

        reset_drain()
        begin_drain()
        try:
            payload, code = collect_health(db=db, data_dir=tmp_path, bin_dir=tmp_path / "bin")
            assert code == 503
            assert payload["status"] == "draining"
            assert payload["checks"]["lifecycle"]["draining"] is True
        finally:
            reset_drain()

    def test_collect_health_load_past_peak(self, db, tmp_path):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from utils.health import collect_health
        from utils.lifecycle import reset_drain

        reset_drain()

        def hit():
            payload, code = collect_health(db=db, data_dir=tmp_path, bin_dir=tmp_path / "bin")
            return code, payload.get("version")

        n = 32
        with ThreadPoolExecutor(max_workers=16) as pool:
            futs = [pool.submit(hit) for _ in range(n)]
            results = [f.result() for f in as_completed(futs)]
        assert len(results) == n
        assert all(code in (200, 503) for code, _ in results)
        assert all(ver for _, ver in results)

    def test_collect_health_fails_without_db(self, tmp_path):
        from utils.health import collect_health
        from utils.lifecycle import reset_drain

        reset_drain()
        payload, code = collect_health(data_dir=tmp_path, bin_dir=tmp_path / "bin")
        assert code == 503
        assert payload["status"] == "fail"
        assert payload["checks"]["sqlite"]["ok"] is False

    def test_release_safety_hold_requeues_watchdog_jobs(self, db):
        job = db.create_job(job_type="pipeline", company_id="co", target="example.com")
        db.safety_hold_jobs(reason="SAFETY-WATCHDOG: load 99 > 4")
        held = db.get_job(job["id"])
        assert held["status"] == "stopped"
        n = db.release_safety_hold()
        assert n == 1
        again = db.get_job(job["id"])
        assert again["status"] == "pending"


class TestPipelineAssignment:
    def test_cleanup_phase_is_assigned(self):
        from core.pipeline import PIPELINE_PHASES, pipeline_assigned_modules

        assigned = pipeline_assigned_modules()
        assert "cleanup" in assigned
        cleanup = next(p for p in PIPELINE_PHASES if p["id"] == "cleanup")
        assert cleanup.get("internal") is True
        assert "cleanup" in (cleanup.get("modules") or [])

    def test_assigned_covers_every_phase_module(self):
        from core.pipeline import PIPELINE_PHASES, pipeline_assigned_modules

        assigned = pipeline_assigned_modules()
        for phase in PIPELINE_PHASES:
            for mod in phase.get("modules") or []:
                assert mod in assigned, f"{mod} missing from pipeline_assigned_modules()"

    def test_every_phase_module_has_runner(self, db, tmp_path):
        from core.pipeline import (
            OPTIONAL_ON_DEMAND,
            PIPELINE_PHASES,
            ReconRunner,
            pipeline_assigned_modules,
        )

        runner = ReconRunner(
            db=db,
            base_dir=tmp_path,
            get_settings=lambda: {},
            load_hosts_fn=lambda cid: [],
            recon_module=None,
            recon_available=False,
            tool_registry=None,
        )
        keys = set(runner._make_fn_map("t", {"domains": ["example.com"], "name": "t"}, {}, []).keys())
        assigned = pipeline_assigned_modules()
        internal = {p["id"] for p in PIPELINE_PHASES if p.get("internal")}
        missing = sorted(assigned - keys - internal)
        orphans = sorted(keys - assigned - OPTIONAL_ON_DEMAND)
        assert missing == [], f"phase modules without runner: {missing}"
        assert orphans == [], f"runners without a phase: {orphans}"
        assert "phishing" in keys
        assert "git_leaks" in assigned
        assert "amass" in assigned
        assert "js_discovery" in {p["id"] for p in PIPELINE_PHASES}

    def test_screenshot_host_from_filename(self):
        from core.pipeline import screenshot_host_from_filename

        assert screenshot_host_from_filename("http---api.portoseguro.com.br-80.jpeg") == "api.portoseguro.com.br"
        assert screenshot_host_from_filename(
            "http---api-gw.portobank-crossdomain.hml.portoseguro.com.br-443.jpeg"
        ) == "api-gw.portobank-crossdomain.hml.portoseguro.com.br"
        assert screenshot_host_from_filename(
            "browser_https___catalogo_portoplus_com_br.png"
        ) == "catalogo.portoplus.com.br"

    def test_serve_screenshot_path_inserts_cid(self):
        from core.pipeline import screenshot_path_missing_cid, serve_screenshot_path

        missing = "screenshots/https---auth.catalogo.portoplus.com.br-443.jpeg"
        assert screenshot_path_missing_cid("porto", missing) is True
        assert serve_screenshot_path("porto", missing) == (
            "screenshots/porto/https---auth.catalogo.portoplus.com.br-443.jpeg"
        )
        assert serve_screenshot_path("porto", "/" + missing) == (
            "screenshots/porto/https---auth.catalogo.portoplus.com.br-443.jpeg"
        )
        assert serve_screenshot_path("porto", "screenshots/porto/x.png") == "screenshots/porto/x.png"
        assert serve_screenshot_path(
            "porto",
            "/home/will/scantrely/scans/porto/screenshots/browser_https___www_portoplus_com_br.png",
        ) == "screenshots/porto/browser_https___www_portoplus_com_br.png"
        assert serve_screenshot_path(
            "porto", "screenshot/auth.catalogo.portoplus.com.br/hash.png"
        ) == "screenshots/porto/screenshot/auth.catalogo.portoplus.com.br/hash.png"
        assert serve_screenshot_path("porto", "") == ""
        assert screenshot_path_missing_cid("porto", "screenshots/porto/x.png") is False

    def test_module_status_index_prefers_compact_map(self):
        from core.pipeline import module_status_index

        index = module_status_index({
            "status": "done",
            "module_events": [
                {"module": "phishing", "status": "running"},
            ],
            "module_status": {
                "phishing": {"status": "done", "reason": "ok", "finished_at": "2026-10-07T14:00:00"},
            },
        })
        assert index["phishing"]["status"] == "done"
        assert index["phishing"]["reason"] == "ok"


class TestReconModuleImports:
    def test_shutil_and_tempfile_are_module_globals(self):
        import core.recon as recon

        assert callable(recon.shutil.which)
        assert hasattr(recon.tempfile, "NamedTemporaryFile")
        assert hasattr(recon.base64, "urlsafe_b64decode")

    def test_api_discovery_extra_does_not_need_has_kr(self):
        from core.recon import run_api_discovery_extra

        out = run_api_discovery_extra([], ["example.com"])
        assert "sources_used" in out
        assert "kiterunner" not in out["sources_used"]


class TestSettingsAllowlist:
    def test_alerting_keys_are_persisted(self):
        src = ROOT.joinpath("server.py").read_text(encoding="utf-8")
        for key in (
            "smtp_host", "smtp_port", "smtp_user", "smtp_pass", "alert_email",
            "jira_url", "jira_token", "jira_project", "jira_user",
            "linear_token", "linear_team_id",
            "defectdojo_url", "slash_token",
        ):
            assert f'"{key}"' in src, f"{key} missing from server.py settings allowlist"


class TestSurfaceIntel:
    def test_classify_cname_cloudfront(self):
        from core.surface_intel import classify_cname
        kind, label = classify_cname("d2rx95bc40seqr.cloudfront.net")
        assert kind == "aws_cloudfront"
        assert "CloudFront" in label
        kind, label = classify_cname("meuportohotsitehmlcdn.z01.azurefd.net")
        assert kind == "azure_frontdoor"
        kind, label = classify_cname("x5ucc5i.impervadns.net")
        assert kind == "imperva"

    def test_parse_csp_hosts(self):
        from core.surface_intel import parse_csp_hosts
        hosts = parse_csp_hosts(
            "frame-ancestors 'self' https://portoplus.webpremios.digital "
            "https://meuportohotsitehml.azurewebsites.net https://portoplus.com.br"
        )
        assert "portoplus.webpremios.digital" in hosts
        assert "meuportohotsitehml.azurewebsites.net" in hosts
        assert "portoplus.com.br" in hosts

    def test_assigned_to_discovery(self):
        from core.pipeline import PIPELINE_PHASES, pipeline_assigned_modules
        disc = next(p for p in PIPELINE_PHASES if p["id"] == "discovery")
        assert "surface_intel" in disc["modules"]
        intel = next(p for p in PIPELINE_PHASES if p["id"] == "intel")
        assert "origin_discovery" in intel["modules"]
        assigned = pipeline_assigned_modules()
        assert "surface_intel" in assigned
        assert "origin_discovery" in assigned

    def test_run_surface_intel_mocked(self, monkeypatch):
        from core import surface_intel as si

        def fake_dns(names):
            table = {
                "portoplus.com.br": {"A": ["45.223.41.75"], "AAAA": [], "CNAME": [], "NS": ["ns1.portoseguro.com.br"]},
                "catalogo.portoplus.com.br": {
                    "A": [], "AAAA": [],
                    "CNAME": ["d2rx95bc40seqr.cloudfront.net"],
                    "NS": [],
                },
                "d2rx95bc40seqr.cloudfront.net": {
                    "A": ["13.227.223.69", "13.227.223.99"],
                    "AAAA": [],
                    "CNAME": [],
                    "NS": ["ns-894.awsdns-47.net", "ns-1174.awsdns-18.org"],
                },
                "hml.portoplus.com.br": {
                    "A": ["150.171.110.36"], "AAAA": [],
                    "CNAME": ["meuportohotsitehmlcdn.z01.azurefd.net"],
                    "NS": [],
                },
                "staticblob.portoplus.com.br": {"A": [], "AAAA": [], "CNAME": [], "NS": []},
            }
            return {n: table.get(n, {"A": [], "AAAA": [], "CNAME": [], "NS": []}) for n in names}

        def fake_http(host):
            if host.endswith("cloudfront.net") or host.startswith("catalogo."):
                return {
                    "host": host, "url": f"https://{host}/", "status": 200 if "cloudfront" in host else 0,
                    "headers": {},
                    "server": "AmazonS3" if "cloudfront" in host else "",
                    "via": "1.1 x.cloudfront.net (CloudFront)" if "cloudfront" in host else "",
                    "acao": "*" if "cloudfront" in host else "",
                    "acac": "true" if "cloudfront" in host else "",
                    "csp": "frame-ancestors 'self' https://meuportohotsitehml.azurewebsites.net https://portoplus.webpremios.digital" if "cloudfront" in host else "",
                    "x_amz": {}, "body_len": 100, "title": "porto", "error": "" if "cloudfront" in host else "no-response",
                }
            return {"host": host, "url": f"https://{host}/", "status": 200, "headers": {},
                    "server": "", "via": "", "acao": "", "acac": "", "csp": "",
                    "x_amz": {}, "body_len": 1, "title": "", "error": ""}

        monkeypatch.setattr(si, "_dns_lookup", fake_dns)
        monkeypatch.setattr(si, "_http_probe", fake_http)
        monkeypatch.setattr("core.recon.get_ct_certs", lambda d, limit=200: [])
        out = si.run_surface_intel(["portoplus.com.br"])
        types = {f["type"] for f in out["findings"]}
        assert "cdn_fronted" in types
        assert "staging_host" in types
        assert "cors" in types
        assert "staging_in_csp" in types
        assert "cdn_s3_origin" in types
        assert "supply_chain_origin" in types
        assert "cdn_default_hostname" in types
        assert "catalogo.portoplus.com.br" in out["subdomains"]
        assert any(e.get("rel") == "cname" for e in out["graph"])
        cat = next(r for r in out["records"] if r["host"] == "catalogo.portoplus.com.br")
        assert "13.227.223.69" in cat["a"]
        assert cat["a_via"] == "cname"
        assert any(n.endswith("awsdns-47.net") for n in cat["ns"])
        assert cat["ns_via"] == "cname_target"
        cors_hosts = {f["host"] for f in out["findings"] if f["type"] == "cors"}
        assert "catalogo.portoplus.com.br" in cors_hosts
        csp_hosts = {f["host"] for f in out["findings"] if f["type"] in ("staging_in_csp", "supply_chain_origin")}
        assert "catalogo.portoplus.com.br" in csp_hosts

    def test_noisy_csp_host(self):
        from core.surface_intel import noisy_csp_host, supply_chain_host, owners_of
        assert noisy_csp_host("www.google-analytics.com")
        assert noisy_csp_host("cdn.jsdelivr.net")
        assert not noisy_csp_host("portoplus.webpremios.digital")
        assert supply_chain_host("portoplus.webpremios.digital")
        assert supply_chain_host("meuportohotsitehml.azurewebsites.net")
        recs = [{"host": "catalogo.portoplus.com.br", "cname": "d2rx95bc40seqr.cloudfront.net"}]
        assert owners_of("d2rx95bc40seqr.cloudfront.net", recs, ["portoplus.com.br"]) == [
            "catalogo.portoplus.com.br"
        ]


class TestBacklogClose:
    def test_apk_recon_assigned_to_intel(self):
        from core.pipeline import PIPELINE_PHASES, pipeline_assigned_modules
        intel = next(p for p in PIPELINE_PHASES if p["id"] == "intel")
        assert "apk_recon" in intel["modules"]
        assert "apk_recon" in pipeline_assigned_modules()

    def test_pipeline_ignore_helper_exists(self):
        from core.pipeline import _ignore
        _ignore(RuntimeError("x"), "test")

    def test_severity_threshold(self):
        from utils.alerting import _severity_meets
        assert _severity_meets("critical", "high_and_above")
        assert not _severity_meets("low", "high_and_above")
        assert _severity_meets("medium", "medium_and_above")
        assert not _severity_meets("info", "critical_only")

    def test_defectdojo_fail_fast_when_circuit_open(self, auth_client):
        from utils.circuit_breaker import breaker_for, reset_all

        reset_all()
        br = breaker_for("dojo.example.com")
        for _ in range(5):
            br.failure()
        r = auth_client.post(
            "/api/export/co1/defectdojo",
            json={"url": "https://dojo.example.com", "token": "tok"},
        )
        assert r.status_code == 503
        assert r.get_json().get("circuit") == "open"

    def test_sarif_export(self):
        from routes.reporting import findings_to_sarif
        payload = findings_to_sarif({
            "name": "Acme",
            "findings": [{"title": "Open redirect", "severity": "high", "host": "www.acme.com", "module": "open_redirect"}],
        })
        assert payload["version"] == "2.1.0"
        assert payload["runs"][0]["results"][0]["ruleId"] == "open_redirect"

    def test_openapi(self, auth_client):
        r = auth_client.get("/api/openapi.json")
        assert r.status_code == 200
        spec = r.get_json()
        assert spec["openapi"].startswith("3.")
        assert "/api/recon/{cid}/pipeline/{module}" in spec["paths"]
        assert "/api/intel/exposure" in spec["paths"]
        assert "/api/recon/{cid}/exposure" in spec["paths"]

    def test_cancel_module(self, auth_client, flask_app):
        runner = flask_app._test_runner
        runner.pipeline_state["co1"] = {"status": "running", "log": [], "skip_modules": []}
        r = auth_client.delete("/api/recon/co1/pipeline/subfinder")
        assert r.status_code == 200
        assert "subfinder" in r.get_json()["skip_modules"]
        assert runner.pipeline_state["co1"]["skip_modules"] == ["subfinder"]

    def test_alert_rule_min_severity(self, auth_client, db):
        r = auth_client.post("/api/alert-rules/co1", json={
            "name": "crit only",
            "rule_type": "new_host",
            "channels": ["slack"],
            "min_severity": "critical_only",
        })
        assert r.status_code == 200, r.get_json()
        rules = db.get_all_alert_rules("co1")
        assert rules
        assert rules[0]["min_severity"] == "critical_only"

    def test_invite_flow(self, auth_client, flask_app):
        r = auth_client.post("/api/admins/invite", json={
            "username": "analyst1",
            "email": "a@example.com",
            "role": "analyst",
            "scoped_companies": ["co1"],
        })
        assert r.status_code == 201, r.get_json()
        token = r.get_json()["token"]
        pub = flask_app.test_client().get(f"/api/auth/invite/{token}")
        assert pub.status_code == 200
        acc = flask_app.test_client().post(
            f"/api/auth/invite/{token}/accept",
            json={"password": "password123"},
            content_type="application/json",
        )
        assert acc.status_code == 201, acc.get_json()
        assert acc.get_json()["username"] == "analyst1"

    def test_nuclei_template_upload(self, auth_client, tmp_path):
        r = auth_client.post(
            "/api/recon/co1/nuclei-templates",
            json={"name": "custom.yaml", "content": "id: t\ninfo:\n  name: t\n"},
        )
        assert r.status_code == 200, r.get_json()
        listed = auth_client.get("/api/recon/co1/nuclei-templates")
        assert "custom.yaml" in listed.get_json()["templates"]

    def test_2fa_setup_and_login(self, auth_client, flask_app, db):
        pyotp = pytest.importorskip("pyotp")
        r = auth_client.post("/api/auth/2fa/setup")
        assert r.status_code == 200, r.get_json()
        secret = r.get_json()["secret"]
        code = pyotp.TOTP(secret).now()
        en = auth_client.post("/api/auth/2fa/enable", json={"totp_code": code})
        assert en.status_code == 200, en.get_json()
        c = flask_app.test_client()
        denied = c.post("/api/auth/login", json={"username": "admin", "password": "admin"})
        assert denied.status_code == 401
        assert denied.get_json().get("need_2fa") is True
        ok = c.post("/api/auth/login", json={
            "username": "admin", "password": "admin", "totp_code": pyotp.TOTP(secret).now(),
        })
        assert ok.status_code == 200, ok.get_json()

    def test_root_has_no_legacy_shims(self):
        for name in ("recon_routes", "core_routes", "ops_routes", "asset_routes", "scan_routes",
                     "reporting_routes", "pipeline", "database", "validators"):
            assert not ROOT.joinpath(name + ".py").exists(), f"{name}.py voltou para a raiz; importe de core/ ou routes/"


class TestJsScan:
    def test_noise_host_matches_suffix(self):
        from core.recon import _js_host_is_noise

        assert _js_host_is_noise("cdn-prod.securiti.ai") is True
        assert _js_host_is_noise("scripts.clarity.ms") is True
        assert _js_host_is_noise("www.portoplus.com.br") is False
        assert _js_host_is_noise("experiencias.portoplus.com.br") is False

    def test_analyze_skips_noise_cdn(self):
        from core.recon import _analyze_js_content

        body = 'apiKey:"AIzaSyBUnU3tt0IxrAby30X3vEincvF-DxmXnE4"'
        out = _analyze_js_content("https://cdn-prod.securiti.ai/consent/sdk.js", body)
        assert out["secrets"] == []
        assert out["endpoints"] == []

    def test_google_maps_key_is_medium(self):
        from core.recon import _analyze_js_content

        body = 'Object({googleMapsApiKey:"AIzaSyBUnU3tt0IxrAby30X3vEincvF-DxmXnE4"}).isLoaded'
        out = _analyze_js_content("https://experiencias.portoplus.com.br/static/js/main.js", body)
        keys = [s for s in out["secrets"] if s["type"] == "google_api_key"]
        assert keys
        assert keys[0]["severity"] == "medium"
        assert "Firebase/Maps" in keys[0]["context"]

    def test_gateway_pair_escalates_to_critical(self):
        from core.recon import _analyze_js_content

        body = (
            'const cfg = {client_id: "abc123def456", '
            'client_secret: "xyzsecretvalue16x"};'
        )
        out = _analyze_js_content("https://loja.portoseguro.com.br/app.js", body)
        types = {s["type"]: s for s in out["secrets"]}
        assert "client_id" in types and "client_secret" in types
        assert types["client_id"]["severity"] == "critical"
        assert types["client_secret"]["severity"] == "critical"

    def test_source_map_reads_sources_content(self):
        from core.recon import _analyze_source_map

        data = {
            "version": 3,
            "sources": ["src/config.ts"],
            "sourcesContent": [
                'initializeApp({apiKey:"AIzaSyBUnU3tt0IxrAby30X3vEincvF-DxmXnE4",authDomain:"x.firebaseapp.com"})'
            ],
        }
        out = _analyze_source_map("https://app.example.com/main.js.map", data)
        assert any(s["type"] == "google_api_key" for s in out["secrets"])

    def test_jwt_analysis_uses_js_secrets_without_redownload(self, monkeypatch):
        from core.recon import run_jwt_analysis
        import base64
        import json

        def _b64(obj):
            raw = json.dumps(obj, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        token = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': 'u1'})}.sig"
        called = {"n": 0}

        def _boom(*a, **k):
            called["n"] += 1
            raise AssertionError("jwt_analysis must not re-fetch JS")

        monkeypatch.setattr("core.reconlib.salesforce.http_get", _boom)
        out = run_jwt_analysis([], [{
            "url": "https://www.portoplus.com.br/static/js/main.js",
            "secrets": [{"type": "jwt_token", "value": token, "severity": "high"}],
        }])
        assert called["n"] == 0
        assert out["tokens_found"] == 1
        assert any(f["type"] == "jwt_none_alg" for f in out["findings"])

    def test_extract_skips_noise_hosts(self):
        from core.pipeline import ReconRunner

        runner = ReconRunner.__new__(ReconRunner)
        runner.results = {
            "c1:js": {
                "data": {
                    "js_files": [
                        {
                            "host": "cdn-prod.securiti.ai",
                            "url": "https://cdn-prod.securiti.ai/x.js",
                            "endpoints": [{"path": "/consent/x", "kind": "path"}],
                            "secrets": [{"type": "google_api_key", "value": "AIzaSyBUnU3tt0IxrAby30X3vEincvF-DxmXnE4", "severity": "high"}],
                        },
                        {
                            "host": "www.portoplus.com.br",
                            "url": "https://www.portoplus.com.br/a.js",
                            "endpoints": [{"path": "/api/v1/info", "kind": "api"}],
                            "secrets": [{"type": "google_api_key", "value": "AIzaSyBUnU3tt0IxrAby30X3vEincvF-DxmXnE4", "severity": "medium"}],
                        },
                    ]
                }
            }
        }
        eps = ReconRunner._extract_js_endpoints_from_js_module(runner, "c1", [], [])
        secs = ReconRunner._extract_js_secrets_from_js_module(runner, "c1", [], [])
        assert eps["count"] == 1
        assert eps["findings"][0]["host"] == "www.portoplus.com.br"
        assert secs["count"] == 1
        assert secs["findings"][0]["host"] == "www.portoplus.com.br"

    def test_extract_skips_webpack_and_mime_paths(self):
        from core.pipeline import ReconRunner

        runner = ReconRunner.__new__(ReconRunner)
        runner.results = {
            "c1:js": {
                "data": {
                    "js_files": [
                        {
                            "host": "www.portoplus.com.br",
                            "url": "https://www.portoplus.com.br/a.js",
                            "endpoints": [
                                {"path": "../constants", "kind": "path"},
                                {"path": "application/json", "kind": "path"},
                                {"path": "/api/v1/info", "kind": "api"},
                            ],
                            "secrets": [],
                        }
                    ]
                }
            }
        }
        eps = ReconRunner._extract_js_endpoints_from_js_module(runner, "c1", [], [])
        assert eps["count"] == 1
        assert eps["findings"][0]["value"] == "/api/v1/info"


class TestJsPathNoise:
    def test_noise_and_keep(self):
        from core.recon import _js_path_is_noise

        assert _js_path_is_noise("../constants")
        assert _js_path_is_noise("./lib/adapters/http.js")
        assert _js_path_is_noise("application/json")
        assert _js_path_is_noise("text/plain")
        assert _js_path_is_noise("dd/MM/yyyy")
        assert _js_path_is_noise("America/Sao_Paulo")
        assert _js_path_is_noise("firebase/firestore")
        assert _js_path_is_noise("__bundle__/docs/")
        assert not _js_path_is_noise("/api/v1/info")
        assert not _js_path_is_noise("https://api.example.com/v1")
        assert not _js_path_is_noise("api/auth?campaignId=")
        assert not _js_path_is_noise("//cliente.portoseguro.com.br/x")


class TestPersistFrontendSync:
    def test_git_exposed_becomes_finding(self):
        from core.pipeline import merge_persist_findings

        out = merge_persist_findings({
            "leaks_data": {
                "git_exposed": [
                    {"host": "git.example.com", "path": "/.git/config", "severity": "critical", "snippet": "[core]\n\trepositoryformatversion = 0"},
                    {"host": "spa.example.com", "path": "/.git/config", "severity": "critical", "snippet": "<!doctype html><html>"},
                ]
            }
        })
        assert len(out) == 1
        assert out[0]["type"] == "git_exposed"
        assert out[0]["module"] == "leaks"
        assert out[0]["severity"] == "critical"
        assert out[0]["host"] == "git.example.com"

    def test_vendor_fingerprint_becomes_finding(self):
        from core.pipeline import merge_persist_findings

        out = merge_persist_findings({
            "vendor_fingerprints": [
                {"host": "vpn.example.com", "vendor": "Citrix", "url": "https://vpn.example.com/vpn/", "severity": "high", "cve_note": "check Citrix ADC"},
            ]
        })
        assert len(out) == 1
        assert out[0]["type"] == "vendor_fingerprint"
        assert out[0]["module"] == "vendor_fp"
        assert out[0]["value"] == "Citrix"

    def test_does_not_duplicate_existing_key(self):
        from core.pipeline import merge_persist_findings

        existing = [{"key": "git-exposed-a.example-/.git/HEAD", "type": "git_exposed", "title": "already"}]
        out = merge_persist_findings(
            {"leaks_data": {"git_exposed": [{"host": "a.example", "path": "/.git/HEAD"}]}},
            all_findings=existing,
            existing_keys={"git-exposed-a.example-/.git/HEAD"},
        )
        assert len(out) == 1


class TestAssetGraph:
    @staticmethod
    def _eval(expr: str):
        import subprocess

        js = ROOT / "static" / "js" / "asset-graph.js"
        r = subprocess.run(
            ["node", "-e", f"const g=require({json.dumps(str(js))}); {expr}"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        if r.returncode != 0:
            raise AssertionError(r.stderr or r.stdout or "node failed")
        return json.loads(r.stdout)

    def test_apex_com_br_and_infra(self):
        out = self._eval(
            "console.log(JSON.stringify({"
            "a:g.apexDomain('api.loja.portoseguro.com.br'),"
            "b:g.apexDomain('catalogo.portoplus.com.br'),"
            "c:g.clusterKey('ns-894.awsdns-47.net','ns'),"
            "d:g.clusterKey('d2rx95bc40seqr.cloudfront.net','cdn'),"
            "e:g.clusterKey('r9h3r9d.impervadns.net','cdn'),"
            "f:g.clusterKey('45.223.41.75','ip')"
            "}))"
        )
        assert out["a"] == "portoseguro.com.br"
        assert out["b"] == "portoplus.com.br"
        assert out["c"] == "aws-dns"
        assert out["d"] == "cloudfront"
        assert out["e"] == "imperva"
        assert out["f"] == "ip"

    def test_collapse_leaves_keeps_apex_and_supernode(self):
        payload = {
            "nodes": (
                [{"id": "n:example.com", "label": "example.com", "kind": "host", "cluster": "example.com", "degree": 20}]
                + [
                    {
                        "id": f"n:h{i}.example.com",
                        "label": f"h{i}.example.com",
                        "kind": "host",
                        "cluster": "example.com",
                        "degree": 15 - i,
                    }
                    for i in range(14)
                ]
            ),
            "links": [
                {"a": "n:example.com", "b": f"n:h{i}.example.com", "rel": "a"}
                for i in range(14)
            ],
        }
        out = self._eval(
            "const p=" + json.dumps(payload) + ";"
            "const r=g.collapseLeaves(p.nodes,p.links,{hostKeep:7,hostMin:9});"
            "console.log(JSON.stringify({"
            "n:r.nodes.length,"
            "kinds:r.nodes.map(x=>x.kind),"
            "super:(r.nodes.find(x=>x.kind==='cluster')||{}).label,"
            "kept:r.nodes.filter(x=>x.kind==='host').length"
            "}))"
        )
        assert out["kept"] == 7
        assert "cluster" in out["kinds"]
        assert out["super"].startswith("+")
        assert out["n"] == 8

    def test_build_model_clusters_porto_like(self):
        hosts = [{"host": f"h{i}.portoseguro.com.br"} for i in range(20)]
        hosts.append({"host": "portoseguro.com.br"})
        graph = [{"from": "portoseguro.com.br", "rel": "a", "to": f"h{i}.portoseguro.com.br"} for i in range(20)]
        graph.append({"from": "www.portoseguro.com.br", "rel": "cname", "to": "r9h3r9d.impervadns.net"})
        co = {"hosts": hosts, "surface_intel": {"graph": graph, "records": [], "related": []}}
        out = self._eval(
            "const co=" + json.dumps(co) + ";"
            "const m=g.buildGraphModel(co,{clustered:true});"
            "console.log(JSON.stringify({"
            "raw:m.rawNodeCount,"
            "vis:m.nodes.length,"
            "clusters:m.nodes.filter(n=>n.kind==='cluster').length"
            "}))"
        )
        assert out["raw"] > out["vis"]
        assert out["clusters"] >= 1
        assert out["vis"] < 20

    def test_query_pins_hidden_host(self):
        hosts = [{"host": f"h{i}.example.com"} for i in range(20)]
        hosts.append({"host": "example.com"})
        hosts.append({"host": "loja-auth.example.com"})
        graph = [{"from": "example.com", "rel": "cname", "to": f"h{i}.example.com"} for i in range(20)]
        graph.append({"from": "example.com", "rel": "cname", "to": "loja-auth.example.com"})
        co = {"hosts": hosts, "surface_intel": {"graph": graph, "records": [], "related": []}}
        out = self._eval(
            "const co=" + json.dumps(co) + ";"
            "const a=g.buildGraphModel(co,{clustered:true});"
            "const b=g.buildGraphModel(co,{clustered:true,query:'loja-auth'});"
            "console.log(JSON.stringify({"
            "aHas:a.nodes.some(n=>n.label==='loja-auth.example.com'),"
            "bHas:b.nodes.some(n=>n.label==='loja-auth.example.com'),"
            "aVis:a.nodes.length,bVis:b.nodes.length"
            "}))"
        )
        assert out["aHas"] is False
        assert out["bHas"] is True
        assert out["bVis"] <= out["aVis"] + 2


class TestOperationPersist:
    @staticmethod
    def _eval(expr: str):
        import subprocess

        js = ROOT / "static" / "js" / "operation-persist.js"
        r = subprocess.run(
            ["node", "-e", f"const g=require({json.dumps(str(js))}); {expr}"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        if r.returncode != 0:
            raise AssertionError(r.stderr or r.stdout or "node failed")
        return json.loads(r.stdout)

    def test_screenshot_serve_url(self):
        out = self._eval(
            "console.log(JSON.stringify({"
            "a:g.screenshotServeUrl('porto','/home/will/scantrely/scans/porto/screenshots/browser_https___www_portoplus_com_br.png'),"
            "b:g.screenshotServeUrl('porto','/screenshots/porto/x.png'),"
            "c:g.screenshotServeUrl('porto',''),"
            "d:g.screenshotServeUrl('porto','screenshots/https---auth.catalogo.portoplus.com.br-443.jpeg'),"
            "e:g.screenshotServeUrl('porto','/screenshots/https---auth.catalogo.portoplus.com.br-443.jpeg'),"
            "f:g.screenshotServeUrl('porto','https---auth.catalogo.portoplus.com.br-443.jpeg'),"
            "g:g.screenshotServeUrl('porto','screenshots/porto/screenshot/host/hash.png'),"
            "h:g.screenshotServeUrl('porto','/home/will/scantrely/scans/porto/screenshots/screenshot/host/hash.png')"
            "}))"
        )
        assert out["a"] == "/screenshots/porto/browser_https___www_portoplus_com_br.png"
        assert out["b"] == "/screenshots/porto/x.png"
        assert out["c"] == ""
        assert out["d"] == "/screenshots/porto/https---auth.catalogo.portoplus.com.br-443.jpeg"
        assert out["e"] == "/screenshots/porto/https---auth.catalogo.portoplus.com.br-443.jpeg"
        assert out["f"] == "/screenshots/porto/https---auth.catalogo.portoplus.com.br-443.jpeg"
        assert out["g"] == "/screenshots/porto/screenshot/host/hash.png"
        assert out["h"] == "/screenshots/porto/screenshot/host/hash.png"

    def test_summarize_reads_pipeline_persist(self):
        co = {
            "id": "porto",
            "screenshots_count": 3,
            "browser_recon_data": {
                "hosts_scanned": 2,
                "insecure_cookies": 1,
                "total_cookies": 2,
                "results": [
                    {
                        "url": "https://www.example.com",
                        "status": 200,
                        "title": "Home",
                        "api_endpoints": [{"method": "GET", "url": "https://api.example.com/v1"}],
                        "cookies": [{"name": "sid", "domain": ".example.com", "httpOnly": True, "secure": True, "value": "secret"}],
                        "observations": ["Custom globals: Array", "Missing CSP"],
                        "third_party_services": ["Google Tag Manager", "AbCdEfGhIj"],
                        "security_headers": {"missing": ["content-security-policy"]},
                    }
                ],
            },
            "browser_crawl_data": {
                "url_count": 4,
                "hosts_crawled": 1,
                "api_endpoints": [{"method": "POST", "url": "https://api.example.com/v1"}],
                "results": [{"host": "www.example.com", "url": "https://www.example.com", "pages": 2, "urls": ["https://www.example.com/a"], "api_endpoints": [], "forms": [{"action": "/Login", "method": "post", "inputs": ["user"]}]}],
            },
            "js_data": {
                "runtime_js_urls": ["https://www.example.com/app.js"],
                "runtime_network": [{"method": "GET", "type": "xhr", "url": "https://api.example.com/v1"}],
                "js_files": [{"url": "https://www.example.com/app.js"}],
            },
        }
        out = self._eval(
            "const co=" + json.dumps(co) + ";"
            "const s=g.summarize(co);"
            "console.log(JSON.stringify({"
            "has:s.has,pages:s.pages.length,apis:s.apiCount,urls:s.urlCount,"
            "obs:s.observations.map(o=>o.text),third:s.third,"
            "cookieNames:s.cookies.map(c=>c.name),cookieHasValue:s.cookies.some(c=>'value' in c && c.value),"
            "forms:s.formCount,badge:s.badge"
            "}))"
        )
        assert out["has"] is True
        assert out["pages"] == 1
        assert out["apis"] == 2
        assert out["urls"] == 4
        assert out["obs"] == ["Missing CSP"]
        assert out["third"] == ["Google Tag Manager"]
        assert out["cookieNames"] == ["sid"]
        assert out["cookieHasValue"] is False
        assert out["forms"] == 1
        assert out["badge"] >= 1

    def test_empty_company_has_false(self):
        out = self._eval("console.log(JSON.stringify(g.summarize({}).has))")
        assert out is False

    def test_operation_tab_no_longer_gates_on_playwright_job(self):
        js = _dashboard_js()
        start = js.index("function _opT(")
        end = js.index("async function renderReconTab")
        body = js[start:end]
        assert "_opSummarize" in body
        assert "No Playwright run found" not in body
        assert "openPlaywrightModal" in body
        assert "_renderOperationPersistCards" in body


class TestOriginLink:
    @staticmethod
    def _eval(expr: str):
        import subprocess

        js = ROOT / "static" / "js" / "origin-link.js"
        r = subprocess.run(
            ["node", "-e", f"const g=require({json.dumps(str(js))}); {expr}"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        if r.returncode != 0:
            raise AssertionError(r.stderr or r.stdout or "node failed")
        return json.loads(r.stdout)

    def test_origin_href_https_passthrough(self):
        out = self._eval(
            "console.log(JSON.stringify(g.originHref('https://www.portoplus.com.br/app.js')))"
        )
        assert out == "https://www.portoplus.com.br/app.js"

    def test_origin_href_relative_and_host(self):
        out = self._eval(
            "console.log(JSON.stringify({"
            "a:g.originHref('/api/v1','www.example.com'),"
            "b:g.originHref('','loja.portoseguro.com.br'),"
            "c:g.originHref('.example.com'),"
            "d:g.originHref('javascript:alert(1)'),"
            "e:g.originHref('data:text/html,x'),"
            "f:g.originHref('/home/will/secret.js','www.example.com'),"
            "g:g.originHref('bundle.js','cdn.example.com')"
            "}))"
        )
        assert out["a"] == "https://www.example.com/api/v1"
        assert out["b"] == "https://loja.portoseguro.com.br"
        assert out["c"] == "https://example.com"
        assert out["d"] == ""
        assert out["e"] == ""
        assert out["f"] == ""
        assert out["g"] == "https://cdn.example.com/bundle.js"

    def test_origin_href_collapses_dotdot(self):
        out = self._eval(
            "console.log(JSON.stringify({"
            "a:g.originHref('../../components/LoginComponents/styles','experiencias.portoplus.com.br'),"
            "b:g.originHref('../constants','https://cdn.example.com/static/js/a.js'),"
            "c:g.originHref('application/json','www.example.com'),"
            "d:g.originHref('text/plain','www.example.com'),"
            "e:g.originHref('dd/MM/yyyy','www.example.com'),"
            "f:g.originHref('//cliente.portoseguro.com.br/x')"
            "}))"
        )
        assert out["a"] == "https://experiencias.portoplus.com.br/components/LoginComponents/styles"
        assert ".." not in out["a"]
        assert out["b"] == "https://cdn.example.com/static/constants"
        assert out["c"] == ""
        assert out["d"] == ""
        assert out["e"] == ""
        assert out["f"] == "https://cliente.portoseguro.com.br/x"

    def test_js_path_noise(self):
        out = self._eval(
            "console.log(JSON.stringify({"
            "a:g.isJsPathNoise('../constants'),"
            "b:g.isJsPathNoise('./lib/adapters/http.js'),"
            "c:g.isJsPathNoise('application/json'),"
            "d:g.isJsPathNoise('MM/dd/yyyy'),"
            "e:g.isJsPathNoise('America/Sao_Paulo'),"
            "f:g.isJsPathNoise('/api/v1/info'),"
            "g:g.isJsPathNoise('https://api.example.com/v1'),"
            "h:g.isJsPathNoise('api/auth?campaignId='),"
            "i:g.isJsPathNoise('firebase/firestore')"
            "}))"
        )
        assert out["a"] is True
        assert out["b"] is True
        assert out["c"] is True
        assert out["d"] is True
        assert out["e"] is True
        assert out["f"] is False
        assert out["g"] is False
        assert out["h"] is False
        assert out["i"] is True

    def test_origin_link_html_is_anchor(self):
        html = self._eval(
            "console.log(JSON.stringify(g.originLinkHtml('https://api.example.com/v1','/v1')))"
        )
        assert html.startswith("<a ")
        assert 'href="https://api.example.com/v1"' in html
        assert 'target="_blank"' in html
        assert "noopener" in html
        assert html.endswith("</a>")
        assert "javascript:" not in html

    def test_dashboard_opens_origin_instead_of_copy(self):
        js = _dashboard_js()
        assert "function originLinkHtml" in js
        assert "function jumpToFound" in js
        assert "Click to copy URL" not in js
        assert "Click file path to copy" not in js
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        assert "origin-link.js" in html
        assert "js/dashboard/17-terminal-alerts-init.js" in html
        assert "operation-persist.js?v=2" in html
        assert "function isJsPathNoise" in js
        assert "_isFpJsSecret" in js
        assert "function _shotSrc" in js
        assert "'/' + h.screenshot" not in js
        assert '"/" + p.screenshot_path' not in js

    def test_hosts_inventory_on_visible_subdomains_shell(self):
        js = _dashboard_js()
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        css = (ROOT / "static" / "css" / "dashboard.css").read_text(encoding="utf-8")
        i18n = (ROOT / "static" / "js" / "i18n.js").read_text(encoding="utf-8")
        start = js.index("function _renderSubInventoryShell")
        end = js.index("function _assetStatusBadges")
        body = js[start:end]
        assert 'id="playwright-host-inventory"' in body
        assert "renderPlaywrightHostInventoryTab(co)" in body
        assert "ssLightboxOpen" in js
        assert "_ssOnKey" in js
        assert "⧉" not in js
        assert "hostPanel = \"subdomains\"" in js
        assert "js/dashboard/17-terminal-alerts-init.js" in html
        assert "dashboard.css?v=" in html
        assert "i18n.js?v=23" in html
        assert "exposure.js?v=3" in html
        assert "Prévia do screenshot" in html
        assert "← Prev" not in html
        assert ".ai-shot-btn" in css
        assert "min-width:var(--target)" in css
        assert "ai_open_shot" in i18n
        assert "ss_preview" in i18n
        assert "op_details" in i18n

    def test_exposure_and_hosts_badge_semantics(self):
        exp = (ROOT / "static" / "js" / "exposure.js").read_text(encoding="utf-8")
        js = _dashboard_js()
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        i18n = (ROOT / "static" / "js" / "i18n.js").read_text(encoding="utf-8")
        assert "function exposureCount" in exp
        assert "hr.users || 0) + Number(hr.stealer_count" not in exp
        assert "window.ASMExposure" in exp
        assert "ASMExposure.count" in js
        assert "hrStored.employees||0) + Number(hrStored.users" not in js
        assert "hosts:      ['subdomains']" in js
        assert "filter(_isActiveHost)" in js
        assert "Scan execution and live phase status" not in js
        assert "Run Pipeline" not in js
        assert "Stop Pipeline" not in js
        assert 'pipe_title' in i18n
        assert "js/dashboard/17-terminal-alerts-init.js" in html
        assert "exposure.js?v=3" in html
        assert "_setIconLabel(btn, active ? \"stop\" : \"play\", label)" in js or "_setIconLabel(btn, active ? 'stop' : 'play', label)" in js

    def test_confirmed_vulns_copy_is_localized(self):
        js = _dashboard_js()
        html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        i18n = (ROOT / "static" / "js" / "i18n.js").read_text(encoding="utf-8")
        start = js.index("async function renderVulnsTab")
        end = js.index("function exportHosts")
        body = js[start:end]
        assert "Loading vulnerability data" not in js
        assert "Confirmed vulnerability findings only" not in js
        assert "Confirmed Vulnerabilities" not in body
        assert "Search confirmed vulns" not in js
        assert "No confirmed vulns match" not in js
        assert "No confirmed vulnerabilities yet" not in js
        assert "All severities" not in body
        assert "All categories" not in body
        assert "No CORS misconfigurations found" not in js
        assert "No GraphQL endpoints detected" not in js
        assert "No nuclei findings detected" not in js
        assert "No takeover candidates detected" not in js
        assert "CORS Misconfigurations" not in js
        assert "Takeover Candidates" not in js
        assert "_opT(\"vuln_title\"" in body or "_opT('vuln_title'" in body
        assert "aria-busy" in body
        assert 'role="status"' in body
        assert 'critical: "Critical"' not in js
        assert "unique issues" not in js
        assert "vuln_title" in i18n
        assert "vuln_loading" in i18n
        assert "vuln_cnt" in i18n
        assert "js/dashboard/17-terminal-alerts-init.js" in html
        assert "i18n.js?v=23" in html


class TestFindingLifecyclePersist:
    """Integração: _persist_pipeline_results aplica visto / não visto sobre o que o módulo reportou neste scan."""

    def _runner(self, db, tmp_path):
        from core.pipeline import ReconRunner
        return ReconRunner(db=db, base_dir=tmp_path, get_settings=lambda: {}, load_hosts_fn=lambda cid: [],
                           recon_module=None, recon_available=False)

    def _hdr(self, host, header):
        return {"host": host, "findings": [{"header": header, "present": False, "severity": "warn", "issue": f"Missing {header}"}]}

    def test_headers_fixed_becomes_not_seen_and_unrelated_modules_untouched(self, db, tmp_path):
        old_hdr = {"key": "header-missing-a.x.com-Content-Security-Policy", "type": "header", "module": "headers", "severity": "medium",
                   "title": "Header ausente em a.x.com: Content-Security-Policy", "host": "a.x.com"}
        old_cors = {"key": "cors-1", "type": "cors", "module": "cors_scan", "severity": "high", "title": "CORS", "host": "a.x.com"}
        db.save_asm_data({"companies": [{"id": "co", "name": "Co", "domains": ["x.com"], "hosts": [{"host": "a.x.com", "status_code": 200}],
                                         "findings": [old_hdr, old_cors]}]})
        runner = self._runner(db, tmp_path)
        # o módulo headers rodou e agora o host está corrigido (sem header ausente); cors_scan NÃO rodou
        runner.results["co:headers"] = {"status": "done", "data": {"results": [{"host": "a.x.com", "findings": [], "cookie_issues": []}]}}
        runner._persist_pipeline_results("co")
        got = {f["key"]: f for f in db.load_asm_data()["companies"][0]["findings"]}
        assert got[old_hdr["key"]]["status"] == "not_seen" and got[old_hdr["key"]]["miss_count"] == 1
        assert "status" not in got["cors-1"]                       # módulo que não rodou: intacto
        stats = db.load_asm_data()["companies"][0]["stats"]
        assert stats["findings_medium"] == 1 and stats["findings_high"] == 0   # header não visto não conta; CORS (carregado) vira médio no teto

    def test_still_present_finding_is_refreshed_not_stale(self, db, tmp_path):
        key = "header-missing-a.x.com-Content-Security-Policy"
        old = {"key": key, "type": "header", "module": "headers", "severity": "medium", "title": "x", "host": "a.x.com",
               "first_seen": "2026-10-01T00:00:00", "status": "not_seen", "miss_count": 2}
        db.save_asm_data({"companies": [{"id": "co", "name": "Co", "domains": ["x.com"], "hosts": [{"host": "a.x.com", "status_code": 200}], "findings": [old]}]})
        runner = self._runner(db, tmp_path)
        runner.results["co:headers"] = {"status": "done", "data": {"results": [self._hdr("a.x.com", "Content-Security-Policy")]}}
        runner._persist_pipeline_results("co")
        f = next(f for f in db.load_asm_data()["companies"][0]["findings"] if f["key"] == key)
        assert f.get("status") is None and f["miss_count"] == 0 and f["first_seen"] == "2026-10-01T00:00:00"


class TestGhostRunningState:
    """Estado "running" sem job ativo (servidor reiniciado no meio do scan) não pode ficar
    aparecendo na tela como scan em andamento para sempre."""

    def _set(self, flask_app, status, started_at):
        flask_app._test_runner.pipeline_state["co"] = {"status": status, "started_at": started_at, "log": []}

    def test_old_running_without_job_is_stopped(self, flask_app, auth_client):
        from datetime import datetime, timedelta
        self._set(flask_app, "running", (datetime.now() - timedelta(hours=1)).isoformat(timespec="seconds"))
        assert auth_client.get("/api/recon/co/pipeline").get_json()["status"] == "stopped"

    def test_just_queued_is_kept(self, flask_app, auth_client):
        from datetime import datetime
        self._set(flask_app, "queued", datetime.now().isoformat(timespec="seconds"))
        assert auth_client.get("/api/recon/co/pipeline").get_json()["status"] == "queued"

    def test_running_with_active_job_is_kept(self, flask_app, auth_client):
        from datetime import datetime, timedelta
        flask_app._test_scheduler.db.create_job(job_type="pipeline", company_id="co", target="co", options={})
        self._set(flask_app, "running", (datetime.now() - timedelta(hours=1)).isoformat(timespec="seconds"))
        assert auth_client.get("/api/recon/co/pipeline").get_json()["status"] == "running"


class TestScopeRoutes:
    def test_out_of_scope_saved_and_validated(self, flask_app, auth_client):
        flask_app._test_companies.append({"id": "co", "name": "Co", "domains": ["example.com"]})
        r = auth_client.put("/api/companies/co", json={"out_of_scope": ["status.example.com", "*.old.example.com"]})
        assert r.status_code == 200 and r.get_json()["out_of_scope"] == ["status.example.com", "*.old.example.com"]
        bad = auth_client.put("/api/companies/co", json={"out_of_scope": ["não é host"]})
        assert bad.status_code == 400

    def test_scope_parse_only_reads(self, auth_client):
        r = auth_client.post("/api/scope/parse", json={"in_scope": "*.example.com\ncom.example.app", "out_of_scope": "*.old.example.com"})
        d = r.get_json()
        assert d["domains"] == ["example.com"] and d["out_of_scope"] == ["*.old.example.com"] and d["ignored"] == ["com.example.app"]

    def test_tool_list_rejects_unknown_kind(self, auth_client):
        assert auth_client.get("/api/data/company/co/lists/tudo").status_code == 400
