#!/usr/bin/env python3
"""
ASM Platform — Backend Server

Usage:
    python3 server.py [--port 5000]
"""
import json, sys, os, threading, uuid, time, re, subprocess
import hashlib, secrets, base64, hmac
import faulthandler, signal
# Dump all thread stacks to stderr (→ logs/server.log) on `kill -USR1 <pid>`.
# Lets the supervisor diagnose a hung pipeline worker without py-spy.
try:
    faulthandler.register(signal.SIGUSR1)
except Exception:
    pass
from functools import wraps
from pathlib import Path
from datetime import datetime, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError

from core.database import ASMDatabase
from routes.core import create_core_blueprint
from routes.ops import create_ops_blueprint
from routes.reporting import create_reporting_blueprint
from routes.assets import create_asset_blueprint
from routes.scans import create_scan_blueprint
from routes.recon import create_recon_blueprint
from core.jobs import JobScheduler
from core.pipeline import ReconRunner, PIPELINE_PHASES, SELF_CONTAINED_MODULES

try:
    from flask import Flask, jsonify, request, Response, abort, send_from_directory, stream_with_context, g, has_request_context
except ImportError:
    print("[!] Flask not installed. Run: pip install flask")
    sys.exit(1)

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE          = Path(__file__).parent.resolve()

# Prefixar bin/ local no PATH para que todos os shutil.which() e subprocess
# encontrem os binários instalados pelo install_tools.sh antes do PATH do sistema.
_BIN_DIR  = BASE / "bin"
_VENV_BIN = BASE / ".venv" / "bin"
_BIN_DIR.mkdir(exist_ok=True)
os.environ["PATH"] = os.pathsep.join(filter(None, [
    str(_BIN_DIR) if _BIN_DIR.exists() else "",
    str(_VENV_BIN) if _VENV_BIN.exists() else "",
    os.environ.get("PATH", ""),
]))

CO_FILE       = BASE / "config" / "companies.json"
ADMINS_FILE   = BASE / "config" / "admins.json"
SETTINGS_FILE = BASE / "config" / "settings.json"
SCHEDULE_FILE = BASE / "config" / "schedules.json"
WEBHOOKS_FILE = BASE / "config" / "webhooks.json"
WHITELIST_FILE= BASE / "config" / "whitelist.json"
DATA_JS       = BASE / "data" / "asm_data.js"
AUDIT_LOG     = BASE / "logs"  / "audit.log"
DB_FILE       = BASE / "data"  / "asm.db"
SNAPSHOTS_DIR = BASE / "data"  / "snapshots"
(BASE / "data").mkdir(exist_ok=True)
(BASE / "logs").mkdir(exist_ok=True)
SNAPSHOTS_DIR.mkdir(exist_ok=True)

DB = ASMDatabase(
    DB_FILE,
    asm_data_file=DATA_JS,
    snapshots_dir=SNAPSHOTS_DIR,
    companies_file=CO_FILE,
    settings_file=SETTINGS_FILE,
    admins_file=ADMINS_FILE,
    schedules_file=SCHEDULE_FILE,
    webhooks_file=WEBHOOKS_FILE,
    whitelist_file=WHITELIST_FILE,
    audit_log_file=AUDIT_LOG,
)
DB.initialize()
DB.migrate_from_legacy()

# ─── Auth helpers ─────────────────────────────────────────────────────────────

_PBKDF2_ITERS = 260_000
_SESSION_TTL  = 86_400 * 7   # 7 days

# token -> {admin_id, username, role, expires_at}
# Seeded from SQLite on startup so sessions survive server restarts.
_sessions: dict[str, dict] = {}
try:
    _sessions = DB.load_sessions()
except Exception:
    pass


def _hash_pw(password: str) -> str:
    salt = secrets.token_hex(16)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERS)
    return f"pbkdf2:sha256:{salt}:{base64.b64encode(dk).decode()}"


def _check_pw(password: str, hash_str: str) -> bool:
    try:
        _, algo, salt, stored = hash_str.split(":")
        dk = hashlib.pbkdf2_hmac(algo, password.encode(), salt.encode(), _PBKDF2_ITERS)
        return hmac.compare_digest(base64.b64encode(dk).decode(), stored)
    except Exception:
        return False


def load_admins() -> list:
    admins = DB.load_admins()
    if admins:
        return admins
    # Bootstrap first admin on fresh install
    default = {
        "id":            uuid.uuid4().hex,
        "username":      "admin",
        "email":         "",
        "password_hash": _hash_pw("admin"),
        "role":          "super_admin",
        "created_at":    datetime.now().isoformat(timespec="seconds"),
        "last_login":    None,
    }
    save_admins([default])
    print("  ┌─────────────────────────────────────────┐")
    print("  │  Default admin created:                 │")
    print("  │  Username: admin  /  Password: admin    │")
    print("  │  !! CHANGE THE PASSWORD IMMEDIATELY !!  │")
    print("  └─────────────────────────────────────────┘")
    return [default]


def save_admins(admins: list):
    DB.save_admins(admins)


def _get_settings() -> dict:
    return DB.get_settings(_SETTINGS_KEYS)


def _get_session() -> dict | None:
    if not has_request_context():
        return None
    token = request.headers.get("X-Auth-Token") or request.cookies.get("asm_token")
    if not token:
        return None
    sess = _sessions.get(token)
    if not sess:
        # Cache miss — try DB (covers server restarts and multi-process scenarios)
        try:
            loaded = DB.load_sessions()
            _sessions.update(loaded)
            sess = _sessions.get(token)
        except Exception:
            pass
    if not sess:
        return None
    if time.time() > sess["expires_at"]:
        _sessions.pop(token, None)
        DB.delete_session(token)
        return None
    return sess


def _normalize_scope(sess: dict | None) -> list[str] | None:
    if not sess:
        return []
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


def _session_can_access_company(cid: str, sess: dict | None = None) -> bool:
    if not cid:
        return True
    sess = sess or _get_session()
    if not sess:
        return False
    scope = _normalize_scope(sess)
    if scope is None:
        return True
    if not scope:
        return False
    return cid in scope or "*" in scope

def _enforce_company_scope():
    sess = _get_session()
    if not sess:
        return None
    if sess.get("role") == "super_admin":
        g.session = sess
        return None
    g.session = sess
    view_args = request.view_args or {}
    candidates = []
    for key in ("cid", "company_id", "company"):
        val = view_args.get(key)
        if val:
            candidates.append(str(val))
        qval = request.args.get(key)
        if qval:
            candidates.append(str(qval))
    # When a route references a company directly, enforce access centrally.
    for cid in candidates:
        if not _session_can_access_company(cid, sess):
            return jsonify({"error": "Forbidden — company not in scope"}), 403
    return None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        sess = _get_session()
        if not sess:
            return jsonify({"error": "Unauthorized — please log in"}), 401
        g.session = sess
        return f(*args, **kwargs)
    return decorated


def require_super_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        sess = _get_session()
        if not sess:
            return jsonify({"error": "Unauthorized"}), 401
        if sess.get("role") != "super_admin":
            return jsonify({"error": "Forbidden — super_admin only"}), 403
        g.session = sess
        return f(*args, **kwargs)
    return decorated

app = Flask(__name__, static_folder=str(BASE))
app.config["JSON_SORT_KEYS"] = False
app.before_request(_enforce_company_scope)


@app.after_request
def _set_security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=()",
    )
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data: blob: https:; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "connect-src 'self' https://fonts.googleapis.com; "
        "frame-ancestors 'none'",
    )
    # Suppress exact version fingerprint
    resp.headers["Server"] = "ASM"
    if request.is_secure:
        resp.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return resp

# Lazy import of recon module
try:
    import core.recon as _recon
    RECON_AVAILABLE = True
except ImportError:
    RECON_AVAILABLE = False

# Lazy import of tools registry
try:
    from utils.tools import registry as _tool_registry
    TOOLS_AVAILABLE = True
except ImportError:
    TOOLS_AVAILABLE = False

# Checkpoints module
try:
    import core.checkpoints as _checkpoints
    CHECKPOINTS_AVAILABLE = True
except ImportError:
    CHECKPOINTS_AVAILABLE = False

# In-memory tool run results: "{tool}:{target}" -> ToolResult dict
tool_run_results: dict[str, dict] = {}
JOB_SCHEDULER = None

# ─── Companies helpers ────────────────────────────────────────────────────────
def load_companies() -> list:
    companies = DB.load_companies()
    return _apply_company_scope(companies)

def save_companies(companies: list):
    DB.save_companies(companies)

# ─── Company scope filter ───────────────────────────────────────────────────

def _apply_company_scope(items: list) -> list:
    """Filter company list based on current user's scoped_companies.
    Super admin gets unrestricted access. Empty scope means no company access."""
    sess = _get_session()
    if not sess:
        return items
    scoped = _normalize_scope(sess)
    if scoped is None:
        return items
    if not scoped:
        return []
    allowed = set(scoped)
    return [c for c in items if c.get("id") in allowed]

def _filter_asm_data_by_scope(data: dict) -> dict:
    """Filter asm_data companies by user scope. Returns copy with filtered list."""
    sess = _get_session()
    if not sess:
        return data
    scoped = _normalize_scope(sess)
    if scoped is None:
        return data
    if not scoped:
        return {**data, "companies": []}
    allowed = set(scoped)
    filtered = [c for c in data.get("companies", []) if c.get("id") in allowed]
    return {**data, "companies": filtered}

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return (BASE / "static" / "index.html").read_text(encoding="utf-8"), 200, {"Content-Type": "text/html; charset=utf-8"}

@app.route("/dashboard.css")
def serve_dashboard_css():
    return (BASE / "static" / "css" / "dashboard.css").read_text(encoding="utf-8"), 200, {"Content-Type": "text/css; charset=utf-8"}

@app.route("/dashboard.js")
def serve_dashboard_js():
    return (BASE / "static" / "js" / "dashboard.js").read_text(encoding="utf-8"), 200, {"Content-Type": "application/javascript; charset=utf-8"}

@app.route("/js/asm.js")
def serve_asm_js():
    return (BASE / "static" / "js" / "asm.js").read_text(encoding="utf-8"), 200, {"Content-Type": "application/javascript; charset=utf-8"}

@app.route("/js/api.js")
def serve_api_js():
    return (BASE / "static" / "js" / "api.js").read_text(encoding="utf-8"), 200, {"Content-Type": "application/javascript; charset=utf-8"}

@app.route("/js/config.js")
def serve_config_js():
    return (BASE / "static" / "js" / "config.js").read_text(encoding="utf-8"), 200, {"Content-Type": "application/javascript; charset=utf-8"}

@app.route("/js/i18n.js")
def serve_i18n_js():
    return (BASE / "static" / "js" / "i18n.js").read_text(encoding="utf-8"), 200, {"Content-Type": "application/javascript; charset=utf-8"}

@app.route("/js/bugbounty.js")
def serve_bugbounty_js():
    return (BASE / "static" / "js" / "bugbounty.js").read_text(encoding="utf-8"), 200, {"Content-Type": "application/javascript; charset=utf-8"}

@app.route("/js/bbprograms.js")
def serve_bbprograms_js():
    return (BASE / "static" / "js" / "bbprograms.js").read_text(encoding="utf-8"), 200, {"Content-Type": "application/javascript; charset=utf-8"}

@app.route("/js/generators.js")
def serve_generators_js():
    return (BASE / "static" / "js" / "generators.js").read_text(encoding="utf-8"), 200, {"Content-Type": "application/javascript; charset=utf-8"}

# ─── Bug Bounty Programs API proxy ────────────────────────────────────

@app.route("/api/bbprograms/hackerone")
@require_auth
def bbprograms_hackerone():
    """Proxy para a API do HackerOne. Requer hackerone_username + hackerone_token nas settings."""
    from urllib.request import urlopen, Request as UrlRequest
    from urllib.error import URLError, HTTPError
    import base64

    settings = _get_settings()
    username = settings.get("hackerone_username", "").strip()
    token    = settings.get("hackerone_token", "").strip()

    if not username or not token:
        return jsonify({"no_creds": True, "programs": [], "total_pages": 0})

    page = request.args.get("page", "1")
    q    = request.args.get("q", "")

    creds = base64.b64encode(f"{username}:{token}".encode()).decode()
    url = f"https://api.hackerone.com/v1/hackers/programs?page[number]={page}&page[size]=25"
    if q:
        url += f"&filter[name]={q}"

    try:
        req = UrlRequest(url, headers={
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
            "User-Agent": "SCANTRELY/1.0",
        })
        with urlopen(req, timeout=15) as resp:
            raw = json.loads(resp.read().decode())
    except HTTPError as e:
        if e.code in (401, 403):
            return jsonify({"error": "Credenciais inválidas. Verifique seu username e API token do HackerOne.", "auth_error": True}), 200
        return jsonify({"error": f"HackerOne API error: {e.code} {e.reason}"}), 502
    except URLError as e:
        return jsonify({"error": f"Erro de conexão: {e.reason}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 502

    data = raw.get("data", [])
    programs = []
    for item in data:
        attrs = item.get("attributes", {})
        programs.append({
            "id":            item.get("id", ""),
            "handle":        attrs.get("handle", ""),
            "name":          attrs.get("name", ""),
            "state":         attrs.get("state", ""),
            "offers_bounties": attrs.get("offers_bounties", False),
            "min_bounty_table_value": attrs.get("minimum_bounty_table_value", 0),
            "max_bounty_table_value": attrs.get("maximum_bounty_table_value", 0),
            "profile_picture_urls": attrs.get("profile_picture_urls", {}),
            "statistics":    attrs.get("statistics", {}),
            "in_scope":      attrs.get("structured_policy_data", {}).get("in_scope", []),
            "platform":      "hackerone",
        })

    links = raw.get("links", {})
    has_next = bool(links.get("next"))
    return jsonify({
        "programs":    programs,
        "total_pages": int(page) + (1 if has_next else 0),
    })





@app.route("/favicon.ico")
def serve_favicon():
    return "", 204

@app.route("/asm_data.js")
def serve_data_js():
    data = DB.load_asm_data()
    return (
        "window.ASM_DATA = " + json.dumps(data, ensure_ascii=False, indent=2) + ";\n",
        200,
        {"Content-Type": "application/javascript"},
    )

_checkpoint_jobs: dict[str, dict] = {}
_sched_lock = threading.Lock()

# ─── Audit log ────────────────────────────────────────────────────────────────

def _audit(action: str, target: str = "", details: str = ""):
    sess = _get_session()
    user = sess["username"] if sess else "system"
    entry = {
        "ts":      datetime.now().isoformat(timespec="seconds"),
        "user":    user,
        "action":  action,
        "target":  target,
        "details": details,
    }
    try:
        DB.append_audit_log(entry)
    except Exception:
        pass


# ─── ASM data helpers ─────────────────────────────────────────────────────────

def _load_asm_data() -> dict:
    data = DB.load_asm_data()
    return _filter_asm_data_by_scope(data)

def _load_asm_data_full() -> dict:
    """Unfiltered — for internal use (pipeline, diffs, etc.)."""
    return DB.load_asm_data()


def _get_company_data(cid: str) -> dict | None:
    if not _session_can_access_company(cid):
        return None
    for co in _filter_asm_data_by_scope(DB.load_asm_data()).get("companies", []):
        if co["id"] == cid:
            return co
    return None


# ─── Webhook dispatch ─────────────────────────────────────────────────────────

def _load_webhooks() -> list:
    return DB.load_webhooks()


def _send_webhook(hook: dict, payload: dict):
    """Test/ad-hoc send for a single webhook (used by /api/webhooks/test)."""
    from utils.notifications import dispatch_webhook
    text = payload.get("text", "")
    dispatch_webhook(hook, "test", {"message": text}, settings=_get_settings(), base_dir=BASE)


def _fire_webhooks(event: str, company_name: str, company_id: str, summary: dict):
    """Dispatch a scan event to every configured webhook subscribed to it."""
    from utils.notifications import notify
    notify(DB, _get_settings, BASE, event, {"company_name": company_name, "company_id": company_id, **summary})


# ─── Surface diff (snapshot-based) ────────────────────────────────────────────

def _save_snapshot(cid: str):
    co = _get_company_data(cid)
    if not co:
        return
    snap = {
        "ts":       datetime.now().isoformat(timespec="seconds"),
        "hosts":    [h["host"] if isinstance(h, dict) else h for h in co.get("hosts", [])],
        "ports":    {(h["host"] if isinstance(h, dict) else h):
                     (h.get("ports", []) if isinstance(h, dict) else [])
                     for h in co.get("hosts", [])},
        "findings": [f"{f.get('host','')}|{f.get('title','')}|{f.get('severity','')}"
                     for f in co.get("findings", [])],
    }
    current = DB.load_snapshot(cid, slot="current")
    if current:
        DB.save_snapshot(cid, current, slot="previous")
    DB.save_snapshot(cid, snap, slot="current")


def _compute_diff(cid: str) -> dict:
    curr = DB.load_snapshot(cid, slot="current")
    if not curr:
        return {"error": "No snapshot — run a scan first"}
    prev = DB.load_snapshot(cid, slot="previous")
    if not prev:
        return {"error": "No previous snapshot to compare against", "current_hosts": len(curr["hosts"])}
    # Normalize hosts: may be dicts ({"host": "x.com", ...}) or strings
    def _hostnames(hosts_list):
        result = []
        for h in (hosts_list or []):
            result.append(h["host"] if isinstance(h, dict) else str(h))
        return result
    # Normalize findings: may be dicts ({"key": "...", "severity": "..."}) or strings
    def _finding_keys(findings_list):
        result = []
        for f in (findings_list or []):
            result.append(f["key"] if isinstance(f, dict) else str(f))
        return result
    def _find_host_ports(hosts_list, hostname):
        for h in (hosts_list or []):
            name = h["host"] if isinstance(h, dict) else str(h)
            if name == hostname:
                return h.get("ports", []) if isinstance(h, dict) else []
        return []
    curr_hosts = set(_hostnames(curr.get("hosts")))
    prev_hosts = set(_hostnames(prev.get("hosts")))
    new_hosts     = sorted(curr_hosts - prev_hosts)
    removed_hosts = sorted(prev_hosts - curr_hosts)
    curr_finds = set(_finding_keys(curr.get("findings")))
    prev_finds = set(_finding_keys(prev.get("findings")))
    new_findings     = sorted(curr_finds - prev_finds)
    resolved_findings= sorted(prev_finds - curr_finds)
    # Port changes
    port_changes = []
    for host in curr_hosts & prev_hosts:
        cp = set(_find_host_ports(curr.get("hosts", []), host))
        pp = set(_find_host_ports(prev.get("hosts", []), host))
        if cp != pp:
            port_changes.append({"host": host, "added": sorted(cp-pp), "removed": sorted(pp-cp)})
    return {
        "prev_ts":          prev.get("ts", ""),
        "curr_ts":          curr.get("ts", ""),
        "new_hosts":        new_hosts,
        "removed_hosts":    removed_hosts,
        "new_findings":     [f.split("|") for f in new_findings],
        "resolved_findings": [f.split("|") for f in resolved_findings],
        "port_changes":     port_changes,
        "summary": {
            "new_hosts":      len(new_hosts),
            "removed_hosts":  len(removed_hosts),
            "new_findings":   len(new_findings),
            "resolved":       len(resolved_findings),
            "port_changes":   len(port_changes),
        },
    }


# ─── Whitelist helpers ────────────────────────────────────────────────────────

def _load_whitelist() -> dict:
    return DB.load_whitelist()


def _save_whitelist(wl: dict):
    DB.save_whitelist(wl)


# ─── Risk score ───────────────────────────────────────────────────────────────

def _compute_risk_score(co_data: dict) -> dict:
    findings = co_data.get("findings", [])
    hosts    = co_data.get("hosts", [])
    stats    = co_data.get("stats", {})
    c = sum(1 for f in findings if f.get("severity") == "critical")
    h = sum(1 for f in findings if f.get("severity") == "high")
    m = sum(1 for f in findings if f.get("severity") == "medium")
    l = sum(1 for f in findings if f.get("severity") == "low")
    score = min(100, c * 40 + h * 10 + m * 3 + l * 1)
    # Exposure multipliers
    waf = co_data.get("waf_coverage", {})
    direct = waf.get("Direct", 0) + waf.get("", 0)
    total  = max(1, sum(waf.values()))
    direct_pct = direct / total
    if direct_pct > 0.5:
        score = min(100, score + 10)
    # Admin port exposure
    admin_ports = {"22", "3389", "5900", "8080", "8443", "9200", "27017", "6379", "5432", "3306"}
    exposed_admin = sum(
        1 for h in hosts
        if isinstance(h, dict) and any(str(p) in admin_ports for p in h.get("ports", []))
    )
    score = min(100, score + min(20, exposed_admin * 5))
    if score == 0 and (stats.get("live_hosts", 0) > 0):
        score = 5  # Base score for any live exposure
    label = ("Critical" if score >= 80 else "High" if score >= 60
             else "Medium" if score >= 40 else "Low" if score >= 20 else "Info")
    return {
        "score": score, "label": label,
        "breakdown": {
            "critical_findings": c, "high_findings": h,
            "medium_findings": m, "low_findings": l,
            "direct_exposed_pct": round(direct_pct * 100),
            "exposed_admin_services": exposed_admin,
        },
    }


# ─── Scheduler ────────────────────────────────────────────────────────────────

def _load_schedules() -> dict:
    return DB.load_schedules()


def _save_schedules(s: dict):
    DB.save_schedules(s)


def _scheduler_loop():
    while True:
        time.sleep(60)
        try:
            scheds = _load_schedules()
            now    = datetime.now()
            for cid, cfg in scheds.items():
                if not cfg.get("enabled"):
                    continue
                next_run = cfg.get("next_run")
                if not next_run:
                    continue
                try:
                    nr = datetime.fromisoformat(next_run)
                except Exception:
                    continue
                if now >= nr:
                    companies = load_companies()
                    co = next((c for c in companies if c["id"] == cid), None)
                    if not co:
                        continue
                    targets = co.get("domains", [])
                    if not targets:
                        continue
                    # Skip if pipeline already running for this company
                    state = _runner.pipeline_state.get(cid, {})
                    if state.get("status") == "running":
                        continue
                    profile = cfg.get("profile", "deep")
                    options = {"rate_mode": "stealth"}  # Default or pull from cfg
                    if JOB_SCHEDULER:
                        JOB_SCHEDULER.enqueue_pipeline(
                            cid,
                            options=options,
                            created_by="scheduler",
                            dedupe=True,
                        )
                    else:
                        threading.Thread(
                            target=lambda cid, co, opts: _runner.run_pipeline(cid, co, opts),
                            args=(cid, co, options),
                            daemon=True
                        ).start()
                    
                    _audit("scheduled_scan", cid, f"profile={profile}")
                    # Update next_run
                    hours = cfg.get("interval_hours", 24)
                    cfg["next_run"] = (now + timedelta(hours=hours)).isoformat(timespec="seconds")
                    cfg["last_run"] = now.isoformat(timespec="seconds")
                    scheds[cid] = cfg
            _save_schedules(scheds)
        except Exception:
            pass


if os.environ.get("ASM_ENABLE_SCHEDULED_SCANS", "0") == "1":
    threading.Thread(target=_scheduler_loop, daemon=True, name="asm-scheduled-scan-loop").start()

# ── Recon modules ─────────────────────────────────────────────────────────────

RECON_MODULES = {
    "email":     ("Email Security (SPF/DMARC/DKIM)",  "~10s"),
    "certs":     ("Certificate Transparency + SSL",    "~20s"),
    "headers":   ("Security Headers",                  "~30s"),
    "typosquat": ("Typosquatting Detection",           "~2m"),
    "cloud":     ("Cloud Asset Discovery (S3/Azure/GCP)", "~3m"),
    "related":   ("Related Domain Discovery",          "~30s"),
    "wayback":   ("Wayback/GAU URL Mining",            "~2m"),
    "waf":       ("WAF Detection",                     "~1m"),
    "takeover":  ("Subdomain Takeover Check",          "~2m"),
    "breach":    ("Breach & Credential Leaks",         "~30s"),
    "shodan":    ("Shodan Intelligence",               "~1m"),
    "portscan":  ("Port Scan (naabu/nmap)",            "~5m"),
    "asn":       ("ASN / IP Blocks",                   "~30s"),
    "services":  ("Exposed Services & Paths",          "~5m"),
    "leaks":     ("GitHub Secrets & .git Exposure",    "~2m"),
    "dns":       ("Full DNS Records",                  "~10s"),
    "cve":       ("CVE Lookup — Tech Stack vs NVD",    "~2m"),
    "vhost":     ("Virtual Host Discovery",            "~3m"),
    "js":        ("JavaScript Recon",                  "~5m"),
    "screenshot":("Screenshots Visual Inventory",      "~3m"),
    "dns_brute":   ("DNS Brute-force & Permutations",     "~5m"),
    "api_panels":  ("API/Panel Exposure (Nuclei)",        "~5m"),
    "certstream":  ("CertStream New Asset Monitor",       "~2m"),
    "wappalyzer":   ("Wappalyzer Tech Detection (httpx)",  "~2m"),
    "dep_confusion":("Dependency Confusion (npm/PyPI/RubyGems)", "~3m"),
    # ── New methodology modules ──────────────────────────────────────────────
    "subjack":      ("Subdomain Takeover (subjack)",        "~3m"),
    "cms_scan":     ("CMS Scan (WPScan)",                   "~5m"),
    "cloud_enum":   ("Cloud Bucket Enumeration (cloud_enum)", "~3m"),
    "param_mine":   ("Parameter Discovery (arjun)",         "~5m"),
    "js_endpoints": ("JS Endpoint Extraction (linkfinder)",  "~2m"),
    "js_secrets":   ("JS Secret Detection (secretfinder)",   "~2m"),
    "favicon_hunt": ("Favicon Hash → Origin IP (Shodan)",   "~1m"),
    # NOTE: "grep_app" was advertised here but has no implementation in
    # _make_fn_map, so running it raised KeyError('grep_app'). Removed until a
    # real grep.app code-search module is implemented.
    # ── New security modules ──────────────────────────────────────────────────
    "cors_scan":     ("CORS Misconfiguration Scanner",       "~3m"),
    "infra_exposure":("K8s/Docker/etcd Exposure Detection",  "~3m"),
    "graphql":       ("GraphQL Endpoint & Introspection",    "~2m"),
    # ── ProjectDiscovery additions ───────────────────────────────────────────
    "asnmap":       ("ASN/IP Range Mapper (asnmap)",        "~30s"),
    "cloudlist":    ("Authenticated Cloud Enumeration (cloudlist)", "~3m"),
    "urlfinder":    ("URL Discovery — Wayback/CC/AVault (urlfinder)", "~2m"),
    # ── Browser deep recon ─────────────────────────────────────────────────────
    "browser_recon":("Deep Browser Recon — APIs, Secrets, Shadow IT (Chromium)","~45s"),
    "supply_chain":  ("JS Supply Chain Scan — Client-side lib CVEs (NVD)","~2m"),
}

def _load_hosts_for_company(cid: str) -> list:
    """Load host list from persisted ASM data for a company.

    Internal pipeline use (runs in background worker threads with NO Flask
    request/session context) — must read directly and NOT apply request-session
    scoping. Going through _get_company_data here returned [] in worker threads
    (no session ⇒ access denied), which silently starved the vuln/active phases
    of targets (has_live_hosts gate failed ⇒ phases skipped)."""
    for co in DB.load_asm_data().get("companies", []):
        if co.get("id") == cid:
            return co.get("hosts", []) or []
    return []

_SETTINGS_KEYS = {
    "hackerone_username", "hackerone_token",
    "shodan_key", "github_token", "hibp_key", "dehashed_key",
    "censys_api_id", "censys_api_secret", "securitytrails_key",
    "virustotal_key", "binaryedge_key", "fullhunt_key",
    "fofa_email", "fofa_key", "netlas_key", "chaos_key",
    "leakix_key", "hunter_key", "intelx_key", "nvd_key",
    "otx_key", "wpscan_token", "whoisxml_key",
    "hermes_api_key", "hermes_base_url", "hermes_model",
    "playwright_auto_run", "playwright_safe_mode", "playwright_headless",
    "playwright_allow_external", "playwright_trace", "playwright_max_pages",
    "playwright_max_depth", "playwright_timeout", "playwright_slow_mo",
    "playwright_user_agent", "playwright_auth_state", "playwright_auth_state_b",
    "playwright_test_xss", "playwright_test_race", "playwright_test_access",
    # Runtime / performance (read from env, persisted in settings.json)
    "asm_job_workers", "asm_global_proc_limit", "asm_domain_fanout",
    "asm_gate_default", "asm_rate_mode", "asm_scan_mode",
    "asm_watchdog_max_load", "asm_watchdog_min_mem_mb", "asm_watchdog_max_procs",
}

_PUBLIC_SETTINGS_KEYS = {
    "playwright_auto_run", "playwright_safe_mode", "playwright_headless",
    "playwright_allow_external", "playwright_trace", "playwright_max_pages",
    "playwright_max_depth", "playwright_timeout", "playwright_slow_mo",
    "playwright_user_agent", "playwright_auth_state", "playwright_auth_state_b",
    "playwright_test_xss", "playwright_test_race", "playwright_test_access",
}

_runner = ReconRunner(
    db=DB,
    base_dir=BASE,
    get_settings=_get_settings,
    load_hosts_fn=_load_hosts_for_company,
    recon_module=_recon if RECON_AVAILABLE else None,
    recon_available=RECON_AVAILABLE,
    tool_registry=_tool_registry if TOOLS_AVAILABLE else None,
)

app.register_blueprint(create_core_blueprint(
    session_ttl=_SESSION_TTL,
    sessions=_sessions,
    load_admins=load_admins,
    save_admins=save_admins,
    hash_pw=_hash_pw,
    check_pw=_check_pw,
    get_session=_get_session,
    require_auth=require_auth,
    require_super_admin=require_super_admin,
    audit=_audit,
    get_settings=_get_settings,
    save_settings=DB.set_settings,
    settings_keys=_SETTINGS_KEYS,
    public_settings_keys=_PUBLIC_SETTINGS_KEYS,
    db=DB,
))

app.register_blueprint(create_ops_blueprint(
    require_auth=require_auth,
    require_super_admin=require_super_admin,
    load_schedules=_load_schedules,
    save_schedules=_save_schedules,
    load_webhooks=_load_webhooks,
    save_webhooks=DB.save_webhooks,
    send_webhook=_send_webhook,
    compute_diff=_compute_diff,
    load_whitelist=_load_whitelist,
    save_whitelist=_save_whitelist,
    get_session=_get_session,
    audit=_audit,
    list_audit_log=DB.list_audit_log,
))

app.register_blueprint(create_reporting_blueprint(
    require_auth=require_auth,
    get_company_data=_get_company_data,
    compute_risk_score=_compute_risk_score,
    load_whitelist=_load_whitelist,
    load_asm_data=_load_asm_data,
    audit=_audit,
))

app.register_blueprint(create_asset_blueprint(
    require_auth=require_auth,
    load_companies=load_companies,
    save_companies=save_companies,
    get_settings=_get_settings,
    save_settings=DB.set_settings,
    get_company_data=_get_company_data,
    tools_available=TOOLS_AVAILABLE,
    tool_registry=_tool_registry if TOOLS_AVAILABLE else None,
    tool_run_results=tool_run_results,
    checkpoints_available=CHECKPOINTS_AVAILABLE,
    checkpoints_module=_checkpoints if CHECKPOINTS_AVAILABLE else None,
    load_hosts_for_company=_load_hosts_for_company,
    checkpoint_jobs=_checkpoint_jobs,
    db=DB,
    scans_dir=BASE / "scans",
))

app.register_blueprint(create_scan_blueprint(
    require_auth=require_auth,
    base_dir=BASE,
    load_companies=load_companies,
    load_asm_data=_load_asm_data,
    save_asm_data=DB.save_asm_data,
    get_asm_data_timestamp=DB.get_asm_data_timestamp,
    load_schedules=_load_schedules,
    save_schedules=_save_schedules,
    db=DB,
))

def _safe_run_pipeline(cid: str, co: dict, options: dict):
    """Wrap run_pipeline so any uncaught exception marks the pipeline as error."""
    try:
        _runner.run_pipeline(cid, co, options)
    except Exception as _e:
        import traceback as _tb
        _msg = f"Pipeline crashed: {_e}\n{_tb.format_exc()[-800:]}"
        state = _runner.pipeline_state.get(cid, {})
        if state.get("status") not in ("done", "stopped"):
            state.update({
                "status": "error",
                "finished_at": datetime.now().isoformat(timespec="seconds"),
            })
            state.setdefault("log", []).append({
                "ts": datetime.now().isoformat(timespec="seconds"),
                "msg": f"❌ {_msg}",
            })
            _runner._save_pipeline_state(cid)


def _safe_run_playwright_recon(cid: str, co: dict, options: dict):
    """Run the Playwright recon pipeline and surface any crash as a job error."""
    try:
        from playwright_agent.asm_bridge import run_company_playwright_job

        result = run_company_playwright_job(
            cid,
            co,
            options,
            base_dir=BASE / "data" / "playwright-jobs",
        )
        try:
            session_path = Path(result.get("session_path", ""))
            if session_path.exists():
                session = json.loads(session_path.read_text(encoding="utf-8"))
                _runner.merge_playwright_findings(cid, session)
        except Exception:
            pass
        return result
    except Exception:
        raise


JOB_SCHEDULER = JobScheduler(
    db=DB,
    load_companies=load_companies,
    run_pipeline=_safe_run_pipeline,
    run_playwright_recon=_safe_run_playwright_recon,
    pipeline_state=_runner.pipeline_state,
    save_pipeline_state=_runner._save_pipeline_state,
    get_settings=_get_settings,
    max_workers=int(os.environ.get("ASM_JOB_WORKERS", "1") or "1"),
)
JOB_SCHEDULER.start()


app.register_blueprint(create_recon_blueprint(
    require_auth=require_auth,
    recon_available=RECON_AVAILABLE,
    recon_modules=RECON_MODULES,
    self_contained_modules=SELF_CONTAINED_MODULES,
    run_recon_handler=_runner.run_module_request,
    load_companies=load_companies,
    get_settings=_get_settings,
    pipeline_state=_runner.pipeline_state,
    pipeline_phases=PIPELINE_PHASES,
    run_pipeline_handler=lambda cid, co, options: threading.Thread(
        target=_safe_run_pipeline, args=(cid, co, options), daemon=True
    ).start(),
    recon_results=_runner.results,
    load_asm_data=_load_asm_data,
    save_asm_data=DB.save_asm_data,
    get_tool_logs=_runner.get_tool_logs,
    clear_tool_logs=_runner.clear_tool_logs,
    get_tool_log_detail=_runner.get_tool_log_detail,
    clear_checkpoints=_runner.clear_checkpoints,
    load_pipeline_state=_runner._load_pipeline_state,
    base_dir=BASE,
    job_scheduler=JOB_SCHEDULER,
    db=DB,
))


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    print(f"""
  ===================================
    ASM Platform - Server v1.1
  ===================================
  -> http://{args.host}:{args.port}
  -> Database       : {DB_FILE}
  -> Companies file : {CO_FILE}
  -> Data output    : {DATA_JS}
    """)

    app.run(host=args.host, port=args.port, debug=False, threaded=True)
