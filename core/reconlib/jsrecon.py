"""JavaScript Recon — extraído de core/recon.py (ver core/recon.py para o índice completo)."""
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from datetime import datetime
from pathlib import Path
import json
import re
import time
from core.reconlib.base import _log, _subp, bind_cancel, current_cancel, http_get
from core.reconlib.browser import _pw_import

# ── JavaScript Recon ──

# Secret patterns: (regex, type, severity)
_JS_SECRET_PATTERNS = [
    # Cloud / infra keys
    (r'AKIA[0-9A-Z]{16}',                                                                   "aws_access_key",    "critical"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key[\s\'"]*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',"aws_secret",        "critical"),
    (r'AIza[0-9A-Za-z\-_]{35}',                                                             "google_api_key",    "high"),
    (r'(?i)firebase[^\n]{0,40}https://[a-zA-Z0-9\-]+\.firebaseio\.com',                     "firebase_url",      "high"),
    (r'ghp_[A-Za-z0-9]{36}',                                                                "github_token",      "critical"),
    (r'ghs_[A-Za-z0-9]{36}',                                                                "github_app_token",  "critical"),
    (r'github_pat_[A-Za-z0-9_]{20,}',                                                       "github_pat",        "critical"),
    (r'xox[baprs]-[A-Za-z0-9-]{10,}',                                                       "slack_token",       "critical"),
    (r'sk-proj-[A-Za-z0-9_-]{20,}',                                                         "openai_key",        "critical"),
    (r'sk-ant-[A-Za-z0-9_-]{20,}',                                                          "anthropic_key",     "critical"),
    (r'npm_[A-Za-z0-9]{36}',                                                                "npm_token",         "high"),
    (r'sk_live_[A-Za-z0-9]{24,}',                                                           "stripe_live_key",   "critical"),
    (r'sk_test_[A-Za-z0-9]{24,}',                                                           "stripe_test_key",   "high"),
    (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',                                        "sendgrid_key",      "critical"),
    (r'(?i)twilio[^\n]{0,20}(?:SK|AC)[a-f0-9]{32}',                                         "twilio_key",        "critical"),
    (r'key-[a-z0-9]{32}',                                                                   "mailgun_key",       "high"),
    (r'(?i)bearer\s+eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',               "jwt_bearer",        "high"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',                "jwt_token",         "medium"),
    # API Gateway credentials — Sensedia, Kong, Apigee, MuleSoft, AWS API GW
    # client_secret alone is high; client_id alone is medium (semi-public); both together → critical (handled in _analyze_js_content)
    (r'(?i)(?:client[_-]?secret|clientSecret)\s*[=:]\s*["\']([A-Za-z0-9_\-\.@]{16,80})["\']',         "client_secret",   "high"),
    (r'(?i)(?<!["\w])client[_-]?id(?!["\w])\s*[=:]\s*["\']([A-Za-z0-9_\-\.@]{8,80})["\']',            "client_id",       "medium"),
    # Quoted-key style: {"client_id":"val"} / {"client-id":"val"} (Sensedia header injection)
    (r'["\']client[_\-]id["\']\s*:\s*["\']([A-Za-z0-9_\-\.@]{8,80})["\']',                            "client_id",       "medium"),
    (r'["\']client[_\-]secret["\']\s*:\s*["\']([A-Za-z0-9_\-\.@]{16,80})["\']',                       "client_secret",   "high"),
    # OAuth2 consumer key/secret (Sensedia / Kong / Apigee also use these names)
    (r'(?i)consumer[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-\.@]{16,80})["\']',                           "consumer_key",    "high"),
    (r'(?i)consumer[_-]?secret\s*[=:]\s*["\']([A-Za-z0-9_\-\.@]{16,80})["\']',                        "consumer_secret", "high"),
    # Generic credentials — values must contain real entropy (mixed chars, not i18n keys or snake_case labels)
    # Exclude AIza* (already caught as google_api_key) and pure snake_case/SCREAMING_SNAKE_CASE labels
    (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\'](?!AIza)([A-Za-z0-9_\-]{20,}[A-Za-z][0-9][A-Za-z0-9_\-]*)["\']', "api_key",      "high"),
    (r'(?i)(?:secret[_-]?key|secretkey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',                    "secret_key",      "high"),
    (r'(?i)(?:access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',           "access_token",    "high"),
    # Password: require value has real entropy — must contain digit OR special char, and NOT be an i18n key pattern
    (r'(?i)(?:password|passwd)\s*[=:]\s*["\']([^\'"]{8,64})["\']',                          "password",          "high"),
    (r'(?i)authorization\s*[=:]\s*["\']Basic\s+([A-Za-z0-9+/=]{8,})["\']',                 "basic_auth",        "high"),
    # Cloud storage
    (r's3\.amazonaws\.com/([a-z0-9\-\.]{3,})',                                              "s3_bucket",         "medium"),
    (r'([a-z0-9\-]{3,})\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com',                            "s3_bucket",         "medium"),
    (r'https?://[a-z0-9\-]+\.blob\.core\.windows\.net',                                     "azure_blob",        "medium"),
    (r'gs://([a-z0-9\-_\.]+)',                                                               "gcs_bucket",        "medium"),
    # Internal network — proper octet validation (0-255 only, prevents SVG coordinate false positives)
    (r'(?<!["\'\w.])(10\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))(?!["\'\w.])', "internal_ip", "low"),
    (r'(?<!["\'\w.])(192\.168\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))(?!["\'\w.])',                                     "internal_ip", "low"),
    (r'(?<!["\'\w.])(172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))(?!["\'\w.])',                   "internal_ip", "low"),
    # Private key material
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',                                           "private_key",       "critical"),
    # Chat/webhook integrations
    (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',    "slack_webhook",     "critical"),
    (r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',                               "discord_webhook",   "critical"),
    (r'https://discordapp\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',                            "discord_webhook",   "critical"),
    # Email addresses in JS (contact, support, noreply — still PII/OSINT useful)
    (r'[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}',                                                       "email_address",     "low"),
    # oauth2/token endpoint with client credentials
    (r'(?i)oauth2?/token[^\n]{0,80}client_id[^\n]{0,40}',                                    "oauth_endpoint",    "medium"),
    # Database connection strings
    (r'(?i)(?:mongodb|mysql|postgresql|redis)://[a-zA-Z0-9_]+:[^@\s]+@',                    "db_connection",     "critical"),
]


# LinkFinder regex — matches the same multi-group pattern as the original tool
_ENDPOINT_RE = re.compile(
    r"""(?:"|')"""
    r"""("""
    r"""(?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}"""   # full URLs
    r"""|(?:/|\.\./|\./)"""                                               # relative: /, ../, ./
    r"""[^"'><,;| *()(%%$^/\\\[\]]{1,}[^"'><,;|()]{1,}"""
    r"""|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}"""                     # path/to/resource.ext
    r"""\.(?:[a-zA-Z]{1,4}|action)(?:[?#][^"']{0,}|)"""
    r"""|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[?#][^"']{0,}|)"""  # REST endpoints
    r"""|[a-zA-Z0-9_\-]{1,}"""                                           # bare filenames
    r"""\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[?#][^"']{0,}|)"""
    r""")"""
    r"""(?:"|')""",
    re.VERBOSE | re.MULTILINE,
)

# Imperva / WAF bot-challenge JS URL patterns — these look like real JS files but aren't
_WAF_CHALLENGE_URL_RE = re.compile(
    r'/(?:[a-z]{1,4}-)?(?:[A-Z][a-z]+-){3,}|'   # CamelCase word-slug paths
    r'\?d=[\w.\-]+\.[a-z]{2,}$|'                  # Imperva ?d=domain fingerprint
    r'/(?:[a-z]+-){2,}(?:[A-Z][a-z]+-){2,}',     # mixed-case random word slug
)


_INTERESTING_RE = [
    (re.compile(r'graphql',          re.I), "GraphQL"),
    (re.compile(r'\.execute\s*\(',   re.I), "JS eval/exec"),
    (re.compile(r'innerHTML\s*=',    re.I), "innerHTML sink"),
    (re.compile(r'document\.write\s*\(', re.I), "document.write sink"),
    (re.compile(r'eval\s*\(',        re.I), "eval() call"),
    (re.compile(r'window\.location\s*=', re.I), "open redirect sink"),
    (re.compile(r'(?i)sql\s*[=+]\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE)', re.I), "SQL string"),
    (re.compile(r'debugger;',        re.I), "debugger statement"),
    (re.compile(r'(?i)(?:mongo|redis|postgres|mysql|oracle)(?:URI|URL|Conn|Connection)?[\s\'"]*[=:]\s*["\']', re.I), "DB connection string"),
    (re.compile(r'(?i)cors.*allow.*origin.*\*',  re.I), "CORS wildcard"),
    (re.compile(r'(?i)Access-Control-Allow-Origin[^\n]*\*', re.I), "CORS wildcard"),
]



_FP_PASSWORD_RE = re.compile(
    r'(?i)(%filtered%|wrong.?password|forgot.?password|invalid.?password|missing.?password'
    r'|need.?password|change.?password|reset.?password|show.?password|confirm.?password'
    r'|enter.?password|password.?hint|password.?set|create.?password|redefine.?password'
    r'|new.?password|old.?password|repeat.?password'
    # MSAL/Azure AD numeric error codes (e.g. PASSWORD:"80041012")
    r'|["\']?[0-9A-F]{8,}["\']?'
    # i18n key patterns used as password labels
    r'|eOTT_|OneTimePassword|NoPassword)',
)

_FP_LABEL_RE = re.compile(r'^[A-Z][A-Z0-9_\-]{3,}$|^[a-z][a-z0-9_]{4,}[a-z0-9]$')



# nome de classe gerado por CSS Modules/bundler: "_forgetPassword_ejzvx_198" (variável forgetPassword
# = estilo do link "esqueci a senha"), não é senha — 3 "altos" falsos em 15/10/2026
_CSS_MODULE_CLASS_RE = re.compile(r"^_?[A-Za-z][\w-]*_[a-z0-9]{5}_\d+$")


def _unescape_js(s: str) -> str:
    """\\xE9 / \\u00e9 do bundle → caractere (texto de interface em espanhol/português vinha escapado)."""
    return re.sub(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1) or m.group(2), 16)), s or "")


def _is_fp_secret(ptype: str, value: str) -> bool:
    """Return True when a regex match is almost certainly a false positive."""
    if ptype == "password":
        # Strip surrounding quotes and key name to get the raw value
        inner = re.sub(r'(?i)^(?:password|passwd|pwd)\s*[=:]\s*["\']', '', value).rstrip('"\'')
        # texto de interface em qualquer língua (letras acentuadas inclusive), duas palavras ou mais
        if re.match(r"^[^\W\d_]+( [^\W\d_]+)+$", _unescape_js(inner).strip()):
            return True
        if _CSS_MODULE_CLASS_RE.match(inner.strip()):
            return True
        if _FP_PASSWORD_RE.search(inner):
            return True
        # Pure i18n keys: ALL_CAPS_WITH_UNDERSCORES or pure snake_case (no digits/specials)
        if re.match(r'^[A-Z][A-Z0-9_\-\.]+$', inner) or re.match(r'^[a-z][a-z\-\.]+$', inner):
            return True
        # Value is itself the word "password" or a trivial variant
        if re.match(r'^["\']?passwords?["\']?$', inner, re.I):
            return True
        # JS code fragments: code chars, .method() calls, or +var. concatenation
        if re.search(r'[\[\]{}&|?]|\.substring\(|\+[a-z]+\.', inner):
            return True
        # Sentence-like phrases: only letters and spaces, no digits or specials
        if re.match(r'^[A-Za-z][A-Za-z ]+$', inner):
            return True
        return False

    if ptype in ("access_token", "secret_key"):
        # Extract just the value portion (after the key name and delimiter)
        inner = re.sub(r'(?i)^[\w\-]+\s*[=:]\s*["\']', '', value).rstrip('"\'')
        # Pure snake_case or SCREAMING_SNAKE_CASE labels are variable name strings, not tokens
        if _FP_LABEL_RE.match(inner):
            return True
        return False

    if ptype == "api_key":
        inner = re.sub(r'(?i)^[\w\-]+\s*[=:]\s*["\']', '', value).rstrip('"\'')
        if _FP_LABEL_RE.match(inner):
            return True
        return False

    if ptype == "internal_ip":
        # Validate octets are all 0-255; stored values may have invalid octets from SVG paths
        m = re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', value)
        if not m:
            return True
        return any(int(o) > 255 for o in m.groups())

    return False



def _decode_jwt_unverified(token: str) -> dict | None:
    """Best-effort decode of a JWT header+payload (no signature verification)."""
    import base64 as _b64
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        def _seg(s: str) -> bytes:
            s += "=" * (-len(s) % 4)
            return _b64.urlsafe_b64decode(s.encode())
        header = json.loads(_seg(parts[0]))
        payload = json.loads(_seg(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"header": header, "payload": payload}



def _jwt_finding_detail(value: str, default_sev: str) -> tuple[str, str]:
    """Re-grade a discovered JWT based on its actual claims/header to cut down
    on noise — most client-side JWTs are normal session tokens, not 'secrets'."""
    dec = _decode_jwt_unverified(value)
    if not dec:
        return default_sev, ""
    header, payload = dec["header"], dec["payload"]
    alg = str(header.get("alg", "")).lower()
    notes: list[str] = []
    severity = "low"

    if alg in ("none", ""):
        severity = "high"
        notes.append("alg=none — signature not verifiable/forgeable")

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        if exp < time.time():
            notes.append("expired token (likely stale/example, low risk)")
        else:
            notes.append("active token, has expiry")
    else:
        severity = "medium" if severity == "low" else severity
        notes.append("no 'exp' claim — token may never expire")

    sensitive = [k for k in ("password", "secret", "client_secret", "private_key") if k in payload]
    if sensitive:
        severity = "high"
        notes.append(f"payload exposes sensitive field(s): {', '.join(sensitive)}")

    auth_claims = [k for k in ("role", "roles", "admin", "isAdmin", "scope", "scopes", "permissions") if k in payload]
    if auth_claims:
        if severity == "low":
            severity = "medium"
        notes.append(f"authorization claims in payload: {', '.join(auth_claims)} — verify server re-checks them")

    return severity, "; ".join(notes)



def _validate_secret(stype: str, value: str) -> bool:
    """Return False if the value is clearly a placeholder/false positive."""
    if not value or len(value) < 6:
        return False
    low = value.lower()
    # Generic placeholders
    _FP = {"your_key_here","your-api-key","api_key_here","insert_key","placeholder",
           "replace_me","changeme","change_me","example","sample","test","demo",
           "xxxxxxxx","00000000","11111111","12345678","abcdefgh","aaaaaaaa",
           "none","null","undefined","false","true","n/a","na","todo",
           "secret_here","token_here","<your","[your","{{","__placeholder__"}
    if any(fp in low for fp in _FP):
        return False
    # Format-specific validation
    import re as _vre
    if stype == "aws_access_key" and not _vre.match(r'^AKIA[0-9A-Z]{16}$', value):
        return False
    if stype == "github_token" and not value.startswith("ghp_"):
        return False
    if stype == "stripe_live_key" and not value.startswith("sk_live_"):
        return False
    if stype == "stripe_test_key" and not value.startswith("sk_test_"):
        return False
    if stype == "sendgrid_key" and not _vre.match(r'^SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}$', value):
        return False
    if stype == "jwt_token":
        parts = value.split(".")
        if len(parts) != 3 or not all(len(p) > 4 for p in parts):
            return False
        # Must decode to a real JWT header+payload, not just a base64-looking string
        if not _decode_jwt_unverified(value):
            return False
    # Entropy check for generic keys: must have mixed chars
    if stype in ("api_key","secret_key","access_token","password"):
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        if not (has_upper or has_lower) or not has_digit:
            return False
        # All same char = placeholder
        if len(set(value)) < 4:
            return False
    return True



# Third-party CDN / library hosts whose JS is public and never contains real secrets.
# Matching is exact host or subdomain suffix via _js_host_is_noise.
_JS_NOISE_HOSTS = frozenset({
    "aadcdn.msauth.net", "aadcdn.msftauth.net", "msauth.net", "msftauth.net",
    "js.live.net", "logincdn.msauth.net",
    "oktacdn.com", "okta.com", "auth0.com",
    "fontawesome.com",
    "jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "googleapis.com", "gstatic.com", "google.com", "google-analytics.com",
    "googletagmanager.com", "recaptcha.net", "doubleclick.net",
    "googlesyndication.com",
    "hotjar.com", "segment.com", "segment.io",
    "intercomcdn.com", "intercom.io",
    "newrelic.com", "sentry-cdn.com", "ravenjs.com",
    "facebook.net", "facebook.com", "twitter.com", "licdn.com", "linkedin.com",
    "zendesk.com",
    "clarity.ms", "securiti.ai",
    "cookiebot.com", "onetrust.com", "cookielaw.org",
    "cloudflareinsights.com",
})

_JS_WAF_HOSTS = frozenset({
    "imperva.com", "incapsula.com", "reblaze.com", "datadome.co",
})



def _js_host_is_noise(host: str) -> bool:
    """True when the JS is served from a public CDN/WAF/analytics host."""
    h = (host or "").lower().rstrip(".")
    if not h:
        return False
    for n in _JS_NOISE_HOSTS | _JS_WAF_HOSTS:
        if h == n or h.endswith("." + n):
            return True
    return False



_JS_PATH_MIME_RE = re.compile(
    r"^(text|application|image|audio|video|font|multipart)/[a-z0-9.+-]+$", re.I
)

_JS_PATH_DATE_RE = re.compile(
    r"^(?:MM|dd|yyyy|yy|HH|mm|ss|\d{2,4}|9{2,4})[/\-.](?:MM|dd|yyyy|yy|HH|mm|ss|\d{2,4}|9{2,4})",
    re.I,
)

_JS_PATH_TZ_RE = re.compile(r"^[A-Z][a-zA-Z]+/[A-Z][a-zA-Z_]+$")

_JS_PATH_SDK_RE = re.compile(
    r"^(firebase|react|rxjs|vue|angular|@angular|@babel|core-js|lodash)/"
)



def _js_path_is_noise(path: str) -> bool:
    """True for webpack imports, MIME types, date masks — not live HTTP endpoints."""
    s = (path or "").strip()
    if not s:
        return True
    if s.startswith(("http://", "https://")) or (s.startswith("//") and len(s) > 3 and s[2] != "/"):
        return False
    if s.startswith("/") and not s.startswith("//"):
        return False
    if _JS_PATH_MIME_RE.match(s):
        return True
    if _JS_PATH_DATE_RE.match(s):
        return True
    if _JS_PATH_TZ_RE.match(s):
        return True
    if "__bundle__" in s:
        return True
    if _JS_PATH_SDK_RE.match(s):
        return True
    if s.startswith(("./", "../", "..")) or "/../" in s or "/./" in s:
        return True
    return False



def _analyze_js_content(js_url: str, content: str) -> dict:
    """Analyze JS content and return per-file findings."""
    host = ""
    try:
        from urllib.parse import urlparse
        host = urlparse(js_url).hostname or ""
    except Exception:
        _log.debug('recon.py:5219 erro ignorado', exc_info=True)

    # Skip well-known third-party library hosts — they never contain real secrets
    if _js_host_is_noise(host):
        return {"secrets": [], "endpoints": [], "urls": [], "interesting": []}

    secrets  = []
    seen_sec = set()
    for pattern, ptype, sev in _JS_SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            val = m.group(0)[:200]
            if _is_fp_secret(ptype, val):
                continue
            if not _validate_secret(ptype, val):
                continue
            key = (ptype, val[:60])
            if key not in seen_sec:
                seen_sec.add(key)
                item_sev = sev
                # Get surrounding context (1 line)
                start = max(0, m.start() - 80)
                end   = min(len(content), m.end() + 40)
                ctx   = content[start:end].replace("\n", " ").replace("\r", "").strip()[:200]
                if ptype in ("jwt_token", "jwt_bearer"):
                    jwt_val = val.split()[-1] if ptype == "jwt_bearer" else val
                    item_sev, note = _jwt_finding_detail(jwt_val, item_sev)
                    if note:
                        ctx = f"{ctx} | {note}"
                if ptype == "google_api_key" and re.search(
                    r"initializeApp|firebaseio|maps/api|maps/embed|googleMapsApiKey|authDomain",
                    ctx, re.I,
                ):
                    item_sev = "medium"
                    ctx = f"{ctx} | client-side Firebase/Maps key (often referrer-restricted)"
                secrets.append({"type": ptype, "value": val, "context": ctx, "severity": item_sev})

    secret_types = {s["type"] for s in secrets}
    if "client_id" in secret_types and "client_secret" in secret_types:
        for s in secrets:
            if s["type"] in ("client_id", "client_secret", "consumer_key", "consumer_secret"):
                s["severity"] = "critical"
                s["note"] = "API gateway credential pair (client_id + client_secret co-located)"

    # Endpoints / paths
    endpoints = []
    seen_ep   = set()
    for m in _ENDPOINT_RE.finditer(content):
        path = m.group(1)
        if path in seen_ep or len(path) < 4:
            continue
        # Filter out obvious non-endpoints
        if re.search(r'\.(png|jpg|gif|svg|ico|woff|ttf|eot|css|less|scss)$', path, re.I):
            continue
        if not re.search(r'[/?]', path):
            continue
        if _js_path_is_noise(path):
            continue
        seen_ep.add(path)
        # Classify by type
        kind = "api" if re.search(r'/api/|/v\d+/|/graphql|/rest/', path, re.I) else \
               "admin" if re.search(r'/admin|/manage|/internal|/debug|/config', path, re.I) else \
               "path"
        # Classify auth: look at surrounding context in content for auth signals
        ep_start = max(0, content.find(path) - 300)
        ep_end   = min(len(content), content.find(path) + 300)
        ctx      = content[ep_start:ep_end].lower() if content.find(path) >= 0 else ""
        if re.search(r'bearer\s+|authorization.*bearer|authheader.*bearer', ctx, re.I):
            auth = "bearer"
        elif re.search(r'x-api-key|apikey.*header|api.key.*header', ctx, re.I):
            auth = "api_key_header"
        elif re.search(r'basic\s+auth|authorization.*basic', ctx, re.I):
            auth = "basic"
        elif re.search(r'oauth|client_id.*client_secret', ctx, re.I):
            auth = "oauth2"
        elif re.search(r'cookie|session|csrf', ctx, re.I):
            auth = "cookie_session"
        elif not re.search(r'auth|token|key|secret|credential|login', ctx, re.I):
            auth = "none_detected"
        else:
            auth = "unknown"
        endpoints.append({"path": path, "kind": kind, "auth": auth})

    # Absolute URLs found in code
    urls = []
    seen_url = set()
    for m in re.finditer(r'https?://[a-zA-Z0-9._\-/?=&%#+@:,;[\]~!*\'()\-]{10,300}', content):
        u = m.group(0).rstrip('.,;)\'"')
        if u not in seen_url:
            seen_url.add(u)
            urls.append(u)

    # Interesting patterns
    interesting = []
    seen_int    = set()
    for rgx, label in _INTERESTING_RE:
        if rgx.search(content) and label not in seen_int:
            seen_int.add(label)
            interesting.append(label)

    return {
        "secrets":     secrets,
        "endpoints":   endpoints[:300],
        "urls":        urls[:200],
        "interesting": interesting,
    }



def _analyze_source_map(map_url: str, data: dict) -> dict:
    """Run secret/endpoint analysis on a webpack/vite source map's original sources."""
    empty = {"secrets": [], "endpoints": [], "urls": [], "interesting": []}
    chunks = data.get("sourcesContent") if isinstance(data, dict) else None
    if not isinstance(chunks, list):
        return empty
    parts: list[str] = []
    total = 0
    for c in chunks:
        if not isinstance(c, str) or len(c) < 40:
            continue
        parts.append(c)
        total += len(c)
        if total >= 800_000:
            break
    if not parts:
        return empty
    return _analyze_js_content(map_url, "\n".join(parts)[:800_000])



def _playwright_js_capture(targets: list, timeout: int = 30) -> dict:
    """
    Use Playwright headless Chromium to capture runtime JS URLs and XHR/fetch
    network calls for each target.  Targets are processed in parallel — each
    worker thread owns its own browser instance so Playwright's sync API is
    thread-safe.

    Returns:
        {
            "runtime_js_urls": [str],
            "network_map": {"https://host": [{"method","url","type"}]},
            "error": str | None,
        }
    """
    result: dict = {"runtime_js_urls": [], "network_map": {}, "error": None}
    if not targets:
        return result

    try:
        sync_playwright, PwTimeout = _pw_import()
    except Exception as e:
        result["error"] = f"playwright unavailable: {e}"
        return result

    # WAF bot-challenge fingerprints
    _IMPERVA_RE   = re.compile(r'\?d=[\w.\-]+\.[a-z]{2,}$')
    _RANDOM_PATH_RE = re.compile(r'^/(?:[A-Z][a-z]+-){4,}')

    def _is_bot_challenge(url: str) -> bool:
        if _IMPERVA_RE.search(url):
            return True
        try:
            from urllib.parse import urlparse
            if _RANDOM_PATH_RE.match(urlparse(url).path):
                return True
        except Exception:
            _log.debug('recon.py:5382 erro ignorado', exc_info=True)
        return False

    _BROWSER_ARGS = [
        "--no-sandbox", "--disable-dev-shm-usage",
        "--ignore-certificate-errors", "--disable-web-security",
        "--disable-blink-features=AutomationControlled",
        "--disable-features=IsolateOrigins,site-per-process",
        "--disable-site-isolation-trials",
    ]
    _CONTEXT_KWARGS = dict(
        ignore_https_errors=True,
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        viewport={"width": 1366, "height": 768},
        locale="pt-BR",
        timezone_id="America/Sao_Paulo",
        extra_http_headers={
            "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
    )
    _INIT_SCRIPT = (
        "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
        "Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3,4,5]});"
        "Object.defineProperty(navigator,'languages',{get:()=>['pt-BR','pt','en-US','en']});"
    )

    def _visit_one(target_url: str):
        """Visit a single URL in its own browser instance; return (js_set, calls_list, js_bodies)."""
        host_calls: list = []
        host_js:    set  = set()
        js_bodies:  dict = {}  # url -> text content fetched via browser (bypasses WAF)
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, args=_BROWSER_ARGS)
                context = browser.new_context(**_CONTEXT_KWARGS)
                context.add_init_script(_INIT_SCRIPT)
                page = context.new_page()

                def _on_request(req):
                    rt = req.resource_type
                    u  = req.url
                    if rt in ("xhr", "fetch"):
                        if not _is_bot_challenge(u):
                            host_calls.append({"method": req.method, "url": u, "type": rt})
                    elif rt == "script":
                        if u.endswith(".js") or ".js?" in u or ".js#" in u:
                            host_js.add(u)

                def _on_response(resp):
                    try:
                        if resp.request.resource_type == "script" and resp.status == 200:
                            u = resp.url
                            if u.endswith(".js") or ".js?" in u or ".js#" in u:
                                host_js.add(u)
                    except Exception:
                        _log.debug('recon.py:5444 erro ignorado', exc_info=True)

                page.on("request",  _on_request)
                page.on("response", _on_response)

                timeout_ms = timeout * 1000
                try:
                    page.goto(target_url, wait_until="networkidle", timeout=timeout_ms)
                except PwTimeout:
                    try:
                        page.goto(target_url, wait_until="domcontentloaded", timeout=15_000)
                    except Exception:
                        _log.debug('recon.py:5456 erro ignorado', exc_info=True)
                except Exception:
                    _log.debug('recon.py:5458 erro ignorado', exc_info=True)

                # Scroll to trigger lazy-loaded chunks / infinite-scroll XHR
                try:
                    page.evaluate(
                        "(function(){"
                        "var h=document.body.scrollHeight;"
                        "window.scrollTo(0,h/3);"
                        "setTimeout(function(){window.scrollTo(0,h*2/3);},500);"
                        "setTimeout(function(){window.scrollTo(0,h);},1000);"
                        "})()"
                    )
                    page.wait_for_timeout(1500)
                except Exception:
                    _log.debug('recon.py:5472 erro ignorado', exc_info=True)

                # Collect webpack chunk URLs from JS globals
                try:
                    chunk_urls = page.evaluate(
                        "(function(){"
                        "try{"
                        "var urls=[];"
                        "var pb=window.__webpack_public_path__||window.__publicPath__||'';"
                        "var chunks=window.webpackChunk||[];"
                        "chunks.forEach(function(c){"
                        "  if(c&&c[1])Object.keys(c[1]).forEach(function(k){"
                        "    urls.push(pb+k+'.js');"
                        "  });"
                        "});"
                        "return urls.slice(0,50)"
                        "}catch(e){return []}"
                        "})()"
                    )
                    if isinstance(chunk_urls, list):
                        for u in chunk_urls:
                            if isinstance(u, str) and u.startswith("http"):
                                host_js.add(u)
                except Exception:
                    _log.debug('recon.py:5496 erro ignorado', exc_info=True)

                # Fetch JS bodies via the browser's own fetch() — bypasses WAF/Imperva
                # because the request originates from the already-authenticated browser session.
                # Cap at 25 files; skip noise/CDN hosts; limit to 1.5MB per file.
                from urllib.parse import urlparse as _pw_parse
                candidate_urls = []
                for u in list(host_js):
                    if _is_bot_challenge(u):
                        continue
                    try:
                        if _js_host_is_noise(_pw_parse(u).hostname or ""):
                            continue
                    except Exception:
                        continue
                    candidate_urls.append(u)
                    if len(candidate_urls) >= 25:
                        break

                for js_url in candidate_urls:
                    try:
                        body = page.evaluate(
                            """async (url) => {
                                try {
                                    const r = await fetch(url, {
                                        credentials: 'include',
                                        cache: 'no-store',
                                    });
                                    if (!r.ok) return null;
                                    const t = await r.text();
                                    if (!t || t.length < 200) return null;
                                    return t.length > 1500000 ? t.slice(0, 1500000) : t;
                                } catch(e) { return null; }
                            }""",
                            js_url,
                        )
                        if body and isinstance(body, str):
                            js_bodies[js_url] = body
                    except Exception:
                        _log.debug('recon.py:5535 erro ignorado', exc_info=True)

                page.close()
                browser.close()
        except Exception:
            _log.debug('recon.py:5540 erro ignorado', exc_info=True)
        return host_js, host_calls[:200], js_bodies

    # Run all targets in parallel — cap workers so we don't OOM the box
    max_workers = min(len(targets), 3)   # cada visita abre um navegador; 8 juntos levavam o load acima de 20
    runtime_js:       set  = set()
    network_map:      dict = {}
    playwright_bodies: dict = {}  # url -> JS text body captured via browser fetch
    errors: list = []

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = {pool.submit(_visit_one, url): url for url in targets}
            for fut in as_completed(futs):
                url = futs[fut]
                try:
                    js_set, calls, bodies = fut.result()
                    runtime_js.update(js_set)
                    network_map[url] = calls
                    playwright_bodies.update(bodies)
                except Exception as e:
                    errors.append(f"{url}: {e}")
    except Exception as e:
        result["error"] = str(e)

    result["runtime_js_urls"]      = list(runtime_js)
    result["network_map"]          = network_map
    result["playwright_js_bodies"] = playwright_bodies
    if errors:
        result["error"] = "; ".join(errors[:5])
    return result



JS_RECON_BUDGET_S = 330.0     # abaixo dos 360s do módulo js no pipeline
DISCOVERY_BUDGET_S = 120.0    # katana/subjs/getJS/gau em paralelo


def run_js_recon(domains: list, hosts: list) -> dict:
    """
    Discover all JS files across live hosts (katana + subjs + getJS + gau),
    capture runtime JS via Playwright, run LinkFinder endpoint extraction,
    then analyze each file for secrets, endpoints, URLs, and dangerous patterns.
    Returns per-file structured results.
    """
    import shutil, tempfile

    katana_bin = shutil.which("katana")
    subjs_bin  = shutil.which("subjs")
    getjs_bin  = shutil.which("getJS")
    gau_bin    = shutil.which("gau")

    # Build target list — prefer HTTPS, fall back to HTTP, include all live hosts
    targets = []
    seen_hosts: set = set()
    for h in hosts:
        host  = h.get("host", "")
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        ports = h.get("ports", [])
        has_https = any(int(p["port"] if isinstance(p, dict) else p) in (443, 8443) for p in ports)
        has_http  = any(int(p["port"] if isinstance(p, dict) else p) in (80, 8080, 8000) for p in ports)
        if has_https:
            targets.append(f"https://{host}")
        elif has_http:
            targets.append(f"http://{host}")
        elif h.get("status_code") is not None:
            targets.append(f"https://{host}")  # httpx-confirmed live, assume HTTPS
        if len(targets) >= 500:
            break
    if not targets:
        for d in domains[:5]:
            targets.append(f"https://{d}")

    raw_js_urls: set = set()
    # Prazo único do módulo (o pipeline corta em 360s). Antes as etapas somavam até
    # ~12 min de limites em série (katana 300 + subjs 150 + getJS 90 + gau 3×60 + navegador + análise).
    deadline = time.monotonic() + JS_RECON_BUDGET_S

    def _left(reserve: float = 0.0) -> float:
        return max(5.0, deadline - time.monotonic() - reserve)

    # ── Discovery Phase ── (ferramentas independentes: em paralelo, o tempo é o da mais lenta)
    disc_budget = min(DISCOVERY_BUDGET_S, _left(reserve=150))

    def _katana():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(targets)); tf_path = tf.name
        try:
            r = _subp(
                [katana_bin, "-list", tf_path, "-d", "5", "-jc",
                 "-ef", "png,jpg,gif,css,svg,ico,woff,ttf,webp",
                 "-silent", "-timeout", "15", "-c", "25", "-rl", "50",
                 "-ct", f"{int(disc_budget * 0.6)}s"],
                capture_output=True, text=True, timeout=disc_budget,
            )
        finally:
            Path(tf_path).unlink(missing_ok=True)
        return [u.strip() for u in r.stdout.splitlines()
                if u.strip() and (u.strip().endswith(".js") or ".js?" in u or ".js#" in u)]

    def _subjs():
        r = _subp([subjs_bin, "-c", "30"], input="\n".join(targets),
                  capture_output=True, text=True, timeout=min(150, disc_budget))
        return [u.strip() for u in r.stdout.splitlines() if u.strip()]

    def _getjs():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(targets)); tf_path = tf.name
        try:
            r = _subp([getjs_bin, "-input", tf_path, "-complete"],
                      capture_output=True, text=True, timeout=min(90, disc_budget))
        finally:
            Path(tf_path).unlink(missing_ok=True)
        return [u.strip() for u in r.stdout.splitlines() if u.strip() and "http" in u]

    def _gau():
        urls = []
        for d in domains[:3]:
            r = _subp(
                [gau_bin, "--subs", "--providers", "wayback,otx,commoncrawl",
                 "--ft", "ttf,woff,css,png,jpg,gif,svg,ico", d],
                capture_output=True, text=True, timeout=min(60, disc_budget / 3),
            )
            urls += [u.strip() for u in r.stdout.splitlines()
                     if u.strip() and (u.strip().endswith(".js") or ".js?" in u)]
        return urls

    jobs = [fn for fn, ok in ((_katana, katana_bin and targets), (_subjs, subjs_bin and targets),
                              (_getjs, getjs_bin and targets), (_gau, gau_bin and domains)) if ok]
    if jobs:
        cancel = current_cancel()

        def _run(fn):
            bind_cancel(cancel)   # para junto com o módulo
            return fn()

        ex = ThreadPoolExecutor(max_workers=len(jobs), thread_name_prefix="js-disc")
        futs = {ex.submit(_run, fn): fn.__name__ for fn in jobs}
        try:
            for fut in as_completed(futs, timeout=disc_budget + 2):
                try:
                    raw_js_urls.update(fut.result())
                except Exception:
                    _log.debug("js discovery %s falhou", futs[fut], exc_info=True)
        except TimeoutError:
            _log.info("js discovery: prazo de %.0fs — seguindo com o que veio", disc_budget)
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

    # ── Playwright Runtime Capture ──
    # Visit all live hosts that are likely frontend web apps.
    # Exclude: pure API gateways, hosts with error/redirect-only titles.
    _API_HOST_RE = re.compile(
        r'^(?:apis?[-.]|api-gw|gateway[-.]|gw[-.]|backend[-.]|mtls[-.])',
        re.I,
    )
    # Titles that indicate the host is NOT a real web app
    _BAD_TITLE_RE = re.compile(
        r'^(?:\d{3}\s|fastly error|bad request|forbidden|not found|'
        r'service unavailable|error|redirecting|nginx)',
        re.I,
    )

    def _pw_score(h: dict) -> int:
        """Score a host for Playwright priority. Higher = better candidate."""
        host = h.get("host", "")
        sc   = h.get("status_code") or 0
        title = h.get("title") or ""

        if _API_HOST_RE.match(host):
            return -1  # exclude API gateways
        if sc in (403, 404, 503, 500, 0):
            return 0   # likely not serving a UI
        score = 1
        if sc in (200, 301, 302):
            score += 2
        if title and not _BAD_TITLE_RE.match(title):
            score += 3  # real application title
        # Prefer hosts with 443 open
        ports = [int(p["port"] if isinstance(p, dict) else p) for p in h.get("ports", [])]
        if 443 in ports or 8443 in ports:
            score += 1
        return score

    def _pw_url(h: dict) -> str:
        ports = [int(p["port"] if isinstance(p, dict) else p) for p in h.get("ports", [])]
        if 443 in ports or 8443 in ports:
            return f"https://{h['host']}"
        return f"http://{h['host']}"

    scored = sorted(
        [(h, _pw_score(h)) for h in hosts if h.get("host")],
        key=lambda x: -x[1],
    )
    pw_targets = [_pw_url(h) for h, score in scored if score > 0][:15]   # antes 30: cabe no prazo do módulo
    if not pw_targets:
        pw_targets = targets[:15]

    if _left(reserve=60) > 30:
        from utils.tool_gate import gate_for
        # um módulo de navegador por vez na máquina; se a vaga não vier a tempo, segue sem navegador
        with gate_for("playwright").try_slot(timeout=_left(reserve=120)) as got:
            if got:
                pw_result = _playwright_js_capture(pw_targets, timeout=25)
            else:
                _log.info("js: vaga do navegador ocupada até o prazo — seguindo sem captura de navegador")
                pw_result = {}
    else:
        _log.info("js: sem tempo para a captura no navegador — seguindo para a análise")
        pw_result = {}
    runtime_network_map  = pw_result.get("network_map", {})
    playwright_js_bodies = pw_result.get("playwright_js_bodies", {})
    for u in pw_result.get("runtime_js_urls", []):
        raw_js_urls.add(u)

    # Filter out WAF bot-challenge URLs before analysis
    js_url_list = [u for u in raw_js_urls if not _WAF_CHALLENGE_URL_RE.search(u)]

    # ── Analysis Phase ──
    js_files = []
    total_secrets   = 0
    total_endpoints = 0
    sev_counts      = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    stats           = {"noise": 0, "fail": 0}


    def _accept_js_file(result: dict) -> None:
        nonlocal total_secrets, total_endpoints
        js_files.append(result)
        total_secrets   += len(result.get("secrets") or [])
        total_endpoints += len(result.get("endpoints") or [])
        for s in result.get("secrets") or []:
            sev = s.get("severity", "low")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

    def _fetch_and_analyze(url: str) -> dict | None:
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
            if _js_host_is_noise(host):
                stats["noise"] += 1
                return None
            status, raw, hdrs = http_get(url, timeout=8, retries=1)
            if status != 200 or not raw:
                stats["fail"] += 1
                return None
            size    = len(raw)
            content = raw[:800_000].decode("utf-8", errors="ignore")
            analysis = _analyze_js_content(url, content)
            return {
                "url":         url,
                "host":        host,
                "size":        size,
                "status":      status,
                "secrets":     analysis["secrets"],
                "endpoints":   analysis["endpoints"],
                "urls":        analysis["urls"],
                "interesting": analysis["interesting"],
            }
        except Exception:
            stats["fail"] += 1
            return None

    # Cap at 200 files; prioritise first-party domains over third-party CDNs
    _domain_keywords = [d.split(".")[-2] for d in domains if "." in d] or []
    def _js_priority(u: str) -> int:
        return 0 if any(kw in u for kw in _domain_keywords) else 1
    def _is_first_party_host(host: str) -> bool:
        h = (host or "").lower()
        return any(kw and kw in h for kw in _domain_keywords)

    capped_list = sorted(js_url_list, key=_js_priority)[:200]

    # Sem "with": a saída do with espera todas as threads, e o teto não cortava nada.
    cancel = current_cancel()

    def _fetch(u):
        bind_cancel(cancel)
        return _fetch_and_analyze(u)

    ex = ThreadPoolExecutor(max_workers=8, thread_name_prefix="js-fetch")
    futures = {ex.submit(_fetch, u): u for u in capped_list}
    try:
        for fut in as_completed(futures, timeout=_left(reserve=10)):
            try:
                result = fut.result()
            except Exception:
                _log.debug("js fetch falhou", exc_info=True)
                continue
            if result:
                _accept_js_file(result)
    except TimeoutError:
        _log.info("js: prazo da análise — %s de %s arquivos analisados", sum(f.done() for f in futures), len(futures))
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

    # Playwright-captured JS bodies (browser fetch bypasses WAF that blocks direct HTTP).
    _seen_pw_urls = {f["url"] for f in js_files}
    for pw_js_url, pw_content in playwright_js_bodies.items():
        if pw_js_url in _seen_pw_urls:
            continue
        try:
            from urllib.parse import urlparse as _urlparse
            pw_host = _urlparse(pw_js_url).hostname or ""
            if _js_host_is_noise(pw_host):
                stats["noise"] += 1
                continue
            analysis = _analyze_js_content(pw_js_url, pw_content[:800_000])
            keep = bool(analysis["secrets"] or analysis["endpoints"] or _is_first_party_host(pw_host))
            if keep:
                _accept_js_file({
                    "url":         pw_js_url,
                    "host":        pw_host,
                    "size":        len(pw_content),
                    "status":      200,
                    "source":      "playwright",
                    "secrets":     analysis["secrets"],
                    "endpoints":   analysis["endpoints"],
                    "urls":        analysis["urls"],
                    "interesting": analysis["interesting"],
                })
                _seen_pw_urls.add(pw_js_url)
        except Exception:
            _log.debug('recon.py:5832 erro ignorado', exc_info=True)

    # Sort: files with critical/high secrets first
    def _sort_key(f):
        sc = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        best = min((sc.get(s["severity"], 3) for s in f["secrets"]), default=9)
        return (best, -len(f["secrets"]))
    js_files.sort(key=_sort_key)

    # Source map discovery — probe .js.map and analyse original sourcesContent
    source_maps = []
    source_map_urls = set()
    for f in list(js_files):
        if f.get("source") == "sourcemap" or _js_host_is_noise(f.get("host") or ""):
            continue
        base_url = f["url"].rstrip("/")
        if base_url.endswith(".map"):
            continue
        map_url = base_url + ".map"
        if map_url in source_map_urls:
            continue
        try:
            sc, raw, _ = http_get(map_url, timeout=4, retries=1)
            if sc == 200 and len(raw) > 100:
                try:
                    data = json.loads(raw.decode("utf-8", "ignore"))
                    if isinstance(data, dict) and "sources" in data:
                        source_maps.append({"url": map_url, "sources_count": len(data.get("sources", [])),
                                            "file": f["url"]})
                        source_map_urls.add(map_url)
                        sm_analysis = _analyze_source_map(map_url, data)
                        if sm_analysis["secrets"] or sm_analysis["endpoints"]:
                            from urllib.parse import urlparse as _sm_parse
                            _accept_js_file({
                                "url":         map_url,
                                "host":        _sm_parse(map_url).hostname or f.get("host") or "",
                                "size":        len(raw),
                                "status":      200,
                                "source":      "sourcemap",
                                "secrets":     sm_analysis["secrets"],
                                "endpoints":   sm_analysis["endpoints"],
                                "urls":        sm_analysis["urls"],
                                "interesting": sm_analysis["interesting"],
                                "sources_count": len(data.get("sources") or []),
                            })
                except Exception:
                    _log.debug('recon.py:5878 erro ignorado', exc_info=True)
        except Exception:
            _log.debug('recon.py:5880 erro ignorado', exc_info=True)

    # Flatten all XHR/fetch calls from Playwright into a deduplicated list
    all_network_calls: list = []
    seen_nc: set = set()
    for calls in runtime_network_map.values():
        for c in calls:
            key = (c["method"], c["url"])
            if key not in seen_nc:
                seen_nc.add(key)
                all_network_calls.append(c)

    return {
        "js_files":           js_files,
        "js_files_found":     len(js_url_list),
        "js_analyzed":        len(js_files),
        "js_skipped_noise":   stats["noise"],
        "js_fetch_failed":    stats["fail"],
        "source_maps":        source_maps,
        "source_maps_count":  len(source_maps),
        "total_secrets":      total_secrets,
        "total_endpoints":    total_endpoints,
        "critical_count":     sev_counts["critical"],
        "high_count":         sev_counts["high"],
        "medium_count":       sev_counts["medium"],
        # Runtime network capture (Playwright)
        "runtime_network":    all_network_calls[:500],  # XHR/fetch observed at runtime
        "runtime_network_map": runtime_network_map,     # keyed by target URL
        "runtime_js_urls":    list(pw_result.get("runtime_js_urls", []))[:500],
        "runtime_js_count":   len(pw_result.get("runtime_js_urls", [])),
        # Legacy flat fields for backward compat
        "secrets_found":      total_secrets,
        "endpoints_found":    total_endpoints,
        "scanned_at":         datetime.now().isoformat(timespec="seconds"),
    }
