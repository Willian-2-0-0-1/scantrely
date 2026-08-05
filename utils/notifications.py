#!/usr/bin/env python3
"""
Unified notification dispatcher.

One agent, one memory, every surface: a single `notify()` call fans out a
scan event (pipeline finished, critical finding found, ...) to every
configured webhook — Telegram, Discord, Slack, WhatsApp, Signal, Email,
CLI (local JSONL feed), or a generic JSON webhook.

Each row from `db.load_webhooks()` is a dict with at least:
    {"id": ..., "type": "telegram|discord|slack|whatsapp|signal|email|cli|generic",
     "url": "...", "chat_id": "...", "events": ["scan_complete", ...], ...extra config}

`extra config` fields (stored in webhooks.config_json) vary by type — see the
per-type send_* functions below for the keys each one reads.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import smtplib
import threading
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

SEVERITY_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪",
}

EVENT_TITLES = {
    "scan_complete":   "✅ Scan finished",
    "scan_error":      "❌ Scan error",
    "critical_finding": "🚨 Critical finding",
    "new_host":        "🆕 New host discovered",
    "new_port":        "🔌 New port",
    "new_tech":        "🔧 Tech stack change",
    "status_change":   "📡 Status change",
    "waf_change":      "🛡 WAF change",
}


# ─── shared helpers ─────────────────────────────────────────────────────────

def _is_public_url(url: str) -> bool:
    """Block SSRF to private/loopback/link-local addresses."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    if not host or not url.startswith(("http://", "https://")):
        return False
    try:
        addr = ipaddress.ip_address(host)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        return host.lower() not in ("localhost",) and not host.lower().endswith(".local")


def _post_json(url: str, body: dict, *, headers: dict | None = None, timeout: int = 10) -> bool:
    if not _is_public_url(url):
        return False
    data = json.dumps({k: v for k, v in body.items() if v is not None}).encode()
    req = Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "ASM-Platform/1.0", **(headers or {})},
        method="POST",
    )
    try:
        urlopen(req, timeout=timeout)
        return True
    except (URLError, Exception):
        return False


def _post_form(url: str, fields: dict, *, headers: dict | None = None, timeout: int = 10) -> bool:
    if not _is_public_url(url):
        return False
    data = urlencode({k: v for k, v in fields.items() if v is not None}).encode()
    req = Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "ASM-Platform/1.0", **(headers or {})},
        method="POST",
    )
    try:
        urlopen(req, timeout=timeout)
        return True
    except (URLError, Exception):
        return False


def format_message(event: str, payload: dict) -> tuple[str, str]:
    """Return (title, body) for an event, suitable for any text-based channel."""
    title = EVENT_TITLES.get(event, f"ASM event: {event}")
    company = payload.get("company_name") or payload.get("company_id") or ""
    if company:
        title = f"{title} — {company}"

    lines: list[str] = []
    for key, value in payload.items():
        if key in ("company_name", "company_id"):
            continue
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value[:10]) + (" ..." if len(value) > 10 else "")
        if isinstance(value, dict):
            value = json.dumps(value, ensure_ascii=False)[:200]
        sev = str(value).lower()
        prefix = SEVERITY_EMOJI.get(sev, "")
        label = key.replace("_", " ").title()
        lines.append(f"{prefix + ' ' if prefix else ''}{label}: {value}")

    return title, "\n".join(lines)


# ─── per-platform senders ───────────────────────────────────────────────────

def send_slack(hook: dict, event: str, payload: dict, **_) -> bool:
    url = hook.get("url", "")
    title, body = format_message(event, payload)
    return _post_json(url, {
        "text": f"*{title}*\n{body}",
    })


def send_discord(hook: dict, event: str, payload: dict, **_) -> bool:
    url = hook.get("url", "")
    title, body = format_message(event, payload)
    return _post_json(url, {
        "embeds": [{
            "title": title,
            "description": body[:4000],
            "timestamp": datetime.now().isoformat(),
            "footer": {"text": "ASM Platform"},
        }]
    })


def send_telegram(hook: dict, event: str, payload: dict, **_) -> bool:
    """hook fields: bot_token (or full url) + chat_id."""
    title, body = format_message(event, payload)
    text = f"<b>{title}</b>\n{body}"
    url = hook.get("url") or ""
    bot_token = hook.get("bot_token", "")
    if not url and bot_token:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    if not url:
        return False
    return _post_json(url, {
        "chat_id": hook.get("chat_id", ""),
        "text": text[:4096],
        "parse_mode": "HTML",
    })


def send_whatsapp(hook: dict, event: str, payload: dict, **_) -> bool:
    """Twilio WhatsApp API. hook fields: account_sid, auth_token, from, to.

    `from`/`to` should be in Twilio's "whatsapp:+1415..." format."""
    title, body = format_message(event, payload)
    text = f"{title}\n{body}"
    sid = hook.get("account_sid", "")
    token = hook.get("auth_token", "")
    sender = hook.get("from", "")
    to = hook.get("to") or hook.get("chat_id", "")
    if not (sid and token and sender and to):
        return False
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    creds = base64.b64encode(f"{sid}:{token}".encode()).decode()
    return _post_form(url, {"From": sender, "To": to, "Body": text[:1500]},
                       headers={"Authorization": f"Basic {creds}"})


def send_signal(hook: dict, event: str, payload: dict, **_) -> bool:
    """signal-cli-rest-api. hook fields: url (base url of the REST API),
    number (registered sender), recipients (list of phone numbers / group ids)."""
    title, body = format_message(event, payload)
    text = f"{title}\n{body}"
    base_url = (hook.get("url") or "").rstrip("/")
    number = hook.get("number", "")
    recipients = hook.get("recipients") or ([hook["chat_id"]] if hook.get("chat_id") else [])
    if not (base_url and number and recipients):
        return False
    return _post_json(f"{base_url}/v2/send", {
        "message": text[:2000],
        "number": number,
        "recipients": recipients,
    })


def send_email(hook: dict, event: str, payload: dict, *, settings: dict | None = None, **_) -> bool:
    """SMTP email. Uses global SMTP settings (smtp_host/port/user/pass) plus
    a per-webhook `to` address (or hook['chat_id'] as a fallback)."""
    settings = settings or {}
    smtp_host = settings.get("smtp_host", "")
    smtp_port = int(settings.get("smtp_port") or 587)
    smtp_user = settings.get("smtp_user", "")
    smtp_pass = settings.get("smtp_pass", "")
    to_addr = hook.get("to") or hook.get("chat_id") or settings.get("alert_email", "")
    if not (smtp_host and to_addr):
        return False

    title, body = format_message(event, payload)
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = f"[ASM] {title}"
    msg["From"] = smtp_user or "asm@localhost"
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            if smtp_user:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return True
    except Exception:
        return False


def send_cli(hook: dict, event: str, payload: dict, *, base_dir: Path | None = None, **_) -> bool:
    """Append a JSON line to a local feed file. CLI tools/agents can `tail -f`
    (or poll) `data/cli_notifications.jsonl` to react to ASM events locally —
    no network call, no credentials needed."""
    base_dir = base_dir or Path(".")
    feed = Path(base_dir) / "data" / "cli_notifications.jsonl"
    try:
        feed.parent.mkdir(parents=True, exist_ok=True)
        entry = {"ts": datetime.now().isoformat(timespec="seconds"), "event": event, **payload}
        with feed.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        return True
    except Exception:
        return False


def send_generic(hook: dict, event: str, payload: dict, **_) -> bool:
    url = hook.get("url", "")
    title, body = format_message(event, payload)
    return _post_json(url, {"event": event, "title": title, "body": body, "data": payload,
                             "ts": datetime.now().isoformat(timespec="seconds")})


DISPATCHERS = {
    "slack":    send_slack,
    "discord":  send_discord,
    "telegram": send_telegram,
    "whatsapp": send_whatsapp,
    "signal":   send_signal,
    "email":    send_email,
    "cli":      send_cli,
    "generic":  send_generic,
}


def dispatch_webhook(hook: dict, event: str, payload: dict, *, settings: dict | None = None,
                      base_dir: Path | None = None) -> bool:
    fn = DISPATCHERS.get(hook.get("type", "generic"), send_generic)
    try:
        return fn(hook, event, payload, settings=settings, base_dir=base_dir)
    except Exception:
        return False


def notify(db, get_settings, base_dir, event: str, payload: dict) -> None:
    """Fire-and-forget: dispatch `event` to every webhook subscribed to it
    (or to every webhook with no `events` filter set), each in its own
    background thread so a slow/unreachable endpoint never blocks the
    pipeline."""
    try:
        hooks = db.load_webhooks()
    except Exception:
        return
    if not hooks:
        return

    settings = None
    try:
        settings = get_settings() if get_settings else None
    except Exception:
        settings = None

    for hook in hooks:
        if hook.get("enabled") is False:
            continue
        subscribed = hook.get("events") or []
        if subscribed and event not in subscribed:
            continue
        threading.Thread(
            target=dispatch_webhook,
            args=(hook, event, payload),
            kwargs={"settings": settings, "base_dir": base_dir},
            daemon=True,
        ).start()
