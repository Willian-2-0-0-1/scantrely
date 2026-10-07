#!/usr/bin/env python3
"""
Alerting engine — scan deltas → alerts → dispatch to webhooks/Slack/email.
"""

from __future__ import annotations

import json
import os
import smtplib
import threading
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path
from urllib.request import Request


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_THRESHOLD = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "medium_and_above": 2,
    "high_and_above": 3,
    "critical_only": 4,
}


def _severity_meets(severity: str, threshold: str) -> bool:
    rank = _SEV_RANK.get((severity or "info").lower(), 0)
    need = _SEV_THRESHOLD.get((threshold or "info").lower(), 0)
    return rank >= need


def _outbound_post(url: str, payload: dict, *, headers: dict | None = None, timeout: int = 10) -> None:
    """JSON POST with per-host circuit breaker. CircuitOpen is swallowed."""
    from utils.circuit_breaker import CircuitOpen, guarded_urlopen

    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = Request(url, data=json.dumps(payload).encode(), headers=hdrs, method="POST")
    try:
        guarded_urlopen(req, timeout=timeout)
    except CircuitOpen:
        return


class AlertEngine:
    """Process scan diffs and dispatch alerts to configured channels."""

    def __init__(self, db, base_dir: Path, get_settings_fn):
        self.db = db
        self.base = base_dir
        self.get_settings = get_settings_fn

    def process_scan_diff(self, company_id: str, diff: dict) -> list[dict]:
        """Given a diff dict (from get_scan_diff), create alerts per active rules."""
        if diff.get("diff") != "ok":
            return []

        rules = self._get_active_rules(company_id)
        alerts = []

        for item in diff.get("new", []):
            alerts.extend(self._fire("new_host", company_id, rules, {
                "host": item.get("host", ""),
                "ip": item.get("ip", ""),
                "ports": item.get("ports", []),
                "status_code": item.get("status_code"),
                "title": item.get("title", ""),
            }))

        for item in diff.get("removed", []):
            alerts.extend(self._fire("new_host", company_id, rules, {
                "host": item.get("host", ""),
                "action": "removed",
            }))

        for item in diff.get("changed", []):
            changes = item.get("changes", {})
            if "status_code" in changes:
                alerts.extend(self._fire("status_change", company_id, rules, {
                    "host": item.get("host", ""),
                    "status_code": changes["status_code"],
                }))
            if "ports" in changes:
                alerts.extend(self._fire("new_port", company_id, rules, {
                    "host": item.get("host", ""),
                    "ports": changes["ports"],
                }))
            if "technologies" in changes:
                alerts.extend(self._fire("new_tech", company_id, rules, {
                    "host": item.get("host", ""),
                    "technologies": changes["technologies"],
                }))
            if "waf" in changes:
                alerts.extend(self._fire("waf_change", company_id, rules, {
                    "host": item.get("host", ""),
                    "waf": changes["waf"],
                }))

        return alerts

    def _get_active_rules(self, company_id: str) -> list[dict]:
        try:
            return self.db.get_alert_rules(company_id)
        except Exception:
            return []

    def _fire(self, rule_type: str, company_id: str, rules: list[dict], data: dict) -> list[dict]:
        """Create alert and dispatch to matching rule channels."""
        matching = [r for r in rules if r.get("rule_type") == rule_type and r.get("enabled")]
        if not matching:
            return []

        host = data.get("host", "unknown")
        alerts_created = []

        for rule in matching:
            title = self._format_title(rule_type, host, data)
            description = self._format_description(rule_type, data)

            severity = "info"
            if rule_type in ("new_host",):
                severity = "low"
            elif rule_type in ("new_port", "status_change", "waf_change"):
                severity = "medium"
            elif rule_type in ("new_tech",):
                severity = "low"
            elif rule_type in ("cve_critical", "supply_chain_critical"):
                severity = "critical"

            if not _severity_meets(severity, rule.get("min_severity") or "info"):
                continue

            alert_id = self.db.create_alert(company_id, rule_type, title, description, severity, data)
            alerts_created.append({
                "id": alert_id, "rule_type": rule_type, "title": title,
                "severity": severity, "channels": rule.get("channels", []),
            })

            # Dispatch to channels (background thread)
            channels = rule.get("channels", [])
            if channels:
                threading.Thread(
                    target=self._dispatch, args=(channels, title, description, severity),
                    daemon=True,
                ).start()

        return alerts_created

    def _format_title(self, rule_type: str, host: str, data: dict) -> str:
        maps = {
            "new_host": f"🆕 New host discovered: {host}",
            "new_port": f"🔌 Port change on {host}",
            "new_tech": f"🔧 Tech stack change on {host}",
            "status_change": f"📡 Status change on {host}",
            "cert_expiring": f"📜 Certificate expiring: {host}",
            "waf_change": f"🛡 WAF change on {host}",
            "cve_critical": f"💥 Critical CVE on {host}",
            "supply_chain_critical": f"📦 Critical JS Lib CVE on {host}",
        }
        return maps.get(rule_type, f"Alert: {host}")

    def _format_description(self, rule_type: str, data: dict) -> str:
        host = data.get("host", "")
        lines = [f"Host: {host}"]

        if rule_type == "new_host":
            lines.append(f"IP: {data.get('ip', '?')}")
            lines.append(f"Ports: {data.get('ports', [])}")
            lines.append(f"Status: {data.get('status_code', '?')}")
            lines.append(f"Title: {data.get('title', '')}")

        elif rule_type == "new_port":
            ports = data.get("ports", {})
            lines.append(f"Before: {ports.get('from', [])}")
            lines.append(f"After: {ports.get('to', [])}")

        elif rule_type == "new_tech":
            techs = data.get("technologies", {})
            lines.append(f"Before: {techs.get('from', [])}")
            lines.append(f"After: {techs.get('to', [])}")

        elif rule_type == "status_change":
            sc = data.get("status_code", {})
            lines.append(f"From {sc.get('from')} → {sc.get('to')}")

        elif rule_type == "waf_change":
            waf = data.get("waf", {})
            lines.append(f"From {waf.get('from')} → {waf.get('to')}")

        return "\n".join(lines)

    def _dispatch(self, channels: list[str], title: str, body: str, severity: str):
        """Send alert to configured channels."""
        settings = self.get_settings() or {}

        for channel in channels:
            try:
                if channel == "slack":
                    self._send_slack(settings, title, body, severity)
                elif channel == "discord":
                    self._send_discord(settings, title, body, severity)
                elif channel == "email":
                    self._send_email(settings, title, body)
                elif channel == "webhook":
                    webhook_url = settings.get("alert_webhook_url", "")
                    if webhook_url:
                        self._send_webhook(webhook_url, title, body, severity)
                elif channel == "jira":
                    self._send_jira(settings, title, body, severity)
                elif channel == "linear":
                    self._send_linear(settings, title, body, severity)
            except Exception as e:
                print(f"[alert] Failed to dispatch to {channel}: {e}")

    def _send_slack(self, settings: dict, title: str, body: str, severity: str):
        url = settings.get("slack_webhook_url", "")
        if not url:
            return
        color = {"critical": "#ff0000", "high": "#ff6600", "medium": "#ffcc00",
                 "low": "#36a64f", "info": "#439FE0"}.get(severity, "#439FE0")
        payload = {
            "attachments": [{
                "fallback": title,
                "color": color,
                "title": title,
                "text": body,
                "footer": "ASM Platform",
                "ts": int(datetime.now().timestamp()),
            }]
        }
        _outbound_post(url, payload)

    def _send_discord(self, settings: dict, title: str, body: str, severity: str):
        url = settings.get("discord_webhook_url", "")
        if not url:
            return
        color = {"critical": 0xFF0000, "high": 0xFF6600, "medium": 0xFFCC00,
                 "low": 0x36A64F, "info": 0x439FE0}.get(severity, 0x439FE0)
        payload = {
            "embeds": [{
                "title": title,
                "description": body,
                "color": color,
                "footer": {"text": "ASM Platform"},
                "timestamp": datetime.now().isoformat(),
            }]
        }
        _outbound_post(url, payload)

    def _send_email(self, settings: dict, title: str, body: str):
        smtp_host = settings.get("smtp_host", "")
        smtp_port = int(settings.get("smtp_port", "587"))
        smtp_user = settings.get("smtp_user", "")
        smtp_pass = settings.get("smtp_pass", "")
        alert_email = settings.get("alert_email", "")
        if not smtp_host or not alert_email:
            return

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = f"[ASM] {title}"
        msg["From"] = smtp_user or "asm@localhost"
        msg["To"] = alert_email

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            if smtp_user:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)

    def _send_webhook(self, url: str, title: str, body: str, severity: str):
        payload = {"title": title, "body": body, "severity": severity, "ts": _now()}
        _outbound_post(url, payload)

    def _send_jira(self, settings: dict, title: str, body: str, severity: str):
        import base64
        jira_url   = settings.get("jira_url", "").rstrip("/")
        project    = settings.get("jira_project", "")
        token      = settings.get("jira_token", "")
        user       = settings.get("jira_user", "")
        if not jira_url or not project or not token:
            return
        priority_map  = {"critical": "Highest", "high": "High", "medium": "Medium",
                         "low": "Low", "info": "Low"}
        issuetype_map = {"critical": "Bug", "high": "Bug", "medium": "Task",
                         "low": "Task", "info": "Task"}
        payload = {
            "fields": {
                "project":     {"key": project},
                "summary":     title[:255],
                "description": {"type": "doc", "version": 1,
                                 "content": [{"type": "paragraph", "content":
                                              [{"type": "text", "text": body}]}]},
                "issuetype":   {"name": issuetype_map.get(severity, "Task")},
                "priority":    {"name": priority_map.get(severity, "Medium")},
            }
        }
        creds = base64.b64encode(f"{user}:{token}".encode()).decode()
        _outbound_post(
            f"{jira_url}/rest/api/3/issue",
            payload,
            headers={"Authorization": f"Basic {creds}"},
        )

    def _send_linear(self, settings: dict, title: str, body: str, severity: str):
        token   = settings.get("linear_token", "")
        team_id = settings.get("linear_team_id", "")
        if not token or not team_id:
            return
        priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 4}
        query = (
            "mutation CreateIssue($title:String!,$teamId:String!,$description:String,$priority:Int){"
            "issueCreate(input:{title:$title,teamId:$teamId,description:$description,priority:$priority})"
            "{success issue{id identifier}}}"
        )
        payload = {
            "query": query,
            "variables": {
                "title":       title[:255],
                "teamId":      team_id,
                "description": body,
                "priority":    priority_map.get(severity, 3),
            },
        }
        _outbound_post(
            "https://api.linear.app/graphql",
            payload,
            headers={"Authorization": token},
        )
