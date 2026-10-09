from core.finding_hygiene import (
    repair_mojibake, tidy_findings, tidy_stored, vhost_findings,
)


def _vh(name, ip="1.1.1.1", status=403, length=23, **kw):
    return {"vhost": name, "ip": ip, "status": status, "length": length, "severity": "low", **kw}


def test_mojibake_repaired_single_and_double():
    once = "â€\x94"              # em dash lido como latin-1/cp1252
    twice = "Ã¢â‚¬â€\x9d"       # dupla codificação (forma real nos dados gravados)
    assert repair_mojibake(f"Missing {once} CSP") == "Missing — CSP"
    assert repair_mojibake(f"Missing {twice} CSP") == "Missing — CSP"
    assert repair_mojibake("sessÃ£o") == "sessão"
    assert repair_mojibake("texto normal — ok") == "texto normal — ok"


def test_identical_vhost_responses_collapse_into_one_info():
    data = {"findings": [_vh(f"a{i}.x.com") for i in range(5)]}
    out = vhost_findings(data)
    assert len(out) == 1
    assert out[0]["severity"] == "info"
    assert len(out[0]["affected_hosts"]) == 5


def test_distinct_vhost_keeps_real_status_and_ip():
    data = {"findings": [_vh("admin.x.com", status=200, length=900),
                         _vh("api.x.com", status=200, length=1200)]}
    out = {f["value"]: f for f in vhost_findings(data)}
    assert out["admin.x.com"]["severity"] == "high"
    assert out["api.x.com"]["severity"] == "medium"
    assert "HTTP 200" in out["api.x.com"]["title"] and "1.1.1.1" in out["api.x.com"]["title"]


def test_forbidden_distinct_vhost_stays_low():
    out = vhost_findings({"findings": [_vh("admin.x.com", length=10), _vh("b.x.com", length=11)]})
    assert {f["severity"] for f in out} == {"low"}


def test_stale_vhost_findings_replaced_by_current_scan():
    old = [{"key": "vhost--old.x.com", "type": "vhost", "severity": "medium", "title": "t", "host": ""}]
    co = {"vhost_data": {"findings": [_vh("new.x.com", status=200, length=5)]}}
    out = tidy_findings(old, co)
    assert [f["value"] for f in out] == ["new.x.com"]


def test_header_findings_grouped_per_header_and_idempotent():
    mk = lambda h: {"key": f"header-missing-{h}-CSP", "type": "header", "severity": "medium",
                    "title": f"Header ausente em {h}: Content-Security-Policy", "host": h, "desc": "d"}
    fs = [mk("a.x.com"), mk("b.x.com"), mk("c.x.com")]
    once = tidy_findings(fs, {})
    assert len(once) == 1 and once[0]["affected_hosts"] == ["a.x.com", "b.x.com", "c.x.com"]
    assert "3 hosts" in once[0]["title"]
    assert tidy_findings(once, {}) == once
    # um host novo entra no mesmo grupo
    again = tidy_findings(once + [mk("d.x.com")], {})
    assert len(again) == 1 and len(again[0]["affected_hosts"]) == 4


def test_single_header_finding_not_grouped():
    f = {"key": "k", "type": "header", "severity": "low", "title": "Header ausente em a.x.com: X-Frame-Options", "host": "a.x.com"}
    assert tidy_findings([f], {}) == [f]


def test_brand_exposure_capped_at_high():
    f = {"key": "t", "type": "brand_domain_exposure", "severity": "critical", "title": "x", "host": "p0rto.com"}
    assert tidy_findings([f], {})[0]["severity"] == "high"


def test_stored_chains_on_non_inventory_hosts_removed_and_stats_updated():
    co = {"id": "c", "hosts": [{"host": "www.x.com"}], "stats": {},
          "findings": [
              {"key": "1", "type": "attack_chain", "severity": "critical", "title": "c1", "host": "typo.com"},
              {"key": "2", "type": "attack_chain", "severity": "critical", "title": "c2", "host": "www.x.com"},
          ]}
    rep = tidy_stored({"companies": [co]})
    assert rep == {"c": (2, 1)}
    assert co["stats"]["findings_critical"] == 1


def test_priorities_rank_and_skip_derived_chains():
    from core.priorities import build_priorities
    co = {"findings": [
        {"key": "a", "type": "attack_chain", "severity": "critical", "host": "x.com", "title": "chain"},
        {"key": "b", "type": "header", "severity": "medium", "host": "x.com", "title": "h"},
        {"key": "c", "type": "git_exposed", "severity": "critical", "host": "dev.x.com", "title": ".git"},
        {"key": "d", "type": "cve", "severity": "high", "host": "y.x.com", "title": "CVE-1", "kev": True},
    ]}
    out = build_priorities(co)
    assert [a["type"] for a in out["actions"]] == ["git_exposed", "cve", "header"]
    assert out["actions"][0]["rank"] == 1 and out["actions"][0]["fix"]
    assert out["hidden"] == 0


def test_priorities_caps_hygiene_types():
    from core.priorities import build_priorities
    co = {"findings": [{"key": "h", "type": "header", "severity": "high", "host": "a", "title": "x"},
                       {"key": "v", "type": "vhost", "severity": "high", "host": "b", "title": "y"}]}
    sev = {a["type"]: a["severity"] for a in build_priorities(co)["actions"]}
    assert sev == {"header": "medium", "vhost": "low"}


def test_repair_deep_fixes_nested_strings():
    from core.finding_hygiene import repair_deep
    bad = "Ã¢â‚¬â€\x9d"
    data = {"a": [{"obs": f"X {bad} y"}], "b": f"k{bad}"}
    assert repair_deep(data) == {"a": [{"obs": "X — y"}], "b": "k—"}


def test_git_exposed_html_is_false_positive_and_audited():
    from core.finding_hygiene import tidy_findings
    spa = {"key": "g1", "type": "git_exposed", "severity": "critical", "host": "a.x.com", "value": "/.git/config",
           "title": ".git exposto em a.x.com/.git/config", "desc": "<!doctype html><html lang=\"en\"><head><base href=\"/\">"}
    real = {"key": "g2", "type": "git_exposed", "severity": "critical", "host": "b.x.com", "value": "/.git/config",
            "title": ".git exposto", "desc": "[core]\n\trepositoryformatversion = 0"}
    co = {"leaks_data": {"git_exposed": [{"host": "a.x.com", "path": "/.git/config", "snippet": spa["desc"]},
                                         {"host": "b.x.com", "path": "/.git/config", "snippet": real["desc"]}]}}
    out = tidy_findings([spa, real], co)
    assert [f["key"] for f in out] == ["g2"]
    assert co["auto_dismissed"][0]["key"] == "g1" and "HTML" in co["auto_dismissed"][0]["reason"]
    assert [g["host"] for g in co["leaks_data"]["git_exposed"]] == ["b.x.com"]
    assert tidy_findings([spa], co) == [] and len(co["auto_dismissed"]) == 1   # idempotente, sem duplicar


def test_verification_helpers():
    from core.verification import classify_live, looks_like_git, looks_like_sensitive_file
    assert not looks_like_git("/.git/config", b"<!DOCTYPE html><html>")
    assert looks_like_git("/.git/HEAD", b"ref: refs/heads/main\n")
    assert classify_live("/.git/config", 403, b"Forbidden") == {"live_status": 403, "verified": False}
    assert classify_live("/.env", 200, b"DB_PASSWORD=x\n")["verified"] is True
    assert not looks_like_sensitive_file("/backup.sql", b"<html><body>Not found</body></html>")


def test_check_exposed_git_requires_git_content(monkeypatch):
    from core.reconlib import leaks
    pages = {"https://spa.x.com/.git/config": (200, b"<!doctype html><html></html>", {}),
             "https://spa.x.com/.git/HEAD": (200, b"<html>", {}),
             "https://real.x.com/.git/config": (200, b"[core]\n\trepositoryformatversion = 0\n", {})}
    monkeypatch.setattr(leaks, "http_get", lambda url, **k: pages.get(url, (404, b"", {})))
    out = leaks.check_exposed_git([{"host": "spa.x.com", "ports": ["443"]}, {"host": "real.x.com", "ports": ["443"]}])
    assert [o["host"] for o in out] == ["real.x.com"] and out[0]["verified"] is True


def test_wayback_marks_live_status(monkeypatch):
    from core.reconlib import wayback
    items = [{"url": "https://a.x.com/.git/config", "path": "/.git/config"}, {"url": "https://a.x.com/about", "path": "/about"}]
    monkeypatch.setattr(wayback, "http_get", lambda url, **k: (403, b"Forbidden", {}))
    wayback._verify_live(items)
    assert items[0]["live_status"] == 403 and items[0]["verified"] is False
    assert "live_status" not in items[1]   # caminho comum não é sondado


# ── ciclo de vida: visto / não visto / resolvido ────────────────────────────
def _hf(key, module="headers", **kw):
    return {"key": key, "module": module, "type": "header", "severity": "medium", "title": key, "host": "a.x.com", **kw}


def test_lifecycle_split_only_reevaluates_modules_that_ran():
    from core.finding_lifecycle import split_prior
    prior = [_hf("h1"), _hf("c1", module="cors_scan"), _hf("t1", module="typosquat")]
    carry, reeval = split_prior(prior, lambda mod: mod == "headers")
    assert set(reeval) == {"h1"} and {f["key"] for f in carry} == {"c1", "t1"}   # cors não rodou; typosquat não é autoritativo


def test_lifecycle_not_seen_then_resolved_then_seen_again():
    from core.finding_lifecycle import RESOLVE_AFTER, apply_lifecycle, is_active
    old = {"h1": _hf("h1", first_seen="2026-10-01T00:00:00", last_seen="2026-10-05T00:00:00")}
    cur = apply_lifecycle([], old, now="2026-10-09T00:00:00")
    assert cur[0]["status"] == "not_seen" and cur[0]["miss_count"] == 1 and not is_active(cur[0])
    assert cur[0]["last_seen"] == "2026-10-05T00:00:00"          # última vez em que foi visto
    for _ in range(RESOLVE_AFTER - 1):
        cur = apply_lifecycle([], {cur[0]["key"]: cur[0]}, now="2026-10-10T00:00:00")
    assert cur[0]["status"] == "resolved"
    back = apply_lifecycle([_hf("h1")], {"h1": cur[0]}, now="2026-10-11T00:00:00")
    assert back[0].get("status") is None and back[0]["miss_count"] == 0 and back[0]["first_seen"] == "2026-10-01T00:00:00"
    assert is_active(back[0])


def test_inactive_findings_do_not_count_anywhere():
    from core.asset_matrix import compute_aggregates
    from core.finding_groups import build_groups
    from core.finding_hygiene import count_by_severity
    from core.priorities import build_priorities
    fs = [_hf("a", severity="high", host="a.x.com", type="cors"), _hf("b", severity="high", host="a.x.com", type="cors", status="not_seen")]
    assert count_by_severity(fs)["findings_high"] == 1
    assert compute_aggregates({"findings": fs})["a.x.com"]["sev"]["high"] == 1
    assert build_priorities({"findings": fs})["findings_total"] == 1
    assert build_groups(fs)["confirmed_total"] == 1
    st = build_groups(fs, view="stale")
    assert st["confirmed_total"] == 1 and st["stale_total"] == 1 and st["groups"][0]["findings"][0]["key"] == "b"


def test_cors_error_response_is_downgraded(monkeypatch):
    from core.reconlib import cors
    def fake(url, **k):
        origin = (k.get("extra_headers") or {}).get("Origin", "")
        return 403, b"Forbidden", {"access-control-allow-origin": origin, "access-control-allow-credentials": "true"}
    monkeypatch.setattr(cors, "http_get", fake)
    out = cors.run_cors_scan([{"host": "api.x.com", "status_code": 403, "ports": ["443"]}])
    f = out["findings"][0]
    assert f["severity"] == "high" and "HTTP 403" in f["desc"]          # crítico → alto quando a raiz responde 403
    monkeypatch.setattr(cors, "http_get", lambda url, **k: (200, b"ok", {"access-control-allow-origin": (k.get("extra_headers") or {}).get("Origin", ""), "access-control-allow-credentials": "true"}))
    assert cors.run_cors_scan([{"host": "api.x.com", "status_code": 200, "ports": ["443"]}])["findings"][0]["severity"] == "critical"
