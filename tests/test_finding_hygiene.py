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


def test_brand_exposure_capped_at_medium():
    f = {"key": "t", "type": "brand_domain_exposure", "severity": "critical", "title": "x", "host": "p0rto.com"}
    assert tidy_findings([f], {})[0]["severity"] == "medium"


def test_stored_chains_are_recomputed_over_inventory_hosts_only():
    co = {"id": "c", "hosts": [{"host": "www.x.com", "waf": "Direct"}], "stats": {},
          "findings": [
              {"key": "r", "type": "git_exposed", "severity": "critical", "title": "real", "host": "www.x.com", "desc": "[core]\nrepositoryformatversion = 0", "value": "/.git/config"},
              {"key": "1", "type": "attack_chain", "severity": "critical", "title": "c1", "host": "typo.com"},
              {"key": "2", "type": "attack_chain", "severity": "critical", "title": "c2", "host": "outro.x.com"},
          ]}
    rep = tidy_stored({"companies": [co]})
    chains = [f for f in co["findings"] if f["type"] == "attack_chain"]
    assert [c["key"] for c in chains] == ["chain-nowaf-critical-www.x.com"]   # recalculada; as antigas fora do inventário saem
    assert rep == {"c": (3, 2)} and co["stats"]["findings_critical"] == 2


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
    assert f["severity"] == "low" and "HTTP 403" in f["desc"]            # com credenciais seria médio; raiz 403 rebaixa para baixo
    monkeypatch.setattr(cors, "http_get", lambda url, **k: (200, b"ok", {"access-control-allow-origin": (k.get("extra_headers") or {}).get("Origin", ""), "access-control-allow-credentials": "true"}))
    assert cors.run_cors_scan([{"host": "api.x.com", "status_code": 200, "ports": ["443"]}])["findings"][0]["severity"] == "medium"   # CORS nunca passa de médio


def test_cors_is_capped_at_medium_everywhere_and_chains_follow():
    from core.finding_hygiene import derive_attack_chains, tidy_findings, tidy_stored
    cors = {"key": "c1", "type": "cors", "module": "cors_scan", "severity": "critical", "title": "CORS", "host": "api.x.com"}
    assert tidy_findings([cors], {})[0]["severity"] == "medium"
    co = {"id": "c", "hosts": [{"host": "api.x.com", "status_code": 200, "waf": "Direct"}], "stats": {},
          "findings": [dict(cors), {"key": "old", "type": "attack_chain", "severity": "critical", "host": "api.x.com", "title": "Sem WAF + Finding Crítico: api.x.com"}]}
    tidy_stored({"companies": [co]})
    assert [f["severity"] for f in co["findings"] if f["type"] == "cors"] == ["medium"]
    assert not [f for f in co["findings"] if f["type"] == "attack_chain"]          # a cadeia só existia por causa do "crítico"
    assert co["stats"]["findings_critical"] == 0
    assert derive_attack_chains([{"key": "x", "type": "git_exposed", "severity": "critical", "host": "api.x.com", "title": "t"}], co)[0]["key"] == "chain-nowaf-critical-api.x.com"


def test_cve_without_detected_version_is_only_possible():
    from core.finding_hygiene import cap_unversioned_cves, tidy_findings
    co = {"cve_findings": [{"cve_id": "CVE-1", "severity": "critical", "detected_version": None, "score": 9.6},
                           {"cve_id": "CVE-2", "severity": "high", "detected_version": "1.2.3", "score": 8},
                           {"cve_id": "CVE-3", "severity": "high", "detected_version": None, "kev": True}],
          "cve_summary": {"critical": 1, "high": 2, "medium": 0, "low": 0}}
    f1 = {"key": "a", "type": "cve", "value": "CVE-1", "severity": "critical", "title": "CVE-1", "host": "h"}
    f2 = {"key": "b", "type": "cve", "value": "CVE-2", "severity": "high", "title": "CVE-2", "host": "h"}
    out = {f["value"]: f for f in tidy_findings([f1, f2], co)}
    assert out["CVE-1"]["severity"] == "low" and out["CVE-1"]["verified"] is False
    assert out["CVE-2"]["severity"] == "high"                      # versão detectada e dentro da faixa: mantém
    sev = {c["cve_id"]: c["severity"] for c in co["cve_findings"]}
    assert sev == {"CVE-1": "low", "CVE-2": "high", "CVE-3": "medium"}   # KEV sem versão: no máximo médio
    assert co["cve_summary"] == {"critical": 0, "high": 1, "medium": 1, "low": 1}


def test_weak_evidence_types_are_capped():
    from core.finding_hygiene import SEVERITY_CAPS, cap_severity
    assert cap_severity("cors", "critical") == "medium" and cap_severity("cors", "low") == "low"
    assert cap_severity("vendor_fingerprint", "high") == "medium" and cap_severity("waf_bypass", "critical") == "medium"
    assert cap_severity("header", "high") == "medium" and cap_severity("staging_in_csp", "high") == "low"
    assert cap_severity("email_security", "high") == "medium" and cap_severity("brand_domain_exposure", "critical") == "medium"
    assert cap_severity("git_exposed", "critical") == "critical"      # sem teto: exige prova (conteúdo de git)
    assert SEVERITY_CAPS["cors"] == "medium"


def test_public_google_key_is_capped_but_real_secret_is_not():
    from core.finding_hygiene import tidy_findings
    gk = {"key": "s1", "type": "secret", "severity": "high", "title": "Secret exposto: google_api_key em a.x.com", "host": "a.x.com", "metadata": {"secret_type": "google_api_key"}}
    aws = {"key": "s2", "type": "secret", "severity": "critical", "title": "Secret exposto: aws_secret_key em a.x.com", "host": "a.x.com", "metadata": {"secret_type": "aws_secret_key"}}
    out = {f["key"]: f["severity"] for f in tidy_findings([gk, aws], {})}
    assert out == {"s1": "medium", "s2": "critical"}
