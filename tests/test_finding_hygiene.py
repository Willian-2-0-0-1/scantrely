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
