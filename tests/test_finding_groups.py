from core.finding_groups import build_groups, hash_id, is_confirmed, normalize_title


def _f(i, sev="high", title=None, host=None, **kw):
    return {"key": f"k{i}", "severity": sev, "title": title or f"Falha {i}", "host": host or f"h{i}.x.com",
            "category": kw.pop("category", "web"), **kw}


def test_noise_and_false_positive_are_not_confirmed():
    assert not is_confirmed(_f(1, title="Typosquat registrado"))
    assert not is_confirmed(_f(2, status="False Positive"))
    assert is_confirmed(_f(3, type="git_exposed", title="phishing kit .git"))   # tipos "sempre confirmados" vencem o ruído


def test_title_normalization_groups_same_issue_across_hosts_and_ports():
    a = normalize_title("CORS em a.x.com:8443 ip 10.0.0.1", "a.x.com")
    b = normalize_title("CORS em b.x.com:8443 ip 10.0.0.2", "b.x.com")
    assert a == "CORS em <HOST>:<PORT> ip <IP>"
    assert a.replace("<HOST>", "h") == b.replace("<HOST>", "h")


def test_hash_matches_front_algorithm():
    # valores calculados pelo _hashId do front (node), incluindo emoji (UTF-16)
    assert hash_id("") == "f00000f80"
    assert hash_id("ab") == "f002d9761"
    assert hash_id("a ✓😀") == "f31fac2c9"


def test_groups_sorted_critical_first_then_by_size_and_paginated():
    fs = [_f(1, "high", "Mesma", "a.x.com"), _f(2, "high", "Mesma", "b.x.com"),
          _f(3, "critical", "Pior"), _f(4, "low", "Leve")]
    out = build_groups(fs, per_page=2)
    assert [g["severity"] for g in out["groups"]] == ["critical", "high"]
    assert out["groups"][1]["count"] == 2
    assert out["total_groups"] == 3 and out["pages"] == 2 and out["total_findings"] == 4
    assert build_groups(fs, per_page=2, page=2)["groups"][0]["severity"] == "low"
    assert out["severity"] == {"critical": 1, "high": 2, "medium": 0, "low": 1}


def test_filters_and_triage():
    fs = [_f(1, "high", "Alfa", category="cors"), _f(2, "low", "Beta", category="headers")]
    assert build_groups(fs, severity="high")["total_groups"] == 1
    assert build_groups(fs, category="headers")["groups"][0]["key"] == "Beta"
    assert build_groups(fs, q="alfa")["total_groups"] == 1
    tmap = {hash_id("Alfa"): {"status": "fixed"}}
    assert build_groups(fs, triage="fixed", triage_map=tmap)["total_groups"] == 1
    assert build_groups(fs, triage="open", triage_map=tmap)["groups"][0]["key"] == "Beta"
    assert build_groups(fs)["categories"] == ["cors", "headers"]
