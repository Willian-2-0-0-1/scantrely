"""Paridade: a matriz de ativos do servidor (core/asset_matrix.py) == o código antigo do navegador (tests/js/legacy),
executado no node sobre uma empresa sintética que cobre WAF, nuvem, portas, achados, endpoints e secrets."""
import json
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from core import asset_matrix as m

ORACLE = Path(__file__).parent / "js" / "asset_matrix_oracle.js"
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node não instalado")


def synthetic_company(seed=7):
    r = random.Random(seed)
    domains = ["alvo.test", "outro.test"]
    wafs = ["Direct", "", None, "Cloudflare", "AWS WAF", "Imperva Incapsula", "Unknown WAF", "Akamai", "Fortinet", "Google Cloud Armor", "Direct (none)"]
    clouds = ["", "aws", "GCP", "Azure", "oracle", "Cloudflare"]
    techs = ["Nginx", "jQuery", "Cloudflare", "Amazon CloudFront", "Azure", "Google Cloud", "WordPress", "HSTS", "React"]
    hosts = []
    for i in range(36):
        dom = r.choice(domains + ["fora.test"])
        h = {"host": f"{r.choice(['www', 'api', 'dev', 'hml', 'loja'])}{i}.{dom}", "ip": r.choice(["", f"10.0.{i}.1", f"45.1.{i}.9"]),
             "status_code": r.choice([200, 200, 301, 403, 503, 404, 0, None]), "waf": r.choice(wafs),
             "cloud_provider": r.choice(clouds), "title": r.choice(["", "Home", f"Painel {i}"]),
             "technologies": r.sample(techs, r.randint(0, 4)), "ports": r.sample(["80", "443", "22", "3306", "8080", "9200", "2083"], r.randint(0, 4))}
        if r.random() < 0.4:
            h["port_details"] = [{"port": p, "service": r.choice(["", "ssh", "http"]), "category": "x"} for p in h["ports"][:2]]
        if r.random() < 0.15:
            h["risk"] = r.choice(["high", "medium", "low", "critical"])
        if r.random() < 0.3:
            h["screenshot"] = f"{i}.png"
        hosts.append(h)
    names = [h["host"] for h in hosts]
    findings = []
    for i in range(60):
        f = {"key": f"k{i}", "title": f"Achado {i}", "severity": r.choice(["critical", "high", "medium", "low", "info", "High"]),
             "type": r.choice(["cve", "header", "cors", "vhost", "secret"])}
        kind = r.random()
        if kind < 0.5:
            f["host"] = r.choice(names)
        elif kind < 0.7:
            f["url"] = f"https://{r.choice(names)}/p?x=1"
        elif kind < 0.85:
            f["affected_hosts"] = r.sample(names, 3)
            f["host"] = f["affected_hosts"][0]
        else:
            f["domain"] = r.choice(domains)
        findings.append(f)
    js_hosts = r.sample(names, 5)
    co = {
        "id": "syn", "domains": domains, "hosts": hosts, "findings": findings,
        "ct_subdomains": ["ct1.alvo.test", {"host": "ct2.outro.test", "ip": "1.2.3.4"}, "1.2.3.4", names[0]],
        "tech_index": {"Nginx": r.sample(names, 4), "Vue": [names[1], "ghost.alvo.test"]},
        "js_data": {
            "js_files": [{"host": js_hosts[i % 5], "file": f"https://{js_hosts[i % 5]}/a{i}.js", "url": f"https://{js_hosts[i % 5]}/a{i}.js",
                          "endpoints": ["/api/v1/x", {"url": "/api/y", "method": "post"}, "application/json", "../rel", "MM/dd/yyyy", "firebase/app",
                                        "Europe/Paris", "//cdn.test/x", f"https://{names[i]}/full", "/api/v1/x", {"endpoint": "/e"}],
                          "secrets": [{"type": "api_key", "value": "key='SOME_LABEL'"}, {"type": "password", "value": "password='abc123'"},
                                      {"type": "password", "value": "password='forgot_password'"}, {"type": "internal_ip", "value": "10.1.2.3"},
                                      {"type": "internal_ip", "value": "999.1.1.1"}, {"type": "token", "value": f"tok{i}"}, "rawsecret"]}
                         for i in range(5)] + [{"host": "scripts.clarity.ms", "endpoints": ["/z"], "secrets": [{"type": "token", "value": "noise"}]}],
            "runtime_network": [{"url": f"https://{names[2]}/rt", "method": "get"}, f"https://{names[3]}/rt2"],
            "runtime_js_urls": [f"https://{names[4]}/chunk.js", {"url": f"https://{names[5]}/c2.js"}],
        },
        "secrets_findings": [{"type": "secret", "host": names[6], "value": "AIzaXYZ", "metadata": {"secret_type": "google_api_key", "source_url": f"https://{names[6]}/m.js"}},
                             {"type": "jwt", "host": names[7], "value": "eyJ.x.y"}],
        "wayback_data": {"interesting": [f"https://{names[8]}/old", {"url": f"https://{names[9]}/w", "host": names[9]}]},
        "urlfinder_data": {"urls": [f"https://{names[10]}/u", {"url": "/relative", "host": names[11]}]},
        "param_mine_data": {"findings": [{"url": f"https://{names[12]}/p?a=1"}, f"https://{names[13]}/pp"]},
        "browser_crawl_data": {"urls": [f"https://{names[14]}/bc"], "api_endpoints": [{"url": f"https://{names[15]}/xhr", "method": "put"}],
                               "results": [{"host": names[16], "urls": ["/r1"], "api_endpoints": [{"url": "/r2", "method": "DELETE"}]}]},
        "api_exposure": {"findings": [{"url": f"https://{names[17]}/panel", "host": names[17], "method": "GET"}, {"url": f"https://{names[18]}/p2"}]},
    }
    history = [{"subdomain": "h1.alvo.test", "is_alive": True, "source": "ct"}, {"subdomain": names[0], "is_alive": False, "source": "x"},
               {"subdomain": "dead.alvo.test", "is_alive": False, "source": "y"}]
    return co, history


def run_oracle(co, history):
    r = subprocess.run(["node", str(ORACLE)], input=json.dumps({"co": co, "history": history}), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-600:]
    return json.loads(r.stdout)


def test_server_matrix_matches_legacy_front_code():
    co, history = synthetic_company()
    js = run_oracle(co, history)
    rows = {h["host"]: h for h in m.build_rows(co, history)}
    assert set(rows) == {x["host"] for x in js} and len(js) > 10
    for x in js:
        r = rows[x["host"]]
        a = r["_agg"]
        agg_py = None if a is None else {k: a[k] for k in ("sev", "findings", "cve", "secrets", "endpoints", "score")}
        agg_js = None if x["agg"] is None else {k: x["agg"][k] for k in ("sev", "findings", "cve", "secrets", "endpoints", "score")}
        assert r["_domain"] == x["domain"], x["host"]
        assert r["_risk"] == x["risk"], x["host"]
        assert m.tech_labels(r) == x["tech"], x["host"]
        assert [p["port"] + ":" + p["service"] for p in m.open_ports(r)] == x["ports"], x["host"]
        assert [s["label"] for s in m.infra_signals(r)] == x["infra"], x["host"]
        assert agg_py == agg_js, x["host"]
    # o fixture precisa realmente exercitar endpoints/secrets/CVE
    totals = {k: sum((r["_agg"] or {}).get(k, 0) for r in rows.values()) for k in ("endpoints", "secrets", "cve")}
    assert all(v > 0 for v in totals.values()), totals


def test_query_filters_sort_and_pages():
    co, history = synthetic_company()
    rows = m.build_rows(co, history)
    q = m.query(rows, per_page=10, sort="findings", asc=False)
    scores = [(h["_agg"] or {"score": 0})["score"] for h in q["items"]]
    assert scores == sorted(scores, reverse=True) and q["pages"] == -(-q["total"] // 10)
    assert all(h["_agg"] and h["_agg"]["sev"]["critical"] > 0 for h in m.query(rows, find="critical", per_page=500)["items"])
    assert all(h["_domain"] == "alvo.test" for h in m.query(rows, domain="alvo.test", per_page=500)["items"])
    nowaf = m.query(rows, has="nowaf", per_page=500)
    assert nowaf["total"] == q["facets"]["chips"]["nowaf"]
    assert m.query(rows, page=999)["page"] == m.query(rows)["pages"]
    assert {h["host"] for h in m.query(rows, q="www", per_page=500)["items"]} == {h["host"] for h in rows if "www" in h["host"] or any("www" in l.lower() for l in m.tech_labels(h)) or "www" in (h.get("title") or "").lower() or "www" in (h.get("ip") or "")}


def test_export_rows_are_flat():
    co, history = synthetic_company()
    rows = m.export_rows(m.build_rows(co, history))
    assert rows and set(rows[0]) >= {"host", "url", "critical", "cve", "secrets", "endpoints", "ports", "waf"}
