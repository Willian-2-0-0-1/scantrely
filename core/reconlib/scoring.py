"""Risk Scoring — extraído de core/recon.py (ver core/recon.py para o índice completo)."""

# ── Risk Scoring ──

def score_host(host: dict, findings: list) -> int:
    """0–100 risk score per host."""
    score = 0
    hostname = host.get("host","")

    for f in findings:
        if hostname in (f.get("host",""), f.get("url","")):
            score += {"critical":30,"high":15,"medium":5,"low":2,"info":1}.get(
                f.get("severity","info"), 1)

    waf = host.get("waf","")
    if "Direct" in waf and "Firewalled" not in waf:
        score += 20

    risky = {"21","22","23","25","110","143","3306","5432","6379","27017","9200","2375","8500"}
    score += sum(8 for p in host.get("ports",[]) if p in risky)

    return min(score, 100)
