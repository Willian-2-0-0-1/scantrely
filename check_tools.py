#!/usr/bin/env python3
"""
check_tools.py — Verificação e diagnóstico de ferramentas do SCANTRELY
Verifica se todas as ferramentas necessárias estão instaladas e disponíveis.

Uso:
    python check_tools.py           # relatório de status
    python check_tools.py --fix     # tenta instalar o que estiver faltando (Linux/Mac)
    python check_tools.py --json    # saída JSON para automação
"""
import sys, os, shutil, subprocess, json, platform
from pathlib import Path

BASE    = Path(__file__).parent.resolve()
BIN_DIR = BASE / "bin"
VENV    = BASE / ".venv"
IS_WIN  = platform.system() == "Windows"
IS_MAC  = platform.system() == "Darwin"

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def _c(color, text): return f"{color}{text}{RESET}" if sys.stdout.isatty() else text

# ─── Tool definitions ─────────────────────────────────────────────────
# (name, category, install_hint_linux, install_hint_windows, required)
CLI_TOOLS = [
    # ProjectDiscovery
    ("httpx",       "HTTP",      "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",         "Download: https://github.com/projectdiscovery/httpx/releases", True),
    ("subfinder",   "Subdomain", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "Download: https://github.com/projectdiscovery/subfinder/releases", True),
    ("nuclei",      "Vuln",      "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",    "Download: https://github.com/projectdiscovery/nuclei/releases",    True),
    ("naabu",       "Port Scan", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",      "Download: https://github.com/projectdiscovery/naabu/releases",     True),
    ("dnsx",        "DNS",       "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",           "Download: https://github.com/projectdiscovery/dnsx/releases",      True),
    ("katana",      "HTTP",      "go install github.com/projectdiscovery/katana/cmd/katana@latest",       "Download: https://github.com/projectdiscovery/katana/releases",    True),
    ("shuffledns",  "DNS",       "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest","Download: https://github.com/projectdiscovery/shuffledns/releases",False),
    ("alterx",      "Subdomain", "go install github.com/projectdiscovery/alterx/cmd/alterx@latest",      "Download: https://github.com/projectdiscovery/alterx/releases",    False),
    ("mapcidr",     "Util",      "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",     "Download: https://github.com/projectdiscovery/mapcidr/releases",   False),
    ("asnmap",      "OSINT",     "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest",       "Download: https://github.com/projectdiscovery/asnmap/releases",    False),
    ("cloudlist",   "Cloud",     "go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest", "Download: https://github.com/projectdiscovery/cloudlist/releases", False),
    ("urlfinder",   "HTTP",      "go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest", "Download: https://github.com/projectdiscovery/urlfinder/releases", False),
    # Other Go tools
    ("ffuf",        "HTTP",      "go install github.com/ffuf/ffuf/v2@latest",                             "Download: https://github.com/ffuf/ffuf/releases",                  True),
    ("gobuster",    "HTTP",      "go install github.com/OJ/gobuster/v3@latest",                           "Download: https://github.com/OJ/gobuster/releases",                False),
    ("gau",         "HTTP",      "go install github.com/lc/gau/v2/cmd/gau@latest",                       "Download: https://github.com/lc/gau/releases",                     False),
    ("amass",       "Subdomain", "go install github.com/owasp-amass/amass/v4/...@master",                 "Download: https://github.com/owasp-amass/amass/releases",          False),
    ("trufflehog",  "Secrets",   "go install github.com/trufflesecurity/trufflehog/v3@latest",            "Download: https://github.com/trufflesecurity/trufflehog/releases", False),
    ("gowitness",   "HTTP",      "go install github.com/sensepost/gowitness@latest",                      "Download: https://github.com/sensepost/gowitness/releases",        False),
    ("waybackurls", "OSINT",     "go install github.com/tomnomnom/waybackurls@latest",                    "go install github.com/tomnomnom/waybackurls@latest (requires Go)",  False),
    ("subjs",       "HTTP",      "go install github.com/lc/subjs@latest",                                 "go install github.com/lc/subjs@latest (requires Go)",              False),
    ("getJS",       "HTTP",      "go install github.com/003random/getJS/v2@latest",                       "go install github.com/003random/getJS/v2@latest (requires Go)",    False),
    ("subjack",     "Subdomain", "go install github.com/haccer/subjack@latest",                           "go install github.com/haccer/subjack@latest (requires Go)",        False),
    ("puredns",     "DNS",       "go install github.com/d3mondev/puredns/v2@latest",                      "Download: https://github.com/d3mondev/puredns/releases",           False),
    ("massdns",     "DNS",       "apt install massdns",                                                    "WSL: apt install massdns / Build from source",                    False),
    # System tools
    ("nmap",        "Port Scan", "apt install nmap",                                                       "Download: https://nmap.org/download.html  (or: winget install nmap)", True),
    ("dig",         "DNS",       "apt install dnsutils",                                                   "WSL: apt install dnsutils  (nslookup built-in on Windows)",        False),
    ("whois",       "OSINT",     "apt install whois",                                                      "WSL: apt install whois  (sysinternals whois for Windows)",         False),
    ("curl",        "Util",      "apt install curl",                                                       "Built-in since Windows 10 1803",                                  True),
    ("git",         "Util",      "apt install git",                                                        "Download: https://git-scm.com/download/win  (or: winget install git.git)", True),
]

PYTHON_PACKAGES = [
    ("flask",          "flask>=3.0",       True),
    ("flask_limiter",  "flask-limiter>=3", False),
    ("playwright",     "playwright>=1.45", True),
    ("httpx",          "httpx>=0.27",      False),
    ("jinja2",         "jinja2>=3.1",      False),
    ("yaml",           "pyyaml>=6.0",      False),
    ("bbot",           "bbot",             False),
    ("dnsgen",         "dnsgen",           False),
    ("requests",       "requests",         False),
]

RUNTIME_CHECKS = [
    ("Python 3.10+",  lambda: sys.version_info >= (3, 10)),
    ("Go installed",  lambda: shutil.which("go") is not None),
    ("bin/ folder",   lambda: BIN_DIR.exists()),
    (".venv/ folder", lambda: (VENV / ("Scripts" if IS_WIN else "bin")).exists()),
    ("Playwright browsers", lambda: _check_playwright()),
]


def _find_bin(name: str) -> str | None:
    # Check project bin/ first (project-local tools installed by install_tools.sh)
    local = BIN_DIR / (name + ".exe" if IS_WIN else name)
    if local.exists() and os.access(local, os.X_OK):
        return str(local)
    return shutil.which(name)


def _check_playwright() -> bool:
    try:
        # Try import
        import playwright  # noqa
        # Check if browsers are installed
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "--dry-run"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _pip_check(module: str) -> bool:
    try:
        __import__(module.replace("-","_"))
        return True
    except ImportError:
        return False


def _venv_pip_install(package: str) -> bool:
    pip_path = VENV / ("Scripts" / "pip.exe" if IS_WIN else "bin" / "pip")
    if not pip_path.exists():
        return False
    result = subprocess.run([str(pip_path), "install", "-q", package], capture_output=True, timeout=120)
    return result.returncode == 0


def check_all(fix: bool = False) -> dict:
    results = {
        "runtime":    [],
        "cli_tools":  [],
        "python_pkgs":[],
        "summary":    {},
    }

    # ── Runtime checks ─────────────────────────────────────────────────
    for name, fn in RUNTIME_CHECKS:
        ok = False
        try: ok = fn()
        except Exception: pass
        results["runtime"].append({"name": name, "ok": ok})

    # ── CLI tools ──────────────────────────────────────────────────────
    for tool, cat, hint_linux, hint_win, required in CLI_TOOLS:
        path = _find_bin(tool)
        ok   = path is not None
        version = ""
        if ok:
            try:
                r = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
                version = (r.stdout or r.stderr).strip().split("\n")[0][:60]
            except Exception:
                pass
        hint = hint_win if IS_WIN else hint_linux
        results["cli_tools"].append({
            "name": tool, "category": cat, "ok": ok,
            "path": path or "", "version": version,
            "hint": hint, "required": required,
        })

    # ── Python packages ────────────────────────────────────────────────
    for module, package, required in PYTHON_PACKAGES:
        ok = _pip_check(module)
        if not ok and fix:
            ok = _venv_pip_install(package)
        results["python_pkgs"].append({
            "name": package, "module": module,
            "ok": ok, "required": required,
        })

    # ── Summary ────────────────────────────────────────────────────────
    total_tools  = len(CLI_TOOLS)
    ok_tools     = sum(1 for t in results["cli_tools"] if t["ok"])
    req_missing  = [t["name"] for t in results["cli_tools"] if not t["ok"] and t["required"]]
    opt_missing  = [t["name"] for t in results["cli_tools"] if not t["ok"] and not t["required"]]
    py_missing   = [p["name"] for p in results["python_pkgs"] if not p["ok"] and p["required"]]

    results["summary"] = {
        "tools_ok":      ok_tools,
        "tools_total":   total_tools,
        "required_missing": req_missing,
        "optional_missing": opt_missing,
        "python_missing":   py_missing,
        "ready":         len(req_missing) == 0 and len(py_missing) == 0,
    }
    return results


def print_report(results: dict):
    s = results["summary"]
    print()
    print(f"{BOLD}{CYAN}============================================={RESET}")
    print(f"{BOLD}{CYAN}  SCANTRELY — Verificação de Ferramentas{RESET}")
    print(f"{BOLD}{CYAN}============================================={RESET}")
    print(f"  Plataforma: {platform.system()} {platform.machine()}")
    print(f"  Python:     {sys.version.split()[0]}")
    print()

    # Runtime
    print(f"{BOLD}[ Ambiente de Execução ]{RESET}")
    for r in results["runtime"]:
        icon = _c(GREEN, "✓") if r["ok"] else _c(RED, "✗")
        print(f"  {icon}  {r['name']}")
    print()

    # CLI Tools
    print(f"{BOLD}[ Ferramentas CLI ]{RESET}")
    print(f"  Instaladas: {_c(GREEN, s['tools_ok'])}/{s['tools_total']}")
    print()
    by_cat = {}
    for t in results["cli_tools"]:
        by_cat.setdefault(t["category"], []).append(t)
    for cat, tools in sorted(by_cat.items()):
        print(f"  {_c(CYAN, cat)}")
        for t in tools:
            if t["ok"]:
                ver = f" ({t['version'][:40]})" if t["version"] else ""
                print(f"    {_c(GREEN,'✓')}  {t['name']}{ver}")
            else:
                tag = _c(RED,"✗ [REQUIRED]") if t["required"] else _c(YELLOW,"○ [optional]")
                print(f"    {tag}  {t['name']}")
                print(f"         Install: {t['hint']}")
    print()

    # Python packages
    print(f"{BOLD}[ Pacotes Python ]{RESET}")
    for p in results["python_pkgs"]:
        if p["ok"]:
            print(f"  {_c(GREEN,'✓')}  {p['name']}")
        else:
            tag = _c(RED,"✗ [REQUIRED]") if p["required"] else _c(YELLOW,"○ [optional]")
            print(f"  {tag}  {p['name']}")
            print(f"       Install: pip install {p['name']}")
    print()

    # Summary
    print(f"{BOLD}[ Resumo ]{RESET}")
    if s["ready"]:
        print(f"  {_c(GREEN, '✓ Plataforma pronta!')} Todas ferramentas obrigatórias instaladas.")
    else:
        if s["required_missing"]:
            print(f"  {_c(RED,'✗ FALTANDO (obrigatórias):')} {', '.join(s['required_missing'])}")
        if s["optional_missing"]:
            print(f"  {_c(YELLOW,'○ Faltando (opcionais):')} {', '.join(s['optional_missing'])}")
        if s["python_missing"]:
            print(f"  {_c(RED,'✗ Python (obrigatórios):')} {', '.join(s['python_missing'])}")
        print()
        if IS_WIN:
            print(f"  {_c(CYAN,'Dica Windows:')} Execute install_tools.sh via WSL ou baixe os")
            print(f"  binários Windows manualmente e coloque em ./bin/")
        else:
            print(f"  {_c(CYAN,'Dica:')} Execute: bash install_tools.sh")
    print()
    print(f"{BOLD}{CYAN}============================================={RESET}")
    print()


def main():
    fix_mode  = "--fix" in sys.argv
    json_mode = "--json" in sys.argv

    if fix_mode and IS_WIN:
        print(_c(YELLOW, "[!] --fix não suportado no Windows. Instale as ferramentas manualmente."))
        fix_mode = False

    results = check_all(fix=fix_mode)

    if json_mode:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print_report(results)

    sys.exit(0 if results["summary"]["ready"] else 1)


if __name__ == "__main__":
    main()
