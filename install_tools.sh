#!/usr/bin/env bash
# install_tools.sh — instala todas as ferramentas externas do ASM Platform em ./bin/
# Uso: bash install_tools.sh [--force]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
VENV_DIR="$SCRIPT_DIR/.venv"
FORCE="${1:-}"

mkdir -p "$BIN_DIR"

# ── Helpers ───────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }
skip() { echo -e "[-] $1 já instalado — pulando (use --force para reinstalar)"; }

need_install() {
  local bin="$1"
  [[ "$FORCE" == "--force" ]] && return 0
  [[ -x "$BIN_DIR/$bin" ]] && { skip "$bin"; return 1; } || return 0
}

# Detecta arquitetura
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)          GOARCH="amd64";  GOARCH_ALT="x86_64" ;;
  aarch64|arm64)   GOARCH="arm64";  GOARCH_ALT="arm64"  ;;
  *)               warn "Arquitetura não suportada: $ARCH"; exit 1 ;;
esac
OS="linux"

# Header de autenticação GitHub (elimina rate limit de 60→5000 req/hora)
# Defina GITHUB_TOKEN no ambiente para evitar erros de rate limit
GH_AUTH_HEADER=""
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  GH_AUTH_HEADER="Authorization: Bearer ${GITHUB_TOKEN}"
  log "GitHub token detectado — rate limit elevado para 5000 req/hora"
fi

# Baixa e extrai arquivo de release do GitHub
# Uso: gh_release <owner/repo> <padrão_asset_regex> <binário_dentro_do_arquivo>
gh_release() {
  local repo="$1" pattern="$2" binary="$3"
  local display_name="${4:-$binary}"

  need_install "$binary" || return 0
  log "Baixando $display_name..."

  local api_url="https://api.github.com/repos/${repo}/releases/latest"
  local curl_auth_args=()
  [[ -n "$GH_AUTH_HEADER" ]] && curl_auth_args=(-H "$GH_AUTH_HEADER")

  local download_url
  download_url=$(curl -fsSL "${curl_auth_args[@]}" "$api_url" 2>/dev/null \
    | python3 -c "
import sys, json, re
try:
    data = json.load(sys.stdin)
    if 'message' in data:
        import sys; print('[API]', data['message'], file=sys.stderr)
    assets = data.get('assets', [])
    pat = r'${pattern}'
    found = [a['browser_download_url'] for a in assets if re.search(pat, a['name'], re.I)]
    print(found[0] if found else '')
except Exception as e:
    print('', file=sys.stdout)
" 2>/dev/null || echo "")

  if [[ -z "$download_url" ]]; then
    err "$display_name: release não encontrado (rate limit? defina GITHUB_TOKEN=<seu_token>)"
    return
  fi

  local tmp; tmp=$(mktemp -d)
  trap "rm -rf '$tmp'" RETURN

  local fname="${download_url##*/}"
  curl -fsSL "$download_url" -o "$tmp/$fname"

  # Extrai conforme extensão
  mkdir -p "$tmp/out"
  if [[ "$fname" == *.zip ]]; then
    unzip -q "$tmp/$fname" -d "$tmp/out/"
  elif [[ "$fname" == *.tar.gz ]] || [[ "$fname" == *.tgz ]]; then
    tar -xzf "$tmp/$fname" -C "$tmp/out/"
  else
    # Binário direto — copia com nome final já correto
    cp "$tmp/$fname" "$tmp/out/$binary"
    chmod +x "$tmp/out/$binary"
  fi

  # Procura o binário (pode estar em subdir)
  local found_bin
  found_bin=$(find "$tmp/out" -name "$binary" -type f 2>/dev/null | head -1 || true)
  if [[ -z "$found_bin" ]]; then
    # Tenta sem extensão / com nome exato
    found_bin=$(find "$tmp/out" -maxdepth 3 -type f -executable 2>/dev/null | head -1 || true)
  fi

  if [[ -n "$found_bin" ]]; then
    cp "$found_bin" "$BIN_DIR/$binary"
    chmod +x "$BIN_DIR/$binary"
    echo "  ✓ $display_name → bin/$binary"
  else
    err "$display_name: binário '$binary' não encontrado no arquivo"
  fi
}

# Instala via go install (requer Go instalado)
go_install() {
  local pkg="$1" binary="$2"
  need_install "$binary" || return 0

  if ! command -v go &>/dev/null; then
    warn "Go não instalado — pulando $binary (instale go e re-execute)"
    return
  fi

  log "go install $binary..."
  export GOPATH="$SCRIPT_DIR/.gopath"
  export GOBIN="$BIN_DIR"
  mkdir -p "$GOPATH"

  if go install "$pkg" 2>/dev/null; then
    echo "  ✓ $binary"
  else
    err "$binary: go install falhou"
  fi
}

# ── ProjectDiscovery tools (binários pré-compilados) ─────────────────────────

echo ""
echo "══════════════════════════════════════════════════"
echo "  ProjectDiscovery Tools"
echo "══════════════════════════════════════════════════"

PD_TOOLS=(
  "httpx:projectdiscovery/httpx:httpx_[0-9._]+_${OS}_${GOARCH}\\.zip:httpx"
  "naabu:projectdiscovery/naabu:naabu_[0-9._]+_${OS}_${GOARCH}\\.zip:naabu"
  "subfinder:projectdiscovery/subfinder:subfinder_[0-9._]+_${OS}_${GOARCH}\\.zip:subfinder"
  "nuclei:projectdiscovery/nuclei:nuclei_[0-9._]+_${OS}_${GOARCH}\\.zip:nuclei"
  "dnsx:projectdiscovery/dnsx:dnsx_[0-9._]+_${OS}_${GOARCH}\\.zip:dnsx"
  "katana:projectdiscovery/katana:katana_[0-9._]+_${OS}_${GOARCH}\\.zip:katana"
  "shuffledns:projectdiscovery/shuffledns:shuffledns_[0-9._]+_${OS}_${GOARCH}\\.zip:shuffledns"
  "mapcidr:projectdiscovery/mapcidr:mapcidr_[0-9._]+_${OS}_${GOARCH}\\.zip:mapcidr"
  "asnmap:projectdiscovery/asnmap:asnmap_[0-9._]+_${OS}_${GOARCH}\\.zip:asnmap"
  "notify:projectdiscovery/notify:notify_[0-9._]+_${OS}_${GOARCH}\\.zip:notify"
  "cloudlist:projectdiscovery/cloudlist:cloudlist_[0-9._]+_${OS}_${GOARCH}\\.zip:cloudlist"
  "urlfinder:projectdiscovery/urlfinder:urlfinder_[0-9._]+_${OS}_${GOARCH}\\.zip:urlfinder"
  "alterx:projectdiscovery/alterx:alterx_[0-9._]+_${OS}_${GOARCH}\\.zip:alterx"
)

for entry in "${PD_TOOLS[@]}"; do
  IFS=':' read -r name repo pattern binary <<< "$entry"
  gh_release "$repo" "$pattern" "$binary" "$name"
done

# ── Outros tools Go ───────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════"
echo "  Outras Ferramentas"
echo "══════════════════════════════════════════════════"

# ffuf
gh_release "ffuf/ffuf" \
  "ffuf_[0-9.]+_${OS}_${GOARCH}\\.tar\\.gz" \
  "ffuf" "ffuf"

# gobuster
gh_release "OJ/gobuster" \
  "gobuster_Linux_${GOARCH_ALT}\\.tar\\.gz" \
  "gobuster" "gobuster"

# gau
gh_release "lc/gau" \
  "gau_[0-9.]+_${OS}_${GOARCH}\\.tar\\.gz" \
  "gau" "gau"

# trufflehog
gh_release "trufflesecurity/trufflehog" \
  "trufflehog_[0-9._]+_${OS}_${GOARCH}\\.tar\\.gz" \
  "trufflehog" "trufflehog"

# gitleaks (git_leaks module)
if [[ "$GOARCH" == "amd64" ]]; then
  GITLEAKS_PAT="gitleaks_[0-9._]+_linux_x64\\.tar\\.gz"
else
  GITLEAKS_PAT="gitleaks_[0-9._]+_linux_${GOARCH}\\.tar\\.gz"
fi
gh_release "gitleaks/gitleaks" "$GITLEAKS_PAT" "gitleaks" "gitleaks"

# gowitness
gh_release "sensepost/gowitness" \
  "gowitness-[0-9.]+-${OS}-${GOARCH}$" \
  "gowitness" "gowitness"

# puredns  (assets: puredns-Linux-amd64.tgz — usa GOARCH, não GOARCH_ALT)
gh_release "d3mondev/puredns" \
  "puredns-Linux-${GOARCH}\\.tgz" \
  "puredns" "puredns"

# amass  (assets: amass_linux_amd64.tar.gz)
gh_release "owasp-amass/amass" \
  "amass_${OS}_${GOARCH}\\.tar\\.gz" \
  "amass" "amass"

# massdns (compilar do fonte se go disponível, senão via apt)
APT_CMD="apt-get"; [[ $EUID -ne 0 ]] && APT_CMD="sudo apt-get"
if need_install "massdns"; then
  if apt-cache show massdns &>/dev/null 2>&1; then
    log "Instalando massdns via apt..."
    $APT_CMD install -y -q massdns 2>/dev/null && cp "$(which massdns)" "$BIN_DIR/" && echo "  ✓ massdns"
  else
    go_install "github.com/blechschmidt/massdns@latest" "massdns" 2>/dev/null || warn "massdns: instale manualmente (apt install massdns)"
  fi
fi

# waybackurls
go_install "github.com/tomnomnom/waybackurls@latest" "waybackurls"

# subjs
go_install "github.com/lc/subjs@latest" "subjs"

# getJS
go_install "github.com/003random/getJS/v2@latest" "getJS"

# subjack (subdomain takeover)
go_install "github.com/haccer/subjack@latest" "subjack"

# assetfinder (passive subdomain enum)
go_install "github.com/tomnomnom/assetfinder@latest" "assetfinder"

# whatweb (tech fingerprint) — clone upstream; o pacote apt 0.6.3 quebra require_relative
if need_install "whatweb"; then
  if ! command -v ruby &>/dev/null; then
    if command -v apt-get &>/dev/null; then
      log "Instalando ruby (dependência do whatweb)..."
      $APT_CMD install -y -q ruby >/dev/null 2>&1 || warn "ruby: apt install falhou"
    fi
  fi
  VENDOR_DIR="${VENDOR_DIR:-$SCRIPT_DIR/vendor}"
  mkdir -p "$VENDOR_DIR"
  log "Instalando whatweb (git)..."
  rm -rf "$VENDOR_DIR/whatweb"
  if git clone --depth 1 -q https://github.com/urbanadventurer/WhatWeb.git "$VENDOR_DIR/whatweb" 2>/dev/null; then
    cat > "$BIN_DIR/whatweb" << 'WW'
#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec ruby "$ROOT/vendor/whatweb/whatweb" "$@"
WW
    chmod +x "$BIN_DIR/whatweb"
    echo "  ✓ whatweb"
  else
    warn "whatweb: git clone falhou — instale: git clone https://github.com/urbanadventurer/WhatWeb vendor/whatweb"
  fi
fi


# ── Python tools (venv local) ─────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════"
echo "  Python Tools (venv em .venv/)"
echo "══════════════════════════════════════════════════"

if [[ ! -d "$VENV_DIR" ]]; then
  log "Criando venv Python em .venv/..."
  python3 -m venv "$VENV_DIR"
fi

PIP="$VENV_DIR/bin/pip"
PYTHON="$VENV_DIR/bin/python3"

# bbot
if [[ ! -x "$VENV_DIR/bin/bbot" ]] || [[ "$FORCE" == "--force" ]]; then
  log "Instalando bbot..."
  "$PIP" install -q --upgrade bbot && echo "  ✓ bbot"
  # Criar wrapper em bin/ para que server.py encontre
  cat > "$BIN_DIR/bbot" << EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/bbot" "\$@"
EOF
  chmod +x "$BIN_DIR/bbot"
else
  skip "bbot"
fi

# dnsgen
if [[ ! -x "$VENV_DIR/bin/dnsgen" ]] || [[ "$FORCE" == "--force" ]]; then
  log "Instalando dnsgen..."
  "$PIP" install -q --upgrade dnsgen && echo "  ✓ dnsgen"
else
  skip "dnsgen"
fi
if [[ -x "$VENV_DIR/bin/dnsgen" ]]; then
  cat > "$BIN_DIR/dnsgen" << EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/dnsgen" "\$@"
EOF
  chmod +x "$BIN_DIR/dnsgen"
fi

# graphqlmap
if [[ ! -x "$VENV_DIR/bin/graphqlmap" ]] || [[ "$FORCE" == "--force" ]]; then
  log "Instalando graphqlmap..."
  if "$PIP" install -q --upgrade graphqlmap 2>/dev/null; then
    echo "  ✓ graphqlmap"
    cat > "$BIN_DIR/graphqlmap" << EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/graphqlmap" "\$@"
EOF
    chmod +x "$BIN_DIR/graphqlmap"
  else
    err "graphqlmap: falha no pip — tentando via git..."
    tmp_gql=$(mktemp -d)
    if git clone -q https://github.com/swisskyrepo/GraphQLmap "$tmp_gql/GraphQLmap" 2>/dev/null; then
      "$PIP" install -q "$tmp_gql/GraphQLmap" && echo "  ✓ graphqlmap (via git)"
      cat > "$BIN_DIR/graphqlmap" << EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/graphqlmap" "\$@"
EOF
      chmod +x "$BIN_DIR/graphqlmap"
    else
      warn "graphqlmap: não foi possível instalar — instale manualmente: pip install graphqlmap"
    fi
    rm -rf "$tmp_gql"
  fi
else
  skip "graphqlmap"
fi

# ── Pip helper: instala pacote + cria wrapper em bin/ ──────────────────────────
pip_tool() {
  local pkg="$1" binary="$2"
  if [[ -x "$VENV_DIR/bin/$binary" ]] && [[ "$FORCE" != "--force" ]]; then
    skip "$binary"; return
  fi
  log "Instalando $binary (pip)..."
  if "$PIP" install -q --upgrade "$pkg" 2>/dev/null; then
    echo "  ✓ $binary"
    cat > "$BIN_DIR/$binary" << WRAPPER
#!/usr/bin/env bash
exec "$VENV_DIR/bin/$binary" "\$@"
WRAPPER
    chmod +x "$BIN_DIR/$binary"
  else
    err "$binary: pip install falhou"
  fi
}

# theHarvester — o pacote PyPI 0.0.1 é stub; instalar do GitHub
if [[ ! -x "$VENV_DIR/bin/theHarvester" ]] || [[ "$FORCE" == "--force" ]]; then
  log "Instalando theHarvester (git)..."
  if "$PIP" install -q "git+https://github.com/laramies/theHarvester.git"; then
    # theHarvester pina playwright antigo; manter o Playwright do ASM
    "$PIP" install -q 'playwright==1.63.0' >/dev/null 2>&1 || true
    cat > "$BIN_DIR/theHarvester" << WRAPPER
#!/usr/bin/env bash
exec "$VENV_DIR/bin/theHarvester" "\$@"
WRAPPER
    chmod +x "$BIN_DIR/theHarvester"
    ln -sfn theHarvester "$BIN_DIR/theharvester"
    echo "  ✓ theHarvester"
  else
    err "theHarvester: pip install do GitHub falhou"
  fi
else
  skip "theHarvester"
  [[ -x "$BIN_DIR/theHarvester" ]] || {
    cat > "$BIN_DIR/theHarvester" << WRAPPER
#!/usr/bin/env bash
exec "$VENV_DIR/bin/theHarvester" "\$@"
WRAPPER
    chmod +x "$BIN_DIR/theHarvester"
  }
  ln -sfn theHarvester "$BIN_DIR/theharvester"
fi

# certstream (python import — crt.sh fallback if missing)
if ! "$VENV_DIR/bin/python3" -c "import certstream" 2>/dev/null; then
  log "Instalando certstream (pip)..."
  "$PIP" install -q certstream && echo "  ✓ certstream (python)" || warn "certstream: pip install falhou (crt.sh continua como fallback)"
else
  skip "certstream"
fi

# cloud_enum
if [[ ! -x "$BIN_DIR/cloud_enum" ]] || [[ "$FORCE" == "--force" ]]; then
  log "Instalando cloud_enum (git)..."
  tmp_ce=$(mktemp -d)
  if git clone -q https://github.com/initstring/cloud_enum "$tmp_ce/cloud_enum" 2>/dev/null; then
    "$PIP" install -q -r "$tmp_ce/cloud_enum/requirements.txt" 2>/dev/null || true
    cp "$tmp_ce/cloud_enum/cloud_enum.py" "$BIN_DIR/cloud_enum"
    chmod +x "$BIN_DIR/cloud_enum"
    # enum_tools is imported as a sibling package; copy it next to the script.
    rm -rf "$BIN_DIR/enum_tools"
    cp -R "$tmp_ce/cloud_enum/enum_tools" "$BIN_DIR/enum_tools"
    # ensure shebang points to venv python
    sed -i "1s|.*|#!$VENV_DIR/bin/python3|" "$BIN_DIR/cloud_enum"
    echo "  ✓ cloud_enum"
  else
    warn "cloud_enum: git clone falhou"
  fi
  rm -rf "$tmp_ce"
else
  skip "cloud_enum"
fi

# arjun (HTTP parameter discovery)
pip_tool "arjun" "arjun"

VENDOR_DIR="$SCRIPT_DIR/vendor"
mkdir -p "$VENDOR_DIR"

# linkfinder (JS endpoint extractor) — persist in vendor/, never /tmp
if [[ ! -x "$BIN_DIR/linkfinder" || ! -f "$VENDOR_DIR/linkfinder/linkfinder.py" ]] || [[ "$FORCE" == "--force" ]]; then
  log "Instalando linkfinder (git)..."
  rm -rf "$VENDOR_DIR/linkfinder"
  if git clone -q https://github.com/GerbenJavado/LinkFinder "$VENDOR_DIR/linkfinder" 2>/dev/null; then
    "$PIP" install -q -r "$VENDOR_DIR/linkfinder/requirements.txt" 2>/dev/null || true
    cat > "$BIN_DIR/linkfinder" << LF_WRAPPER
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python3" "$VENDOR_DIR/linkfinder/linkfinder.py" "\$@"
LF_WRAPPER
    chmod +x "$BIN_DIR/linkfinder"
    echo "  ✓ linkfinder"
  else
    warn "linkfinder: git clone falhou"
  fi
else
  skip "linkfinder"
fi

# secretfinder (JS secret detector) — persist in vendor/, never /tmp
if [[ ! -x "$BIN_DIR/secretfinder" || ! -f "$VENDOR_DIR/secretfinder/SecretFinder.py" ]] || [[ "$FORCE" == "--force" ]]; then
  log "Instalando secretfinder (git)..."
  rm -rf "$VENDOR_DIR/secretfinder"
  if git clone -q https://github.com/m4ll0k/SecretFinder "$VENDOR_DIR/secretfinder" 2>/dev/null; then
    "$PIP" install -q -r "$VENDOR_DIR/secretfinder/requirements.txt" 2>/dev/null || true
    cat > "$BIN_DIR/secretfinder" << SF_WRAPPER
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python3" "$VENDOR_DIR/secretfinder/SecretFinder.py" "\$@"
SF_WRAPPER
    chmod +x "$BIN_DIR/secretfinder"
    echo "  ✓ secretfinder"
  else
    warn "secretfinder: git clone falhou"
  fi
else
  skip "secretfinder"
fi

# mmh3 + shodan (needed by FaviconHashTool)
if ! "$VENV_DIR/bin/python3" -c "import mmh3" 2>/dev/null; then
  log "Instalando mmh3..."
  "$PIP" install -q mmh3 && echo "  ✓ mmh3"
fi
if ! "$VENV_DIR/bin/python3" -c "import shodan" 2>/dev/null; then
  log "Instalando shodan..."
  "$PIP" install -q shodan && echo "  ✓ shodan (python)"
fi

# wpscan (via gem if available, else warn)
if need_install "wpscan"; then
  if command -v gem &>/dev/null; then
    log "Instalando wpscan (gem)..."
    gem install wpscan --no-document -q 2>/dev/null && cp "$(which wpscan 2>/dev/null || echo '')" "$BIN_DIR/wpscan" 2>/dev/null && echo "  ✓ wpscan" || warn "wpscan: gem install falhou — instale manualmente: gem install wpscan"
  else
    warn "wpscan: ruby gems não disponível — instale manualmente: apt install ruby && gem install wpscan"
  fi
fi

# ── apkleaks (mobile recon) + jadx (decompiler dependency) ────────────────────
pip_tool "apkleaks" "apkleaks"
if ! command -v jadx >/dev/null 2>&1; then
  log "Instalando jadx (dependência do apkleaks)..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y jadx >/dev/null 2>&1 && echo "  ✓ jadx" \
      || warn "jadx: instale manualmente (apt install jadx) — apkleaks precisa dele para decompilar"
  else
    warn "jadx: instale manualmente — apkleaks precisa dele para decompilar APKs"
  fi
else
  skip "jadx"
fi

# ── Resumo ────────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════"
echo "  Resumo"
echo "══════════════════════════════════════════════════"

INSTALLED=0; MISSING=0
for tool in httpx naabu subfinder nuclei dnsx katana shuffledns ffuf gobuster \
            gau trufflehog gitleaks gowitness puredns amass waybackurls subjs subjack \
            assetfinder whatweb theHarvester \
            bbot dnsgen alterx graphqlmap cloud_enum arjun linkfinder secretfinder wpscan apkleaks; do
  if [[ -x "$BIN_DIR/$tool" ]]; then
    echo "  ✓ $tool"
    INSTALLED=$((INSTALLED + 1))
  else
    echo "  ✗ $tool  ← não instalado"
    MISSING=$((MISSING + 1))
  fi
done

echo ""
echo "  Instalados : $INSTALLED"
[[ $MISSING -gt 0 ]] && echo "  Faltando   : $MISSING (opcional — o sistema usa os que estiver disponível)"
echo ""
echo "  Os binários estão em: $BIN_DIR"
echo "  O server.py adiciona bin/ ao PATH automaticamente na inicialização."
echo ""

# ── Playwright + Chromium (VPS headless) ─────────────────────────────────────

log "Verificando Playwright (VPS headless)..."

install_playwright_deps() {
  local pkg
  local deps=(
    libnss3 libnspr4 libatk-bridge2.0-0 libatk1.0-0
    libcups2 libdrm2 libdbus-1-3 libxkbcommon0
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2
    libgbm1 libasound2 libpango-1.0-0 libcairo2
    libx11-xcb1 libxcb-dri3-0 libxcb1
  )
  local missing=()
  for pkg in "${deps[@]}"; do
    dpkg -s "$pkg" &>/dev/null || missing+=("$pkg")
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    log "Playwright system deps: OK"
    return 0
  fi
  warn "Playwright VPS deps: ${#missing[@]} pacotes faltando"
  if command -v apt-get &>/dev/null; then
    log "Instalando ${missing[*]} ..."
    sudo apt-get install -y -qq "${missing[@]}" 2>/dev/null && log "Playwright deps instalados" || warn "apt-get falhou — instale manualmente: sudo apt install ${missing[*]}"
  else
    warn "apt-get não encontrado. Instale manualmente: ${missing[*]}"
  fi
}

# Instalar/atualizar playwright + chromium
ensure_playwright() {
  local pw_home="${ASM_PLAYWRIGHT_HOME:-$HOME/.asm-playwright}"
  if python3 -c "from playwright.sync_api import sync_playwright" 2>/dev/null; then
    log "Playwright Python: OK"
  else
    log "Instalando playwright..."
    pip install playwright 2>/dev/null || warn "pip install playwright falhou"
  fi
  # Install chromium separately to respect ASM_PLAYWRIGHT_HOME
  if [[ -d "$pw_home" ]] && [[ -x "$pw_home/ms-playwright/chromium-"*"/chrome-linux/chrome" ]] 2>/dev/null || true; then
    log "Chromium (Playwright): OK"
  else
    log "Instalando chromium para Playwright..."
    PLAYWRIGHT_BROWSERS_PATH="$pw_home" python3 -m playwright install chromium 2>/dev/null || warn "playwright install chromium falhou"
  fi
}

if [[ "${SKIP_PLAYWRIGHT:-0}" != "1" ]]; then
  install_playwright_deps
  ensure_playwright
else
  warn "Playwright pulado (SKIP_PLAYWRIGHT=1)"
fi

echo ""
echo "  Setup completo."
