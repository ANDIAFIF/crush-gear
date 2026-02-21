#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║              CrushGear — One-Command Installer                      ║
# ║                                                                      ║
# ║  Usage:                                                              ║
# ║    bash install.sh          ← install semua (pre-built binaries)    ║
# ║    bash install.sh --full   ← clone & build SEMUA dari source       ║
# ║                               (metasploit ~1GB, full modules/CVEs)  ║
# ║    bash install.sh --no-msf ← skip metasploit (lebih cepat)        ║
# ║    bash install.sh --fix    ← re-install hanya tools yg MISSING    ║
# ╚══════════════════════════════════════════════════════════════════════╝

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

NO_MSF=0
FULL=0
FORCE=0
FIX=0
for arg in "$@"; do
  [[ "$arg" == "--no-msf" ]] && NO_MSF=1
  [[ "$arg" == "--full"   ]] && FULL=1
  [[ "$arg" == "--force"  ]] && FORCE=1
  [[ "$arg" == "--fix"    ]] && FIX=1
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() {
  echo
  echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${CYAN}║        CrushGear — Automated Installer                   ║${NC}"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
  echo
}

step()  { echo -e "\n${BOLD}${YELLOW}▶ $1${NC}"; }
ok()    { echo -e "  ${GREEN}✓ $1${NC}"; }
warn()  { echo -e "  ${YELLOW}⚠ $1${NC}"; }
err()   { echo -e "  ${RED}✗ $1${NC}"; }
info()  { echo -e "  ${CYAN}→ $1${NC}"; }

# ── Detect best available Python ──────────────────────────────────────────────
# Cari Python 3.9-3.12 dulu (kompatibel semua tools), fallback ke apapun 3.9+
detect_python() {
  # Priority: Python 3.12 > 3.11 > 3.10 > 3.9 > 3.13 > 3.14 > generic
  for py in python3.12 python3.11 python3.10 python3.9 python3.13 python3.14 python3 python; do
    if command -v "$py" &>/dev/null; then
      local ver
      ver=$("$py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
      local major="${ver%%.*}"
      local minor="${ver##*.}"
      if [[ "$major" -eq 3 && "$minor" -ge 9 ]] 2>/dev/null; then
        echo "$py"
        return 0
      fi
    fi
  done
  echo ""
}

# ── Find Python compatible with netexec (3.9-3.12) ───────────────────────────
find_netexec_python() {
  for py in python3.12 python3.11 python3.10 python3.9; do
    if command -v "$py" &>/dev/null; then
      echo "$py"
      return 0
    fi
  done
  # Cek Homebrew paths (macOS)
  if [[ "$(uname -s)" == "Darwin" ]]; then
    for ver in 3.12 3.11 3.10 3.9; do
      for prefix in /opt/homebrew/opt/python@${ver}/bin /usr/local/opt/python@${ver}/bin; do
        if [[ -x "${prefix}/python${ver}" ]]; then
          echo "${prefix}/python${ver}"
          return 0
        fi
      done
    done
  fi
  # Cek common paths (Linux — deadsnakes PPA, system)
  if [[ "$(uname -s)" == "Linux" ]]; then
    for ver in 3.12 3.11 3.10 3.9; do
      for prefix in /usr/bin /usr/local/bin; do
        if [[ -x "${prefix}/python${ver}" ]]; then
          echo "${prefix}/python${ver}"
          return 0
        fi
      done
    done
  fi
  echo ""
}

# ── Ensure Python 3.12 is installed (for netexec compat) ─────────────────────
# NOTE: This function echoes ONLY the python path to stdout.
#       All status messages go to stderr so $() capture works correctly.
ensure_compat_python() {
  local nxc_py
  nxc_py=$(find_netexec_python)
  if [[ -n "$nxc_py" ]]; then
    ok "Python compatible for netexec: $nxc_py ($($nxc_py --version 2>&1))" >&2
    echo "$nxc_py"
    return 0
  fi

  # Tidak ada Python 3.9-3.12, auto-install
  step "Installing Python 3.12 (needed for netexec compatibility)" >&2
  info "Current Python too new — netexec needs 3.9-3.12. Auto-installing ..." >&2

  if [[ "$(uname -s)" == "Darwin" ]]; then
    # macOS: install via Homebrew
    if command -v brew &>/dev/null; then
      brew install python@3.12 2>&1 | tail -5 >&2
    fi
  elif [[ "$(uname -s)" == "Linux" ]]; then
    # Linux: try apt (deadsnakes PPA), dnf, yum
    if command -v apt-get &>/dev/null; then
      # Try deadsnakes PPA (Ubuntu/Debian)
      if command -v add-apt-repository &>/dev/null; then
        sudo add-apt-repository -y ppa:deadsnakes/ppa 2>&1 | tail -3 >&2
        sudo apt-get update -qq 2>&1 | tail -3 >&2
      fi
      sudo apt-get install -y python3.12 python3.12-venv python3.12-dev 2>&1 | tail -5 >&2
    elif command -v dnf &>/dev/null; then
      sudo dnf install -y python3.12 2>&1 | tail -5 >&2
    elif command -v yum &>/dev/null; then
      sudo yum install -y python3.12 2>&1 | tail -5 >&2
    elif command -v pacman &>/dev/null; then
      sudo pacman -Sy --noconfirm python 2>&1 | tail -5 >&2
    fi
  fi

  # Cari lagi
  nxc_py=$(find_netexec_python)
  if [[ -n "$nxc_py" ]]; then
    ok "Python 3.12 installed: $nxc_py" >&2
    echo "$nxc_py"
    return 0
  fi

  # Fallback: gunakan Python utama meskipun mungkin terlalu baru
  # (mungkin tetap bisa jika install dari git source)
  local fallback_py
  fallback_py=$(detect_python)
  if [[ -n "$fallback_py" ]]; then
    warn "Python 3.12 not available. Trying with ${fallback_py} (may fail for PyPI, but git source should work)" >&2
    echo "$fallback_py"
    return 0
  fi

  warn "Could not find compatible Python for netexec" >&2
  echo ""
  return 1
}

# ── Ensure Ruby 3.0+ is in PATH ──────────────────────────────────────────────
ensure_ruby_in_path() {
  if command -v ruby &>/dev/null; then
    local ruby_ver
    ruby_ver=$(ruby -e "puts RUBY_VERSION" 2>/dev/null || echo "0")
    local major="${ruby_ver%%.*}"
    if [[ "$major" -ge 3 ]] 2>/dev/null; then
      ok "Ruby ${ruby_ver} in PATH"
      return 0
    fi
  fi

  if [[ "$(uname -s)" == "Darwin" ]]; then
    # macOS: cek Homebrew Ruby
    for prefix in /opt/homebrew/opt/ruby/bin /usr/local/opt/ruby/bin; do
      if [[ -x "${prefix}/ruby" ]]; then
        local ver
        ver=$("${prefix}/ruby" -e "puts RUBY_VERSION" 2>/dev/null || echo "0")
        local major="${ver%%.*}"
        if [[ "$major" -ge 3 ]] 2>/dev/null; then
          local gem_dir
          gem_dir=$("${prefix}/ruby" -e 'puts RbConfig::CONFIG["ruby_version"]' 2>/dev/null)
          export PATH="${prefix}:$(dirname "${prefix}")/lib/ruby/gems/${gem_dir}/bin:${PATH}"
          ok "Added Homebrew Ruby ${ver} to PATH"
          return 0
        fi
      fi
    done
    if command -v brew &>/dev/null; then
      step "Installing Ruby via Homebrew"
      brew install ruby 2>&1 | tail -5
      for prefix in /opt/homebrew/opt/ruby/bin /usr/local/opt/ruby/bin; do
        if [[ -x "${prefix}/ruby" ]]; then
          local gem_dir
          gem_dir=$("${prefix}/ruby" -e 'puts RbConfig::CONFIG["ruby_version"]' 2>/dev/null)
          export PATH="${prefix}:$(dirname "${prefix}")/lib/ruby/gems/${gem_dir}/bin:${PATH}"
          ok "Ruby installed via brew"
          return 0
        fi
      done
    fi

  elif [[ "$(uname -s)" == "Linux" ]]; then
    # Linux: install Ruby 3.0+ via package manager
    step "Installing Ruby 3.0+ (needed for Metasploit) ..."
    if command -v apt-get &>/dev/null; then
      sudo apt-get update -qq 2>&1 | tail -3
      sudo apt-get install -y ruby-full ruby-bundler ruby-dev 2>&1 | tail -5
    elif command -v dnf &>/dev/null; then
      sudo dnf install -y ruby ruby-devel rubygem-bundler 2>&1 | tail -5
    elif command -v yum &>/dev/null; then
      sudo yum install -y ruby ruby-devel 2>&1 | tail -5
    elif command -v pacman &>/dev/null; then
      sudo pacman -Sy --noconfirm ruby ruby-bundler 2>&1 | tail -5
    elif command -v zypper &>/dev/null; then
      sudo zypper install -y ruby ruby-devel 2>&1 | tail -5
    fi
    # Verify
    if command -v ruby &>/dev/null; then
      local ruby_ver
      ruby_ver=$(ruby -e "puts RUBY_VERSION" 2>/dev/null || echo "0")
      local major="${ruby_ver%%.*}"
      if [[ "$major" -ge 3 ]] 2>/dev/null; then
        ok "Ruby ${ruby_ver} installed"
        return 0
      fi
    fi
  fi
  warn "Ruby 3.0+ not found"
  return 1
}

# ── Ensure Rust/cargo is available ────────────────────────────────────────────
ensure_rust_in_path() {
  if command -v cargo &>/dev/null; then
    ok "Rust/cargo in PATH"
    return 0
  fi
  if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
    ok "Rust found at ~/.cargo/bin"
    return 0
  fi
  step "Installing Rust compiler (needed for some dependencies)"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y --no-modify-path 2>&1 | tail -3
  if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
    ok "Rust installed"
    return 0
  fi
  warn "Rust install failed"
  return 1
}

# ── Ensure pipx is available ─────────────────────────────────────────────────
ensure_pipx() {
  if command -v pipx &>/dev/null; then
    return 0
  fi
  if command -v brew &>/dev/null; then
    brew install pipx 2>&1 | tail -3
  elif command -v apt-get &>/dev/null; then
    sudo apt-get install -y pipx 2>&1 | tail -3
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y pipx 2>&1 | tail -3
  else
    # Fallback: install pipx via pip
    $PY -m pip install --user pipx --break-system-packages 2>&1 | tail -3
  fi
  pipx ensurepath 2>/dev/null
  export PATH="$HOME/.local/bin:$PATH"
  command -v pipx &>/dev/null
}

# ═══════════════════════════════════════════════════════════════════════════════
# TOOL INSTALLERS (fully automatic, multiple fallback strategies)
# ═══════════════════════════════════════════════════════════════════════════════

# ── Install netexec ───────────────────────────────────────────────────────────
install_netexec() {
  # Check if already installed in project bin/
  if [[ -x "${SCRIPT_DIR}/bin/nxc" ]]; then
    ok "netexec (nxc) already in project: bin/nxc"
    return 0
  fi
  # Check PATH
  if command -v nxc &>/dev/null; then
    ok "netexec (nxc) already installed: $(command -v nxc)"
    return 0
  fi

  # Find compatible Python (3.9-3.12)
  local NXC_PY
  NXC_PY=$(ensure_compat_python)

  if [[ -z "$NXC_PY" ]]; then
    err "No compatible Python found for netexec"
    return 1
  fi

  # Ensure Rust is available (netexec deps need it)
  ensure_rust_in_path

  local NXC_GIT="git+https://github.com/Pennyw0rth/NetExec.git"

  # Strategy 1: venv install in PROJECT folder (BEST — portable, self-contained)
  # Tools installed here stay inside tools-crushgear/ folder
  step "Installing netexec in project-local virtualenv ..."
  info "This keeps nxc inside your project folder (portable for team sharing)"
  local NXC_VENV="${SCRIPT_DIR}/.nxc_venv"
  [[ -d "$NXC_VENV" ]] && rm -rf "$NXC_VENV"
  "$NXC_PY" -m venv "$NXC_VENV" 2>/dev/null
  # Linux: if venv fails, install python3-venv
  if [[ ! -d "$NXC_VENV" && "$(uname -s)" == "Linux" ]]; then
    if command -v apt-get &>/dev/null; then
      local py_minor
      py_minor=$("$NXC_PY" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
      sudo apt-get install -y "python${py_minor}-venv" 2>&1 | tail -3
      "$NXC_PY" -m venv "$NXC_VENV" 2>/dev/null
    fi
  fi
  if [[ -f "${NXC_VENV}/bin/pip" ]]; then
    info "pip install from GitHub source (this may take a few minutes) ..."
    "${NXC_VENV}/bin/pip" install "$NXC_GIT" 2>&1 | tail -8
    if [[ -x "${NXC_VENV}/bin/nxc" ]]; then
      mkdir -p "${SCRIPT_DIR}/bin"
      # Create wrapper script instead of symlink (more portable)
      cat > "${SCRIPT_DIR}/bin/nxc" << 'WRAPPER'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "${SCRIPT_DIR}/.nxc_venv/bin/nxc" "$@"
WRAPPER
      chmod +x "${SCRIPT_DIR}/bin/nxc"
      ok "netexec installed in project: bin/nxc → .nxc_venv/bin/nxc"
      return 0
    fi
  fi
  warn "venv install failed, trying pipx ..."

  # Strategy 2: pipx from GitHub source (fallback)
  if ensure_pipx; then
    step "Installing netexec via pipx from GitHub source ..."
    if pipx install "$NXC_GIT" --python "$NXC_PY" --force 2>&1 | tail -8; then
      if command -v nxc &>/dev/null; then
        ok "netexec installed via pipx (git source)"
        return 0
      fi
      if [[ -x "$HOME/.local/bin/nxc" ]]; then
        export PATH="$HOME/.local/bin:$PATH"
        ok "netexec installed via pipx at ~/.local/bin/nxc"
        return 0
      fi
    fi
  fi

  # Strategy 3: pipx from PyPI
  if ensure_pipx; then
    step "Trying pipx install netexec from PyPI ..."
    if pipx install netexec --python "$NXC_PY" --force 2>&1 | tail -8; then
      if command -v nxc &>/dev/null; then
        ok "netexec installed via pipx (PyPI)"
        return 0
      fi
    fi
  fi

  # Strategy 4: pip install from PyPI
  step "Trying pip install netexec ..."
  "$NXC_PY" -m pip install netexec --break-system-packages 2>&1 | tail -8
  if command -v nxc &>/dev/null; then
    ok "netexec installed via pip"
    return 0
  fi

  err "netexec install failed after all attempts"
  return 1
}

# ── Install metasploit ────────────────────────────────────────────────────────
install_metasploit() {
  # Check if already installed anywhere
  if command -v msfconsole &>/dev/null; then
    ok "metasploit already installed: $(command -v msfconsole)"
    return 0
  fi
  # Check common install paths
  for msf_dir in /opt/metasploit-framework/bin /usr/local/bin /opt/homebrew/bin; do
    if [[ -x "${msf_dir}/msfconsole" ]]; then
      export PATH="${msf_dir}:$PATH"
      ok "metasploit found at: ${msf_dir}/msfconsole"
      return 0
    fi
  done

  if [[ "$(uname -s)" == "Darwin" ]]; then
    if command -v brew &>/dev/null; then
      step "Installing Metasploit via Homebrew ..."
      info "Running: brew install --cask metasploit"
      info "This may take a few minutes and may ask for your password ..."
      brew install --cask metasploit 2>&1 | tail -10

      # Check common install locations after brew cask
      for msf_dir in /opt/metasploit-framework/bin /opt/homebrew/bin /usr/local/bin; do
        if [[ -x "${msf_dir}/msfconsole" ]]; then
          export PATH="${msf_dir}:$PATH"
          ok "metasploit installed: ${msf_dir}/msfconsole"
          return 0
        fi
      done

      # Search more broadly
      local found
      found=$(find /opt -name msfconsole -type f 2>/dev/null | head -1)
      if [[ -n "$found" ]]; then
        export PATH="$(dirname "$found"):$PATH"
        ok "metasploit installed: ${found}"
        return 0
      fi
      warn "brew cask install may have failed"
    fi
  elif [[ "$(uname -s)" == "Linux" ]]; then
    step "Installing Metasploit (Linux) ..."
    # Delegate to setup_tools.py for Linux
    $PY -c "
import setup_tools
result = setup_tools.setup_metasploit()
if result:
    print(f'  ✓ Installed: {result}')
" 2>&1 | tail -10
    if command -v msfconsole &>/dev/null; then
      return 0
    fi
  fi

  # Fallback: Build from source if available
  local msf_src="${SCRIPT_DIR}/../metasploit-framework-master"
  if [[ -d "$msf_src" && -f "${msf_src}/msfconsole" ]]; then
    step "Setting up Metasploit from source ..."
    ensure_ruby_in_path

    # Install PostgreSQL headers (needed for pg gem)
    if [[ "$(uname -s)" == "Darwin" ]]; then
      if command -v brew &>/dev/null; then
        brew install libpq postgresql 2>&1 | tail -3
        local pg_config
        pg_config=$(find /opt/homebrew /usr/local -name pg_config -type f 2>/dev/null | head -1)
        if [[ -n "$pg_config" ]]; then
          export PATH="$(dirname "$pg_config"):$PATH"
        fi
      fi
    elif [[ "$(uname -s)" == "Linux" ]]; then
      if command -v apt-get &>/dev/null; then
        sudo apt-get install -y libpq-dev postgresql-client build-essential libssl-dev libffi-dev 2>&1 | tail -5
      elif command -v dnf &>/dev/null; then
        sudo dnf install -y postgresql-devel gcc make openssl-devel libffi-devel 2>&1 | tail -5
      elif command -v yum &>/dev/null; then
        sudo yum install -y postgresql-devel gcc make openssl-devel libffi-devel 2>&1 | tail -5
      elif command -v pacman &>/dev/null; then
        sudo pacman -Sy --noconfirm postgresql-libs base-devel 2>&1 | tail -5
      fi
    fi

    local bundle_bin
    bundle_bin=$(command -v bundle 2>/dev/null)
    if [[ -z "$bundle_bin" ]]; then
      gem install bundler --no-document 2>&1 | tail -3
      bundle_bin=$(command -v bundle 2>/dev/null)
    fi

    if [[ -n "$bundle_bin" ]]; then
      info "Running: bundle install (this may take a while) ..."
      (cd "$msf_src" && "$bundle_bin" install 2>&1 | tail -10)
      chmod +x "${msf_src}/msfconsole" 2>/dev/null
      # Symlink to bin/
      ln -sf "${msf_src}/msfconsole" "${SCRIPT_DIR}/bin/msfconsole" 2>/dev/null
      ok "metasploit source setup: ${msf_src}/msfconsole"
      return 0
    fi
  fi

  err "metasploit install failed"
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN INSTALLER LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

banner

# ── Step 1: Check Python ──────────────────────────────────────────────────────
step "Checking Python (3.9+ required)"
PY=$(detect_python)
if [[ -z "$PY" ]]; then
  err "Python 3.9+ not found."
  echo "  Install: https://python.org/downloads"
  exit 1
fi
PY_VER=$($PY --version 2>&1)
ok "Using: $PY ${PY_VER}"

# Check if Python is too new (warning)
PY_MINOR=$($PY -c "import sys; print(sys.version_info.minor)" 2>/dev/null)
if [[ "$PY_MINOR" -ge 13 ]] 2>/dev/null; then
  warn "Python ${PY_VER} detected — some tools (netexec) need Python 3.12 or older"
  info "Will auto-install Python 3.12 as fallback for incompatible tools"
fi

# ── Step 2: Install Python dependencies ───────────────────────────────────────
step "Installing Python dependencies (rich, jinja2, aiofiles)"

# Gunakan virtualenv jika pip terkena PEP 668 (externally managed)
VENV_DIR="${SCRIPT_DIR}/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
  $PY -m venv "$VENV_DIR" 2>/dev/null
  # Linux: jika venv gagal, install python3-venv package
  if [[ ! -d "$VENV_DIR" && "$(uname -s)" == "Linux" ]]; then
    if command -v apt-get &>/dev/null; then
      info "Installing python3-venv (required on Debian/Ubuntu) ..."
      sudo apt-get install -y python3-venv python3-pip 2>&1 | tail -3
      $PY -m venv "$VENV_DIR" 2>/dev/null
    fi
  fi
fi

if [[ -f "${VENV_DIR}/bin/pip" ]]; then
  "${VENV_DIR}/bin/pip" install -r requirements.txt -q 2>&1 | tail -3
  # Also install to main Python for compatibility
  $PY -m pip install -r requirements.txt -q --break-system-packages 2>/dev/null
  ok "Python deps installed (venv + system)"
  # Use venv Python for crushgear
  CRUSHGEAR_PY="${VENV_DIR}/bin/python"
else
  $PY -m pip install -r requirements.txt -q --break-system-packages 2>&1 | tail -3
  ok "Python deps installed"
  CRUSHGEAR_PY="$PY"
fi

# ── Step 3: Pre-install build dependencies ────────────────────────────────────
# All done BEFORE tool installation, so nothing fails mid-way
step "Pre-installing build dependencies"

# Rust (needed for netexec dependencies)
ensure_rust_in_path

# Ruby 3.0+ (needed for metasploit) — only if not --no-msf
if [[ $NO_MSF -eq 0 ]]; then
  ensure_ruby_in_path
fi

# Ensure ~/.local/bin is in PATH (pipx puts things there)
export PATH="$HOME/.local/bin:$PATH"

# ── Step 4: Install tools ────────────────────────────────────────────────────
# IMPORTANT: set +e agar satu tool gagal TIDAK menghentikan yang lain
set +e

if [[ $FIX -eq 1 ]]; then
  # ── FIX MODE ──────────────────────────────────────────────────────────────
  step "FIX MODE — Re-installing only MISSING tools"

  if ! command -v nxc &>/dev/null && ! [[ -x "${SCRIPT_DIR}/bin/nxc" ]]; then
    echo -e "\n  ${YELLOW}━━ netexec (nxc) ━━${NC}"
    install_netexec
  else
    ok "netexec: OK"
  fi

  if [[ $NO_MSF -eq 0 ]]; then
    if ! command -v msfconsole &>/dev/null && ! [[ -x "${SCRIPT_DIR}/bin/msfconsole" ]]; then
      echo -e "\n  ${YELLOW}━━ metasploit (msfconsole) ━━${NC}"
      install_metasploit
    else
      ok "metasploit: OK"
    fi
  fi

  # Rebuild remaining tools that might be missing via setup_tools
  step "Checking other tools via setup_tools.py ..."
  export CRUSHGEAR_PATH="$PATH"
  $PY <<'PYEOF'
import setup_tools, shutil, json, os, pathlib
os.environ['PATH'] = os.environ.get('CRUSHGEAR_PATH', os.environ.get('PATH', ''))
cfg_path = setup_tools.CONFIG_FILE
project_dir = cfg_path.parent
try:
    cfg = json.loads(cfg_path.read_text())
except Exception:
    cfg = {}
bins = cfg.get('binaries', {})
for key, fn in [
    ('nmap', setup_tools.setup_nmap),
    ('smbmap', setup_tools.setup_smbmap),
    ('amass', setup_tools.setup_amass),
    ('httpx', setup_tools.setup_httpx),
    ('nuclei', setup_tools.setup_nuclei),
    ('feroxbuster', setup_tools.setup_feroxbuster),
]:
    existing = bins.get(key, '')
    if existing:
        p = pathlib.Path(existing)
        if not p.is_absolute():
            p = project_dir / p
        if p.exists():
            print(f'  \u2713 {key}: OK ({existing})')
            continue
    if not shutil.which(key):
        print(f'\n\u2500\u2500 {key} ' + '\u2500'*(50-len(key)))
        bins[key] = fn()
    else:
        bins[key] = shutil.which(key)
        print(f'  \u2713 {key}: OK ({bins[key]})')
# Check nxc: prefer bin/nxc (project-local)
nxc_bin = project_dir / 'bin' / 'nxc'
if nxc_bin.exists():
    bins['nxc'] = str(nxc_bin)
elif shutil.which('nxc'):
    bins['nxc'] = shutil.which('nxc')
# Check msfconsole: prefer bin/msfconsole
msf_bin = project_dir / 'bin' / 'msfconsole'
if msf_bin.exists():
    bins['msfconsole'] = str(msf_bin)
elif shutil.which('msfconsole'):
    bins['msfconsole'] = shutil.which('msfconsole')
setup_tools.save_config(bins)
n = sum(1 for v in bins.values() if v)
print(f'\n  {n}/{len(bins)} tools ready')
PYEOF

elif [[ $FULL -eq 1 ]]; then
  # ── FULL MODE ─────────────────────────────────────────────────────────────
  step "FULL MODE — Cloning all tools from GitHub + building from source"
  echo "  This will clone & build:"
  echo "  • metasploit-framework (~1 GB, all exploits/payloads/CVE modules)"
  echo "  • amass, httpx, nuclei    (Go — requires go 1.21+)"
  echo "  • feroxbuster             (Rust — requires rustup/cargo)"
  echo "  • NetExec, smbmap         (Python — pip install -e .)"
  echo "  • nmap                    (system package manager)"
  echo

  SETUP_ARGS="--full"
  [[ $FORCE -eq 1 ]] && SETUP_ARGS="$SETUP_ARGS --force"
  $PY setup_tools.py $SETUP_ARGS

  # Also install netexec via our robust method if missing
  if ! command -v nxc &>/dev/null; then
    install_netexec
  fi

elif [[ $NO_MSF -eq 1 ]]; then
  # ── NO-MSF MODE ───────────────────────────────────────────────────────────
  step "Installing pentest tools (skip metasploit)"
  info "Installing: nmap, netexec, smbmap, amass, httpx, nuclei, feroxbuster"
  echo

  # Install netexec via our robust bash method first
  install_netexec

  # Install the rest via setup_tools.py
  export CRUSHGEAR_PATH="$PATH"
  $PY <<'PYEOF'
import setup_tools, shutil, sys, os, pathlib
os.environ['PATH'] = os.environ.get('CRUSHGEAR_PATH', os.environ.get('PATH', ''))
project_dir = setup_tools.CONFIG_FILE.parent
setup_tools.BIN_DIR.mkdir(exist_ok=True)
binaries = {
    'nmap':        setup_tools.setup_nmap(),
    'nxc':         '',
    'smbmap':      setup_tools.setup_smbmap(),
    'amass':       setup_tools.setup_amass(),
    'httpx':       setup_tools.setup_httpx(),
    'nuclei':      setup_tools.setup_nuclei(),
    'feroxbuster': setup_tools.setup_feroxbuster(),
    'msfconsole':  '',
}
# Prefer project-local bin/nxc
nxc_bin = project_dir / 'bin' / 'nxc'
if nxc_bin.exists():
    binaries['nxc'] = str(nxc_bin)
elif shutil.which('nxc'):
    binaries['nxc'] = shutil.which('nxc')
else:
    binaries['nxc'] = setup_tools.setup_netexec()
setup_tools.save_config(binaries)
n = sum(1 for v in binaries.values() if v)
print(f'  {n}/{len(binaries)} tools ready')
PYEOF

else
  # ── DEFAULT MODE (all tools) ──────────────────────────────────────────────
  step "Installing all pentest tools"
  info "Installing: nmap, netexec, smbmap, amass, httpx, nuclei, feroxbuster, metasploit"
  echo

  # Install netexec via our robust bash method first
  install_netexec

  # Install metasploit via our robust bash method
  install_metasploit

  # Install the rest via setup_tools.py
  export CRUSHGEAR_PATH="$PATH"
  $PY <<'PYEOF'
import setup_tools, shutil, sys, os, pathlib
os.environ['PATH'] = os.environ.get('CRUSHGEAR_PATH', os.environ.get('PATH', ''))
project_dir = setup_tools.CONFIG_FILE.parent
setup_tools.BIN_DIR.mkdir(exist_ok=True)
binaries = {
    'nmap':        setup_tools.setup_nmap(),
    'nxc':         '',
    'smbmap':      setup_tools.setup_smbmap(),
    'amass':       setup_tools.setup_amass(),
    'httpx':       setup_tools.setup_httpx(),
    'nuclei':      setup_tools.setup_nuclei(),
    'feroxbuster': setup_tools.setup_feroxbuster(),
    'msfconsole':  '',
}
# Prefer project-local bin/ paths
for key, name in [('nxc', 'nxc'), ('msfconsole', 'msfconsole')]:
    local_bin = project_dir / 'bin' / name
    if local_bin.exists():
        binaries[key] = str(local_bin)
    elif shutil.which(name):
        binaries[key] = shutil.which(name)
if not binaries['nxc']:
    binaries['nxc'] = setup_tools.setup_netexec()
setup_tools.save_config(binaries)
n = sum(1 for v in binaries.values() if v)
print(f'  {n}/{len(binaries)} tools ready')
PYEOF
fi

# ── Step 5: Download nuclei templates ────────────────────────────────────────
step "Setting up nuclei templates"

NUCLEI_BIN=""
command -v nuclei &>/dev/null       && NUCLEI_BIN=$(command -v nuclei)
[[ -z "$NUCLEI_BIN" && -x "bin/nuclei" ]] && NUCLEI_BIN="$(pwd)/bin/nuclei"

if [[ -n "$NUCLEI_BIN" ]]; then
  # Check if templates already exist with enough files
  NUCLEI_TMPL_COUNT=0
  for tdir in \
    "$HOME/.local/nuclei-templates" \
    "$HOME/nuclei-templates" \
    "/usr/share/nuclei-templates" \
    "/opt/nuclei-templates"; do
    if [[ -d "$tdir" ]]; then
      NUCLEI_TMPL_COUNT=$(find "$tdir" -name "*.yaml" 2>/dev/null | wc -l)
      if [[ "$NUCLEI_TMPL_COUNT" -gt 100 ]]; then
        ok "Nuclei templates: ${NUCLEI_TMPL_COUNT} templates already at $tdir"
        break
      fi
    fi
  done

  if [[ "$NUCLEI_TMPL_COUNT" -le 100 ]]; then
    info "Nuclei templates missing or incomplete — downloading now..."
    info "This may take 3-10 minutes depending on internet speed..."
    "$NUCLEI_BIN" -update-templates 2>&1
    # Recount after download
    NUCLEI_TMPL_COUNT=0
    for tdir in \
      "$HOME/.local/nuclei-templates" \
      "$HOME/nuclei-templates" \
      "/usr/share/nuclei-templates"; do
      if [[ -d "$tdir" ]]; then
        NUCLEI_TMPL_COUNT=$(find "$tdir" -name "*.yaml" 2>/dev/null | wc -l)
        if [[ "$NUCLEI_TMPL_COUNT" -gt 100 ]]; then
          ok "Nuclei templates downloaded: ${NUCLEI_TMPL_COUNT} templates at $tdir"
          break
        fi
      fi
    done
    [[ "$NUCLEI_TMPL_COUNT" -le 100 ]] && err "Nuclei template download failed — check internet connection"
  fi
else
  warn "Nuclei binary not found — skipping template download"
fi

# ── Step 5b: Wordlists — SecLists + bundled fallback ─────────────────────────
step "Setting up wordlists"

SECLISTS_OK=0
SECLISTS_DIR=""

# Check if SecLists already installed
for dir in \
  /usr/share/seclists \
  /usr/share/SecLists \
  /opt/seclists \
  /opt/homebrew/share/seclists; do
  if [[ -d "$dir/Discovery/Web-Content" ]]; then
    SECLISTS_DIR="$dir"
    SECLISTS_OK=1
    ok "SecLists found: $dir"
    break
  fi
done

if [[ $SECLISTS_OK -eq 0 ]]; then
  info "SecLists not found — attempting install..."

  if [[ "$(uname -s)" == "Linux" ]]; then
    # Kali Linux / Debian / Ubuntu
    if command -v apt-get &>/dev/null; then
      sudo apt-get install -y seclists 2>&1 | tail -3
      if [[ -d "/usr/share/seclists" ]]; then
        SECLISTS_DIR="/usr/share/seclists"
        SECLISTS_OK=1
        ok "SecLists installed via apt: /usr/share/seclists"
      else
        # Fallback: git clone SecLists (if apt package not available)
        if command -v git &>/dev/null; then
          info "Cloning SecLists from GitHub (~500MB)..."
          sudo git clone --depth 1 \
            https://github.com/danielmiessler/SecLists.git \
            /usr/share/seclists 2>&1 | tail -5
          [[ -d "/usr/share/seclists" ]] && SECLISTS_DIR="/usr/share/seclists" && SECLISTS_OK=1 && ok "SecLists cloned to /usr/share/seclists"
        fi
      fi
    elif command -v pacman &>/dev/null; then
      # Arch / BlackArch
      sudo pacman -Sy --noconfirm seclists 2>&1 | tail -3
      [[ -d "/usr/share/seclists" ]] && SECLISTS_DIR="/usr/share/seclists" && SECLISTS_OK=1 && ok "SecLists installed via pacman"
    fi

  elif [[ "$(uname -s)" == "Darwin" ]]; then
    # macOS via Homebrew
    if command -v brew &>/dev/null; then
      brew install seclists 2>&1 | tail -5
      for dir in /opt/homebrew/share/seclists /usr/local/share/seclists; do
        [[ -d "$dir/Discovery/Web-Content" ]] && SECLISTS_DIR="$dir" && SECLISTS_OK=1 && ok "SecLists installed: $dir" && break
      done
    fi
  fi
fi

# Always ensure a decent bundled fallback wordlist exists (used when SecLists unavailable)
BUNDLED_WORDLIST="wordlists/common.txt"
BUNDLED_COUNT=$(wc -l < "$BUNDLED_WORDLIST" 2>/dev/null || echo 0)

if [[ "$BUNDLED_COUNT" -lt 4000 ]]; then
  info "Bundled wordlist too small (${BUNDLED_COUNT} lines) — downloading raft-small..."
  # Download raft-small-directories from SecLists GitHub (raw, ~18k lines)
  RAFT_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt"
  if command -v curl &>/dev/null; then
    curl -sL "$RAFT_URL" -o "$BUNDLED_WORDLIST" 2>/dev/null && ok "Bundled wordlist updated ($(wc -l < "$BUNDLED_WORDLIST") lines)" || warn "Bundled wordlist download failed — keeping existing"
  elif command -v wget &>/dev/null; then
    wget -q "$RAFT_URL" -O "$BUNDLED_WORDLIST" 2>/dev/null && ok "Bundled wordlist updated ($(wc -l < "$BUNDLED_WORDLIST") lines)" || warn "Bundled wordlist download failed"
  fi
else
  ok "Bundled wordlist OK (${BUNDLED_COUNT} lines)"
fi

[[ $SECLISTS_OK -eq 0 ]] && warn "SecLists not installed — feroxbuster will use bundled fallback wordlist"

# ── Step 6: Comprehensive Validation ─────────────────────────────────────────
step "Validating all tools & dependencies"
echo

# Helper: find binary (system PATH or project bin/)
_find_bin() {
  local name="$1"
  if command -v "$name" &>/dev/null; then
    command -v "$name"
  elif [[ -x "bin/$name" ]]; then
    echo "$(pwd)/bin/$name"
  else
    echo ""
  fi
}

# Helper: get version string from binary
_get_ver() {
  local bin="$1"; local flag="${2:---version}"
  "$bin" "$flag" 2>&1 | grep -oP 'v?\d+\.\d+[\d.]*' | head -1
}

# Helper: print status row
# _row "TOOL" "STATUS_COLOR" "STATUS_TEXT" "DETAIL"
_row() {
  local tool="$1" color="$2" status="$3" detail="$4"
  printf "  %-14s  ${color}%-10s${NC}  %s\n" "$tool" "$status" "$detail"
}

PASS="${GREEN}"; WARN="${YELLOW}"; FAIL="${RED}"
ALL_OK=1

echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║               CrushGear — Tool Validation Report                ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════════╣${NC}"
echo

# ── 1. nmap ──────────────────────────────────────────────────────────────────
BIN=$(_find_bin nmap)
if [[ -n "$BIN" ]]; then
  VER=$(_get_ver "$BIN" "--version")
  _row "nmap" "$PASS" "OK" "$VER  ($BIN)"
else
  _row "nmap" "$FAIL" "MISSING" "install: apt install nmap"
  ALL_OK=0
fi

# ── 2. amass ─────────────────────────────────────────────────────────────────
BIN=$(_find_bin amass)
if [[ -n "$BIN" ]]; then
  VER=$(_get_ver "$BIN" "-version" 2>/dev/null || _get_ver "$BIN" "--version")
  _row "amass" "$PASS" "OK" "$VER  ($BIN)"
else
  _row "amass" "$WARN" "MISSING" "run: bash install.sh --fix"
  ALL_OK=0
fi

# ── 3. httpx ─────────────────────────────────────────────────────────────────
BIN=$(_find_bin httpx)
if [[ -n "$BIN" ]]; then
  VER=$(_get_ver "$BIN" "-version")
  _row "httpx" "$PASS" "OK" "$VER  ($BIN)"
else
  _row "httpx" "$WARN" "MISSING" "run: bash install.sh --fix"
  ALL_OK=0
fi

# ── 4. netexec (nxc) ─────────────────────────────────────────────────────────
BIN=$(_find_bin nxc)
if [[ -n "$BIN" ]]; then
  VER=$(_get_ver "$BIN" "--version")
  _row "netexec" "$PASS" "OK" "$VER  ($BIN)"
else
  _row "netexec" "$FAIL" "MISSING" "pipx install netexec --python python3.12"
  ALL_OK=0
fi

# ── 5. smbmap ────────────────────────────────────────────────────────────────
BIN=$(_find_bin smbmap)
if [[ -n "$BIN" ]]; then
  VER=$("$BIN" --version 2>&1 | grep -oP 'v?\d+\.\d+[\d.]*' | head -1)
  [[ -z "$VER" ]] && VER="installed"
  _row "smbmap" "$PASS" "OK" "$VER  ($BIN)"
else
  _row "smbmap" "$WARN" "MISSING" "run: bash install.sh --fix"
  ALL_OK=0
fi

# ── 6. nuclei + templates ─────────────────────────────────────────────────────
BIN=""
command -v nuclei &>/dev/null       && BIN=$(command -v nuclei)
[[ -z "$BIN" && -x "bin/nuclei" ]]  && BIN="$(pwd)/bin/nuclei"

if [[ -n "$BIN" ]]; then
  VER=$(_get_ver "$BIN" "-version")
  # Count templates
  TMPL_COUNT=0; TMPL_DIR=""
  for tdir in \
    "$HOME/.local/nuclei-templates" \
    "$HOME/nuclei-templates" \
    "/usr/share/nuclei-templates" \
    "/opt/nuclei-templates"; do
    if [[ -d "$tdir" ]]; then
      CNT=$(find "$tdir" -name "*.yaml" 2>/dev/null | wc -l)
      if [[ "$CNT" -gt "$TMPL_COUNT" ]]; then
        TMPL_COUNT="$CNT"; TMPL_DIR="$tdir"
      fi
    fi
  done

  if [[ "$TMPL_COUNT" -gt 100 ]]; then
    _row "nuclei" "$PASS" "OK" "$VER  |  ${TMPL_COUNT} templates at $TMPL_DIR"
  else
    _row "nuclei" "$WARN" "NO TMPL" "$VER binary OK but templates missing — run: $BIN -update-templates"
    ALL_OK=0
  fi
else
  _row "nuclei" "$FAIL" "MISSING" "run: bash install.sh --fix"
  ALL_OK=0
fi

# ── 7. feroxbuster ───────────────────────────────────────────────────────────
BIN=$(_find_bin feroxbuster)
if [[ -n "$BIN" ]]; then
  VER=$(_get_ver "$BIN" "--version")
  # Find active wordlist
  ACTIVE_WL=""
  for wl in \
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt" \
    "/usr/share/seclists/Discovery/Web-Content/big.txt" \
    "/usr/share/wordlists/dirb/big.txt" \
    "/usr/share/wordlists/dirb/common.txt" \
    "wordlists/common.txt"; do
    if [[ -f "$wl" ]]; then
      WL_LINES=$(wc -l < "$wl" 2>/dev/null)
      ACTIVE_WL="$wl (${WL_LINES} lines)"
      break
    fi
  done
  if [[ -n "$ACTIVE_WL" ]]; then
    _row "feroxbuster" "$PASS" "OK" "$VER  |  wordlist: $ACTIVE_WL"
  else
    _row "feroxbuster" "$WARN" "NO WLIST" "$VER binary OK but no wordlist found — run: apt install seclists"
    ALL_OK=0
  fi
else
  _row "feroxbuster" "$WARN" "MISSING" "run: bash install.sh --fix"
  ALL_OK=0
fi

# ── 8. metasploit ────────────────────────────────────────────────────────────
BIN=""
command -v msfconsole &>/dev/null       && BIN=$(command -v msfconsole)
[[ -z "$BIN" && -x "bin/msfconsole" ]] && BIN="$(pwd)/bin/msfconsole"
if [[ -n "$BIN" ]]; then
  VER=$("$BIN" --version 2>/dev/null | grep -oP 'v?\d+\.\d+[\d.]*' | head -1 || echo "installed")
  _row "metasploit" "$PASS" "OK" "$VER  ($BIN)"
else
  if [[ $NO_MSF -eq 1 ]]; then
    _row "metasploit" "$WARN" "SKIPPED" "skipped via --no-msf flag"
  else
    _row "metasploit" "$WARN" "MISSING" "brew install --cask metasploit  OR  bash install.sh --full"
    ALL_OK=0
  fi
fi

echo
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════════╣${NC}"

# ── SecLists status ───────────────────────────────────────────────────────────
if [[ $SECLISTS_OK -eq 1 ]]; then
  WL_COUNT=$(find "$SECLISTS_DIR/Discovery/Web-Content" -name "*.txt" 2>/dev/null | wc -l)
  _row "seclists" "$PASS" "OK" "${WL_COUNT} wordlists at $SECLISTS_DIR"
else
  _row "seclists" "$WARN" "MISSING" "apt install seclists  (feroxbuster will use bundled fallback)"
fi

# ── Nuclei templates quick summary ───────────────────────────────────────────
FINAL_TMPL=0
for tdir in "$HOME/.local/nuclei-templates" "$HOME/nuclei-templates" "/usr/share/nuclei-templates"; do
  [[ -d "$tdir" ]] && CNT=$(find "$tdir" -name "*.yaml" 2>/dev/null | wc -l) && [[ "$CNT" -gt "$FINAL_TMPL" ]] && FINAL_TMPL="$CNT"
done
if [[ "$FINAL_TMPL" -gt 100 ]]; then
  _row "nuclei-tmpl" "$PASS" "OK" "${FINAL_TMPL} templates ready"
else
  _row "nuclei-tmpl" "$FAIL" "MISSING" "run: $(pwd)/bin/nuclei -update-templates"
  ALL_OK=0
fi

echo
echo -e "${BOLD}╠══════════════════════════════════════════════════════════════════╣${NC}"

# ── Final verdict ─────────────────────────────────────────────────────────────
if [[ $ALL_OK -eq 1 ]]; then
  echo -e "${BOLD}${GREEN}║  RESULT: ALL SYSTEMS GO — CrushGear is ready to run!            ║${NC}"
else
  echo -e "${BOLD}${YELLOW}║  RESULT: Some issues found — see warnings above                  ║${NC}"
  echo -e "${BOLD}${YELLOW}║  Re-run:  bash install.sh --fix                                  ║${NC}"
fi
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"

# ── Done ──────────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║  Installation complete!                                  ║${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}║  Quick start:                                            ║${NC}"
echo -e "${GREEN}║    python3 crushgear.py -t <IP/domain/URL/CIDR>          ║${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}║  Help:                                                   ║${NC}"
echo -e "${GREEN}║    python3 crushgear.py --help-full                      ║${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}║  Update CVE mapping:                                     ║${NC}"
echo -e "${GREEN}║    python3 crushgear.py --update-cves                    ║${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}║  Fix missing tools:                                      ║${NC}"
echo -e "${GREEN}║    bash install.sh --fix                                 ║${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
if [[ $FULL -eq 1 ]]; then
echo -e "${GREEN}║  Full source — all MSF modules active!                   ║${NC}"
echo -e "${GREEN}║    Metasploit: ../metasploit-framework-master/           ║${NC}"
fi
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo
