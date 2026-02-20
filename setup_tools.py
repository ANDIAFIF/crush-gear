"""
CrushGear Setup — Fully Automated, Self-Contained.

Jalankan:  python3 crushgear.py --setup
           ATAU: python3 setup_tools.py
           ATAU: python3 setup_tools.py --full   ← clone semua source dari GitHub

Mode --full:
  • git clone semua 7 repos ke folder parent (../NetExec, ../amass, dll)
  • Build dari source (full features, semua modules/exploits/payloads)
  • Termasuk metasploit framework lengkap dengan semua exploit modules

Mode default:
  1. Sudah ada di PATH            → langsung dipakai
  2. pip install                  → netexec, smbmap
  3. GitHub Releases download     → amass, httpx, nuclei, feroxbuster
  4. System package manager       → nmap (brew/apt/yum/dnf/pacman)
  5. Official installer           → metasploit (Rapid7 script / brew / apt)
  6. Build dari source            → jika folder source sudah ada di parent
"""

import io
import json
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

BASE        = Path(__file__).parent
PARENT      = BASE.parent
BIN_DIR     = BASE / "bin"
CONFIG_FILE = BASE / "config.json"

_OS   = sys.platform
_ARCH = platform.machine().lower()

# ── Source repos mapping ──────────────────────────────────────────────────────
# key = folder name under PARENT, value = GitHub URL
SOURCE_REPOS: dict[str, str] = {
    "NetExec":                      "https://github.com/Pennyw0rth/NetExec.git",
    "smbmap-master":                "https://github.com/ShawnDEvans/smbmap.git",
    "amass":                        "https://github.com/owasp-amass/amass.git",
    "httpx":                        "https://github.com/projectdiscovery/httpx.git",
    "nuclei":                       "https://github.com/projectdiscovery/nuclei.git",
    "feroxbuster":                  "https://github.com/epi052/feroxbuster.git",
    "metasploit-framework-master":  "https://github.com/rapid7/metasploit-framework.git",
}

def _os_tag()   -> str:
    return {"darwin": "macOS", "linux": "linux", "win32": "windows"}.get(_OS, "linux")

def _arch_tag() -> str:
    return "arm64" if _ARCH in ("arm64", "aarch64") else "amd64"

def _bin_ext()  -> str:
    return ".exe" if _OS == "win32" else ""

def _find(name: str) -> str:
    return shutil.which(name) or ""

def _run(cmd: list[str], label: str, cwd: Path = BASE, check_sudo: bool = False) -> bool:
    if check_sudo and _find("sudo"):
        cmd = ["sudo"] + cmd
    print(f"  [{label}] $ {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, cwd=str(cwd))
        ok = r.returncode == 0
        print(f"  [{label}] {'✓ OK' if ok else '✗ FAILED (exit ' + str(r.returncode) + ')'}")
        return ok
    except FileNotFoundError:
        print(f"  [{label}] ✗ Command not found: {cmd[0]}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# GitHub release helpers
# ─────────────────────────────────────────────────────────────────────────────

def _latest_release(repo: str) -> dict:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={"User-Agent": "CrushGear/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"  [github] API error for {repo}: {e}")
        return {}


def _download(url: str, label: str) -> bytes | None:
    filename = url.split("/")[-1]
    print(f"  [{label}] Downloading {filename} ...", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "CrushGear/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            total = int(r.headers.get("Content-Length", 0))
            buf   = b""
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                buf += chunk
                if total:
                    pct = len(buf) * 100 // total
                    print(f"\r  [{label}] {pct:3d}% ({len(buf)//1024} KB)", end="", flush=True)
            print()
            return buf
    except Exception as e:
        print(f"\n  [{label}] ✗ Download error: {e}")
        return None


def _find_asset(assets: list[dict], *keywords: str) -> str:
    kw = [k.lower() for k in keywords]
    for a in assets:
        name = a.get("name", "").lower()
        if all(k in name for k in kw):
            return a.get("browser_download_url", "")
    return ""


def _extract(data: bytes, binary_name: str, dest: Path, is_tar: bool = False) -> bool:
    try:
        if is_tar:
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                for m in tf.getmembers():
                    nm = Path(m.name).name
                    if nm in (binary_name, binary_name + _bin_ext()):
                        f = tf.extractfile(m)
                        if f:
                            dest.write_bytes(f.read())
                            dest.chmod(0o755)
                            return True
        else:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    nm = Path(info.filename).name
                    if nm in (binary_name, binary_name + _bin_ext()):
                        dest.write_bytes(zf.read(info.filename))
                        dest.chmod(0o755)
                        return True
    except Exception as e:
        print(f"  ✗ Extract error: {e}")
    return False


def _install_go_release(
    tool: str,
    repo: str,
    asset_kw: list[str],
    is_tar: bool = False,
    src_dir: str = "",
    src_cmd: str = "",
) -> str:
    dest = BIN_DIR / (tool + _bin_ext())

    # PATH already installed
    path = _find(tool)
    if path:
        print(f"  [{tool}] ✓ Already in PATH: {path}")
        return path

    # Build from source if available
    if src_dir:
        src = PARENT / src_dir
        if src.exists() and _find("go"):
            print(f"  [{tool}] Building from source: {src}")
            ok = _run(["go", "build", "-o", str(dest), src_cmd], tool, cwd=src)
            if ok and dest.exists():
                return str(dest)

    # GitHub release download
    print(f"  [{tool}] Fetching latest from github.com/{repo} ...")
    rel    = _latest_release(repo)
    assets = rel.get("assets", [])
    url    = _find_asset(assets, *asset_kw)

    if not url:
        names = [a["name"] for a in assets[:12]]
        print(f"  [{tool}] ✗ No asset matches {asset_kw}. Available:\n    {names}")
        return ""

    data = _download(url, tool)
    if not data:
        return ""

    is_tar_file = url.endswith(".tar.gz") or url.endswith(".tgz")
    ok = _extract(data, tool + _bin_ext(), dest, is_tar=is_tar_file)
    if ok:
        print(f"  [{tool}] ✓ Installed → {dest}")
        return str(dest)
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Package manager auto-install
# ─────────────────────────────────────────────────────────────────────────────

def _pkg_install(pkg_name: str, label: str) -> bool:
    """Try to install via system package manager. Auto-detects brew/apt/yum/dnf/pacman."""
    if _OS == "darwin":
        if _find("brew"):
            return _run(["brew", "install", pkg_name], label)
        if _find("port"):
            return _run(["sudo", "port", "install", pkg_name], label)

    elif _OS == "linux":
        if _find("apt-get"):
            _run(["apt-get", "update", "-qq"], label, check_sudo=True)
            return _run(["apt-get", "install", "-y", pkg_name], label, check_sudo=True)
        if _find("apt"):
            return _run(["apt", "install", "-y", pkg_name], label, check_sudo=True)
        if _find("dnf"):
            return _run(["dnf", "install", "-y", pkg_name], label, check_sudo=True)
        if _find("yum"):
            return _run(["yum", "install", "-y", pkg_name], label, check_sudo=True)
        if _find("pacman"):
            return _run(["pacman", "-Sy", "--noconfirm", pkg_name], label, check_sudo=True)
        if _find("zypper"):
            return _run(["zypper", "install", "-y", pkg_name], label, check_sudo=True)

    print(f"  [{label}] ✗ No supported package manager found. Install {pkg_name} manually.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Per-tool setup
# ─────────────────────────────────────────────────────────────────────────────

def _ensure_rust() -> bool:
    """Install Rust/cargo jika belum ada (diperlukan untuk beberapa pip deps)."""
    if _find("cargo"):
        return True
    print("  [rust] cargo not found — installing Rust via rustup ...")
    # rustup one-liner
    try:
        req = urllib.request.Request(
            "https://sh.rustup.rs",
            headers={"User-Agent": "CrushGear/1.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            script = r.read()
        script_path = BASE / "_rustup.sh"
        script_path.write_bytes(script)
        script_path.chmod(0o755)
        ok = _run(["bash", str(script_path), "-y", "--no-modify-path"], "rust")
        script_path.unlink(missing_ok=True)
        # Activate cargo in current env
        cargo_bin = Path.home() / ".cargo" / "bin"
        if cargo_bin.exists():
            import os as _os
            _os.environ["PATH"] = str(cargo_bin) + ":" + _os.environ.get("PATH", "")
        return ok and bool(_find("cargo"))
    except Exception as e:
        print(f"  [rust] ✗ rustup install failed: {e}")
        return False


def setup_nmap() -> str:
    path = _find("nmap")
    if path:
        print(f"  [nmap] ✓ Already installed: {path}")
        return path
    print("  [nmap] Not found — installing via package manager ...")
    ok = _pkg_install("nmap", "nmap")
    return _find("nmap") if ok else ""


def setup_netexec() -> str:
    path = _find("nxc")
    if path:
        print(f"  [netexec] ✓ Already in PATH: {path}")
        return path

    # Also check ~/.local/bin (pipx installs here)
    local_nxc = Path.home() / ".local" / "bin" / "nxc"
    if local_nxc.exists():
        print(f"  [netexec] ✓ Found at: {local_nxc}")
        return str(local_nxc)

    # Strategy 1: Build from source if available
    src = PARENT / "NetExec"
    if src.exists():
        print(f"  [netexec] Building from source: {src}")
        ok = _run([sys.executable, "-m", "pip", "install", "-e", ".", "-q"], "netexec", cwd=src)
        path = _find("nxc")
        if path:
            return path
        # Source build failed — try auto-fixing: install Rust then retry
        print("  [netexec] Source build failed — auto-fix: installing Rust compiler ...")
        if _ensure_rust():
            print("  [netexec] Retrying build with Rust ...")
            ok = _run([sys.executable, "-m", "pip", "install", "-e", ".", "-q"], "netexec", cwd=src)
            path = _find("nxc")
            if path:
                return path
        # Still failed → fallback to PyPI
        print("  [netexec] Source build failed — falling back to PyPI ...")

    # Strategy 2: pipx install (clean isolation, no conflict)
    if _find("pipx"):
        print("  [netexec] Installing via pipx (isolated env) ...")
        ok = _run(["pipx", "install", "netexec"], "netexec")
        path = _find("nxc")
        if not path and local_nxc.exists():
            path = str(local_nxc)
        if path:
            return path
        print("  [netexec] pipx install failed — trying pip ...")

    # Strategy 3: pip install (ensure Rust is available first)
    if not _find("cargo"):
        print("  [netexec] Rust compiler needed for some deps — installing ...")
        _ensure_rust()

    print("  [netexec] Installing via pip (netexec from PyPI) ...")
    ok = _run([sys.executable, "-m", "pip", "install", "netexec"], "netexec")
    path = _find("nxc")
    if path:
        return path

    # Strategy 4: pip install with --break-system-packages
    if not path:
        print("  [netexec] Retrying pip with --break-system-packages ...")
        ok = _run([sys.executable, "-m", "pip", "install", "netexec",
                   "--break-system-packages"], "netexec")
        path = _find("nxc")
        if not path and local_nxc.exists():
            path = str(local_nxc)

    return path or ""


def setup_smbmap() -> str:
    path = _find("smbmap")
    if path:
        print(f"  [smbmap] ✓ Already in PATH: {path}")
        return path
    src = PARENT / "smbmap-master"
    if src.exists():
        print(f"  [smbmap] Building from source: {src}")
        ok = _run([sys.executable, "-m", "pip", "install", "-e", ".", "-q"], "smbmap", cwd=src)
        return _find("smbmap") if ok else ""
    print("  [smbmap] Installing via pip ...")
    ok = _run([sys.executable, "-m", "pip", "install", "smbmap", "-q"], "smbmap")
    return _find("smbmap") if ok else ""


def setup_amass() -> str:
    # amass releases use 'darwin' not 'macos' in asset names
    os_kw = "darwin" if _OS == "darwin" else ("windows" if _OS == "win32" else "linux")
    return _install_go_release(
        "amass", "owasp-amass/amass",
        asset_kw=[os_kw, _arch_tag()],
        src_dir="amass", src_cmd="./cmd/amass/",
    )


def setup_httpx() -> str:
    return _install_go_release(
        "httpx", "projectdiscovery/httpx",
        asset_kw=[_os_tag().lower(), _arch_tag()],
        src_dir="httpx", src_cmd="./cmd/httpx/",
    )


def setup_nuclei() -> str:
    return _install_go_release(
        "nuclei", "projectdiscovery/nuclei",
        asset_kw=[_os_tag().lower(), _arch_tag()],
        src_dir="nuclei", src_cmd="./cmd/nuclei/",
    )


def setup_feroxbuster() -> str:
    path = _find("feroxbuster")
    if path:
        print(f"  [feroxbuster] ✓ Already in PATH: {path}")
        return path

    dest = BIN_DIR / ("feroxbuster" + _bin_ext())

    # Source build
    src = PARENT / "feroxbuster"
    if src.exists() and _find("cargo"):
        print(f"  [feroxbuster] Building from source: {src}")
        ok = _run(["cargo", "build", "--release"], "feroxbuster", cwd=src)
        if ok:
            rb = src / "target" / "release" / ("feroxbuster" + _bin_ext())
            if rb.exists():
                shutil.copy2(str(rb), str(dest))
                dest.chmod(0o755)
                print(f"  [feroxbuster] ✓ Installed → {dest}")
                return str(dest)

    # GitHub release
    print("  [feroxbuster] Fetching latest from github.com/epi052/feroxbuster ...")
    rel    = _latest_release("epi052/feroxbuster")
    assets = rel.get("assets", [])
    arch_m = {"x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}
    arch   = arch_m.get(_ARCH, "x86_64")

    url = ""
    if _OS == "darwin":
        url = _find_asset(assets, arch, "apple-darwin")
        if not url:
            url = _find_asset(assets, "macos") or _find_asset(assets, "darwin")
    elif _OS == "linux":
        url = _find_asset(assets, arch, "linux")
        if not url:
            url = _find_asset(assets, "linux", "musl") or _find_asset(assets, "linux")
    elif _OS == "win32":
        url = _find_asset(assets, "windows", ".exe") or _find_asset(assets, ".zip", "windows")

    if not url:
        print(f"  [feroxbuster] ✗ No matching asset. Available: {[a['name'] for a in assets[:8]]}")
        return ""

    data = _download(url, "feroxbuster")
    if not data:
        return ""

    is_tar = url.endswith(".tar.gz") or url.endswith(".tgz")
    is_zip = url.endswith(".zip")
    if is_tar or is_zip:
        ok = _extract(data, "feroxbuster" + _bin_ext(), dest, is_tar=is_tar)
    else:
        dest.write_bytes(data)
        dest.chmod(0o755)
        ok = True

    if ok:
        print(f"  [feroxbuster] ✓ Installed → {dest}")
        return str(dest)
    return ""


def setup_metasploit() -> str:
    # Check common install locations first
    path = _find("msfconsole")
    if not path:
        # Check common metasploit install paths
        for msf_dir in [
            "/opt/metasploit-framework/bin",
            "/usr/local/bin",
            "/opt/homebrew/bin",
            str(PARENT / "metasploit-framework-master"),
        ]:
            candidate = Path(msf_dir) / "msfconsole"
            if candidate.exists():
                path = str(candidate)
                # Add to PATH so future lookups work
                import os as _os
                _os.environ["PATH"] = msf_dir + ":" + _os.environ.get("PATH", "")
                break

    if path:
        print(f"  [metasploit] ✓ Already installed: {path}")
        return path

    # Source build (requires Ruby 3.0+ and bundler)
    src = PARENT / "metasploit-framework-master"
    if src.exists():
        # Find Ruby 3.0+ (important: macOS system Ruby is 2.6, too old)
        ruby_bin, bundle_bin = _find_ruby3()
        if ruby_bin and bundle_bin:
            print(f"  [metasploit] Installing from source: {src}")
            print(f"  [metasploit] Using Ruby: {ruby_bin}, Bundle: {bundle_bin}")
            ok = _run([bundle_bin, "install"], "metasploit", cwd=src)
            if ok:
                msf = src / "msfconsole"
                if msf.exists():
                    msf.chmod(0o755)
                    return str(msf)
        elif ruby_bin:
            # Ruby found but no bundler — install it
            gem_bin = str(Path(ruby_bin).parent / "gem")
            if Path(gem_bin).exists():
                _run([gem_bin, "install", "bundler", "--no-document"], "bundler")
                bundle_bin = str(Path(ruby_bin).parent / "bundle")
                if Path(bundle_bin).exists():
                    ok = _run([bundle_bin, "install"], "metasploit", cwd=src)
                    if ok:
                        msf = src / "msfconsole"
                        if msf.exists():
                            msf.chmod(0o755)
                            return str(msf)
        # Source exists but couldn't build — continue to package manager
        print(f"  [metasploit] Source build skipped/failed (Ruby 3.0+ or bundler missing)")

    print("  [metasploit] Not found — installing via package manager ...")

    if _OS == "darwin":
        if _find("brew"):
            ok = _run(["brew", "install", "--cask", "metasploit"], "metasploit")
            if ok:
                # brew --cask installs to /opt/metasploit-framework/bin/
                for msf_dir in [
                    "/opt/metasploit-framework/bin",
                    "/opt/homebrew/bin",
                    "/usr/local/bin",
                ]:
                    if Path(msf_dir, "msfconsole").exists():
                        import os as _os
                        _os.environ["PATH"] = msf_dir + ":" + _os.environ.get("PATH", "")
                        print(f"  [metasploit] ✓ Installed at: {msf_dir}/msfconsole")
                        return str(Path(msf_dir) / "msfconsole")
                return _find("msfconsole")

    elif _OS == "linux":
        # Official Rapid7 apt repo (Debian/Ubuntu/Kali)
        if _find("apt-get") or _find("apt"):
            print("  [metasploit] Adding Rapid7 apt repository ...")
            cmds = [
                # Download GPG key
                ["bash", "-c",
                 "curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg"
                 " | sudo gpg --dearmor -o /usr/share/keyrings/metasploit.gpg"],
                # Add repo
                ["bash", "-c",
                 'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/metasploit.gpg]'
                 ' https://apt.metasploit.com/ bullseye main"'
                 " | sudo tee /etc/apt/sources.list.d/metasploit.list"],
                ["sudo", "apt-get", "update", "-qq"],
                ["sudo", "apt-get", "install", "-y", "metasploit-framework"],
            ]
            for cmd in cmds:
                if not _run(cmd, "metasploit"):
                    break
            path = _find("msfconsole")
            if path:
                return path

        # Fallback: official omnibus installer
        print("  [metasploit] Trying Rapid7 omnibus installer ...")
        data = _download(
            "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master"
            "/config/templates/metasploit-framework-wrappers/msfupdate.erb",
            "metasploit-installer",
        )
        if data:
            script = BASE / "_msf_install.rb"
            script.write_bytes(data)
            _run(["sudo", "ruby", str(script)], "metasploit")
            script.unlink(missing_ok=True)

    return _find("msfconsole")


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

def save_config(binaries: dict):
    try:
        cfg = json.loads(CONFIG_FILE.read_text())
    except Exception:
        cfg = {}

    # Convert paths inside project dir to relative paths (portable)
    portable_binaries = {}
    for key, path in binaries.items():
        if path:
            p = Path(path)
            try:
                rel = p.resolve().relative_to(BASE.resolve())
                portable_binaries[key] = str(rel)
            except ValueError:
                # Path is outside project dir (system tool) — keep absolute
                portable_binaries[key] = path
        else:
            portable_binaries[key] = ""

    cfg["binaries"] = portable_binaries
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Source clone (--full mode)
# ─────────────────────────────────────────────────────────────────────────────

def clone_sources(force: bool = False) -> dict[str, bool]:
    """
    git clone semua tool repos ke PARENT directory.
    Jika folder sudah ada dan tidak --force, lakukan git pull saja.
    Returns: {folder_name: success}
    """
    if not _find("git"):
        print("  [clone] ✗ git not found. Install git first.")
        return {k: False for k in SOURCE_REPOS}

    results: dict[str, bool] = {}
    for folder, url in SOURCE_REPOS.items():
        dest   = PARENT / folder
        tool   = folder.lower()
        is_git = (dest / ".git").exists()

        if dest.exists() and not force:
            if is_git:
                print(f"\n  [{tool}] Folder exists — git pull (update) ...")
                ok = _run(["git", "pull", "--rebase", "--autostash"], tool, cwd=dest)
            else:
                # Folder ada tapi bukan git repo (manual copy) — skip, suggest --force
                print(f"\n  [{tool}] Folder exists but is NOT a git repo (manual copy).")
                print(f"  [{tool}] Run with --force to delete & re-clone from GitHub.")
                ok = False
        else:
            if dest.exists() and force:
                import shutil as _shutil
                print(f"\n  [{tool}] Removing existing folder (--force) ...")
                _shutil.rmtree(str(dest))
            print(f"\n  [{tool}] Cloning {url} ...")
            ok = _run(["git", "clone", "--depth=1", url, str(dest)], tool)
        results[folder] = ok

    return results


def _find_ruby3() -> tuple[str, str]:
    """
    Cari Ruby 3.0+ dan bundle binary yang matching.
    Returns: (ruby_path, bundle_path) — kosong jika tidak ketemu.
    """
    candidates: list[Path] = []

    # Brew-installed Ruby (macOS)
    if _OS == "darwin":
        for prefix in ["/opt/homebrew/opt/ruby/bin", "/usr/local/opt/ruby/bin"]:
            p = Path(prefix)
            if p.exists():
                candidates.append(p)

    # rbenv / rvm shims
    for shim_dir in [Path.home() / ".rbenv" / "shims", Path.home() / ".rvm" / "bin"]:
        if shim_dir.exists():
            candidates.append(shim_dir)

    # System PATH candidates with version check
    for name in ["ruby3.3", "ruby3.2", "ruby3.1", "ruby3.0", "ruby"]:
        p = shutil.which(name)
        if p:
            candidates.append(Path(p).parent)

    seen: set[str] = set()
    for d in candidates:
        ruby = d / "ruby"
        if not ruby.exists():
            ruby = Path(shutil.which("ruby") or "") if str(d) in (shutil.which("ruby") or "") else Path("")
        # Re-search in directory
        for rname in ["ruby3.3", "ruby3.2", "ruby3.1", "ruby3.0", "ruby"]:
            r = d / rname
            if not r.exists():
                continue
            key = str(r)
            if key in seen:
                continue
            seen.add(key)
            try:
                res = subprocess.run([str(r), "--version"], capture_output=True, text=True, timeout=5)
                ver_str = res.stdout.split()[1] if res.stdout.split() else "0"
                major = int(ver_str.split(".")[0])
                if major >= 3:
                    bundle = d / "bundle"
                    if not bundle.exists():
                        bundle = d / "bundler"
                    return str(r), str(bundle) if bundle.exists() else ""
            except Exception:
                continue

    return "", ""


def install_metasploit_deps() -> bool:
    """
    Install Ruby 3.0+ + bundler deps untuk metasploit dari source.
    """
    src = PARENT / "metasploit-framework-master"
    if not src.exists():
        print("  [metasploit] Source not found, clone first with --full")
        return False

    # Cari Ruby 3.0+
    ruby_bin, bundle_bin = _find_ruby3()

    if not ruby_bin:
        print("  [metasploit] Ruby 3.0+ not found — installing ...")
        if _OS == "darwin":
            _pkg_install("ruby", "ruby")
            # Brew installs ruby to /opt/homebrew/opt/ruby/bin
            for prefix in ["/opt/homebrew/opt/ruby/bin", "/usr/local/opt/ruby/bin"]:
                r = Path(prefix) / "ruby"
                if r.exists():
                    ruby_bin = str(r)
                    bundle_bin = str(Path(prefix) / "bundle")
                    break
        elif _OS == "linux":
            _pkg_install("ruby-full", "ruby")
            _pkg_install("ruby-bundler", "bundler")
        ruby_bin, bundle_bin = _find_ruby3()

    if not ruby_bin:
        print("  [metasploit] ✗ Ruby 3.0+ not found. Install manually: brew install ruby")
        return False

    print(f"  [metasploit] Using Ruby: {ruby_bin}")

    # Cari / install bundler
    if not bundle_bin or not Path(bundle_bin).exists():
        bundle_bin = shutil.which("bundle") or shutil.which("bundler") or ""

    if not bundle_bin:
        print("  [metasploit] Installing bundler ...")
        gem_bin = str(Path(ruby_bin).parent / "gem")
        if not Path(gem_bin).exists():
            gem_bin = shutil.which("gem") or "gem"
        _run([gem_bin, "install", "bundler", "--no-document"], "bundler")
        bundle_bin = str(Path(ruby_bin).parent / "bundle") or shutil.which("bundle") or "bundle"

    print(f"  [metasploit] Using bundle: {bundle_bin}")
    print("  [metasploit] Running bundle install (this may take a while) ...")

    ok = _run([bundle_bin, "install"], "metasploit", cwd=src)
    if ok:
        msf_bin = src / "msfconsole"
        if msf_bin.exists():
            msf_bin.chmod(0o755)
            link = BIN_DIR / "msfconsole"
            if not link.exists():
                try:
                    link.symlink_to(msf_bin)
                except Exception:
                    pass
            return True
    return False


def main():
    import argparse as _argparse
    p = _argparse.ArgumentParser(description="CrushGear Setup")
    p.add_argument("--full",  action="store_true",
                   help="Clone semua source dari GitHub lalu build (full features)")
    p.add_argument("--force", action="store_true",
                   help="Re-clone semua (hapus folder lama)")
    p.add_argument("--clone-only", action="store_true",
                   help="Hanya clone source, tidak build/install")
    args = p.parse_args()

    BIN_DIR.mkdir(exist_ok=True)

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          CrushGear — Automated Tool Setup                ║")
    print(f"║  Platform: {_os_tag():<10}  Arch: {_arch_tag():<8}                    ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    # ── Full mode: git clone ALL sources then build ───────────────────────────
    if args.full or args.clone_only:
        print()
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  FULL MODE — Cloning all tool sources from GitHub")
        print("  This includes metasploit-framework (~1 GB), amass, httpx,")
        print("  nuclei, feroxbuster, NetExec, smbmap with ALL modules.")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print()

        clone_results = clone_sources(force=args.force)

        print()
        print("── Clone summary " + "─" * 44)
        for folder, ok in clone_results.items():
            mark = "✓" if ok else "✗"
            print(f"  {mark} {folder}")
        cloned = sum(clone_results.values())
        failed_non_git = [f for f, ok in clone_results.items()
                          if not ok and (PARENT / f).exists() and not (PARENT / f / ".git").exists()]
        if failed_non_git:
            print()
            print("  ⚠ Some folders exist but are not git repos (manually placed):")
            for f in failed_non_git:
                print(f"    • {f}")
            print("  → Run with --force to delete & re-clone: python3 setup_tools.py --full --force")
        print(f"\n  {cloned}/{len(clone_results)} repos cloned/updated.")

        if args.clone_only:
            print()
            print("  --clone-only: skipping build. Run setup_tools.py to build.")
            print()
            return

        print()
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  Building tools from source ...")
        print("  (Go required for amass/httpx/nuclei, Rust for feroxbuster,")
        print("   Ruby+bundler for metasploit)")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        # ── Pre-install build deps untuk --full ───────────────────────────────
        # Install Rust jika belum ada (netexec deps butuh cargo)
        if not _find("cargo"):
            print("\n── rust (build dep) " + "─" * 41)
            _ensure_rust()
        # Install Ruby 3.0+ jika belum ada (metasploit butuh ruby 3+)
        ruby_bin, _ = _find_ruby3()
        if not ruby_bin:
            print("\n── ruby 3.0+ (build dep) " + "─" * 37)
            print("  Installing Ruby 3.0+ via package manager ...")
            if _OS == "darwin":
                _pkg_install("ruby", "ruby")
            elif _OS == "linux":
                _pkg_install("ruby-full", "ruby")

    # ── Install / build each tool ─────────────────────────────────────────────
    steps = [
        ("nmap",        setup_nmap),
        ("nxc",         setup_netexec),
        ("smbmap",      setup_smbmap),
        ("amass",       setup_amass),
        ("httpx",       setup_httpx),
        ("nuclei",      setup_nuclei),
        ("feroxbuster", setup_feroxbuster),
        ("msfconsole",  setup_metasploit),
    ]

    binaries: dict[str, str] = {}
    for key, fn in steps:
        print(f"\n── {key} {'─'*(50-len(key))}")
        binaries[key] = fn()

    # ── Full mode: install metasploit Ruby deps ───────────────────────────────
    if args.full and not binaries.get("msfconsole"):
        print("\n── metasploit deps " + "─" * 42)
        print("  Installing Ruby dependencies for metasploit source build ...")
        ok = install_metasploit_deps()
        if ok:
            binaries["msfconsole"] = str(PARENT / "metasploit-framework-master" / "msfconsole")
            print("  [metasploit] ✓ Bundle install complete")
        else:
            print("  [metasploit] ✗ bundle install failed (Ruby/bundler required)")

    # ── Full mode: update nuclei templates ───────────────────────────────────
    if args.full:
        nuclei_bin = binaries.get("nuclei") or _find("nuclei")
        if nuclei_bin:
            print("\n── nuclei templates " + "─" * 41)
            print("  Updating nuclei templates (full CVE coverage) ...")
            _run([nuclei_bin, "-update-templates", "-silent"], "nuclei-templates")

    save_config(binaries)

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  Setup Result                                            ║")
    print("╠══════════════════════════════════════════════════════════╣")
    ok_count = 0
    for key, path in binaries.items():
        status = "✓ OK     " if path else "✗ MISSING"
        short  = path[-45:] if path and len(path) > 45 else (path or "-")
        print(f"║  {key:<14}  {status}  {short:<27}║")
        if path:
            ok_count += 1
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  {ok_count}/{len(binaries)} tools ready                                       ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    if ok_count == len(binaries):
        print("  ✓ All tools installed! Run: python3 crushgear.py -t <target>")
    else:
        missing = [k for k, v in binaries.items() if not v]
        print(f"  ✗ Missing: {', '.join(missing)}")
        print("  Try: python3 setup_tools.py --full   (full source clone + build)")
        print("  Or:  python3 crushgear.py --check    (see details)")
    print()


if __name__ == "__main__":
    main()
