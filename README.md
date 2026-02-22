# CrushGear — All-in-One Pentest Automation

```
  ██████╗██████╗ ██╗   ██╗███████╗██╗  ██╗ ██████╗ ███████╗ █████╗ ██████╗
 ██╔════╝██╔══██╗██║   ██║██╔════╝██║  ██║██╔════╝ ██╔════╝██╔══██╗██╔══██╗
 ██║     ██████╔╝██║   ██║███████╗███████║██║  ███╗█████╗  ███████║██████╔╝
 ██║     ██╔══██╗██║   ██║╚════██║██╔══██║██║   ██║██╔══╝  ██╔══██║██╔══██╗
 ╚██████╗██║  ██║╚██████╔╝███████║██║  ██║╚██████╔╝███████╗██║  ██║██║  ██║
  ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

> All-in-One Pentest Automation: nmap (2-phase) → amass + httpx → netexec + smbmap + nuclei + feroxbuster → metasploit

---

## Instalasi

### Mode 1 — Default (Pre-built binaries, Recommended)

```bash
cd tools-crushgear

# Jalankan installer — otomatis download pre-built binaries semua tools
bash install.sh
```

Selesai. Tidak perlu install apa-apa manual.

### Mode 2 — UPDATE (Aman, tanpa hapus folder)

> Gunakan ini untuk memperbarui semua tools yang sudah ter-install.
> **Tidak menghapus** folder git clone apapun.

```bash
cd tools-crushgear

# Update semua: git pull source repos + update CVE mapping + update nuclei templates
bash install.sh --update
```

Ini akan:
- `git pull` semua source repo yang sudah di-clone (NetExec, amass, httpx, dll)
- Update CVE → Metasploit mapping dari GitHub
- Update nuclei templates (CVE templates terbaru)

### Mode 3 — FULL SOURCE (Metasploit + semua tools dari source)

> **Gunakan ini untuk metasploit lengkap** dengan semua exploit modules, payloads, CVE scanners, dll.
> Butuh ~2-5 GB disk, Go 1.21+, Rust/cargo, Ruby 3.0+, git.

```bash
cd tools-crushgear

# Clone & build SEMUA dari GitHub source (git pull jika folder sudah ada)
bash install.sh --full
```

> ⚠️  **PERINGATAN — `--force` menghapus folder!**
> ```bash
> bash install.sh --full --force   # ← HAPUS semua folder git clone, lalu re-clone dari awal
> ```
> Gunakan `--force` hanya jika folder corrupt atau ingin full re-clone.
> Untuk update rutin, gunakan `bash install.sh --update` saja.

Ini akan:
- `git clone` metasploit-framework (semua exploit modules, payloads, post modules)
- `git clone` amass, httpx, nuclei, feroxbuster, NetExec, smbmap
- Build semua dari source (Go / Rust / Ruby bundle install)
- Update nuclei templates (semua CVE templates terbaru)

### Mode 4 — Manual step by step

```bash
cd tools-crushgear

# Step 1: Install Python deps
pip install -r requirements.txt

# Step 2: Auto-install semua pentest tools (pre-built)
python3 crushgear.py --setup

# ATAU full source (build dari GitHub)
python3 setup_tools.py --full

# Step 3: Verify
python3 crushgear.py --check
```

### Mode 5 — Fix missing tools only

Jika ada tools yang MISSING setelah install, jalankan:

```bash
bash install.sh --fix
```

Ini hanya akan re-install tools yang belum ter-install (netexec, metasploit, dll) tanpa menyentuh tools yang sudah OK.

### Skip metasploit (opsional, lebih cepat)

```bash
bash install.sh --no-msf
# atau
python3 crushgear.py --tools nmap,amass,httpx,netexec,smbmap,nuclei,feroxbuster -t <target>
```

---

## Requirements

### Mode Default

| Requirement | Versi Minimum | Notes |
|-------------|--------------|-------|
| Python | 3.9+ | Wajib |
| pip | latest | Wajib |
| Internet | — | Untuk download tools & update CVE |
| sudo/admin | — | Untuk install nmap & metasploit |

### Mode Full Source (--full)

| Requirement | Versi Minimum | Notes |
|-------------|--------------|-------|
| Python | 3.9+ | Wajib |
| git | latest | Clone repos |
| go | 1.21+ | Build amass, httpx, nuclei |
| cargo (Rust) | 1.70+ | Build feroxbuster |
| ruby | 3.0+ | Build metasploit |
| bundler | 2.0+ | Install MSF Ruby gems |
| Disk space | ~5 GB | metasploit ~1.5GB, semua tools |

Tools yang di-install:

| Tool | Mode Default | Mode --full | Fungsi |
|------|-------------|-------------|--------|
| nmap | brew/apt/yum | brew/apt/yum | Port scan |
| netexec | pip install | build dari source | SMB/SSH/LDAP enum |
| smbmap | pip install | build dari source | SMB share enum |
| amass | GitHub Release | `go build` dari source | Subdomain recon |
| httpx | GitHub Release | `go build` dari source | HTTP probing |
| nuclei | GitHub Release | `go build` dari source | Vuln scanner (semua CVE templates) |
| feroxbuster | GitHub Release | `cargo build` dari source | Dir bruteforce |
| metasploit | Rapid7 installer/brew | `git clone` + `bundle install` | Exploitation (ALL modules) |

---

## Penggunaan

### Scan basic

```bash
# Target IP
python3 crushgear.py -t 192.168.1.1

# Target domain
python3 crushgear.py -t example.com

# Target URL
python3 crushgear.py -t http://target.com

# Target network range
python3 crushgear.py -t 192.168.1.0/24
```

### Dengan kredensial (SMB/NetExec)

```bash
python3 crushgear.py -t 192.168.1.1 -u admin -p password123
python3 crushgear.py -t 10.0.0.0/24 -u administrator -p "P@ssw0rd!"
```

### Custom tools (tidak perlu semua)

```bash
# Hanya recon
python3 crushgear.py -t example.com --tools amass,httpx

# Hanya scan vuln
python3 crushgear.py -t http://target.com --tools nuclei,feroxbuster

# Tanpa metasploit
python3 crushgear.py -t 192.168.1.0/24 --tools nmap,amass,httpx,netexec,smbmap,nuclei,feroxbuster
```

### Custom LHOST/LPORT (reverse shell untuk metasploit)

```bash
# Auto-detect local IP (default)
python3 crushgear.py -t 192.168.1.1

# Manual set
python3 crushgear.py -t 192.168.1.1 --lhost 10.0.0.99 --lport 9001
```

---

## Alur Eksekusi (4 Fase)

```
Target Input
    │
    ▼
┌──────────────────────────────────────────────────────────┐
│  PHASE 0 — Port Scan (2-Phase)                           │
│  Step 1: nmap -p- --min-rate 2000 (fast SYN all 65535)  │
│  Step 2: nmap -sV -sC -O pada port yang ditemukan saja  │
│  → Output: port list, services, OS, product banners     │
└─────────────────────┬────────────────────────────────────┘
                      │ FEED: open ports per host
                      ▼
┌──────────────────────────────────────────────────────────┐
│  PHASE 1 — Reconnaissance (paralel)                      │
│  amass  → subdomain / DNS enumeration                    │
│  httpx  → probe web services di port yang nmap temukan   │
│  → Output: host list, live URLs                          │
└─────────────────────┬────────────────────────────────────┘
                      │ FEED: hosts (amass) + live URLs (httpx)
                      ▼
┌──────────────────────────────────────────────────────────┐
│  PHASE 2 — Scanning & Enumeration (paralel)              │
│  netexec    ← SMB/SSH hosts dari amass + nmap port 445   │
│  smbmap     ← SMB hosts                                  │
│  nuclei     ← live URLs dari httpx                       │
│  feroxbuster← live URLs dari httpx                       │
│  → Output: shares, users, CVEs found, directories        │
└─────────────────────┬────────────────────────────────────┘
                      │ FEED: CVE findings dari nuclei
                      ▼
┌──────────────────────────────────────────────────────────┐
│  PHASE 3 — Exploitation                                  │
│  metasploit ← auto-pilih module dari CVE findings        │
│    CVE-2017-0144 → ms17_010_eternalblue                  │
│    CVE-2021-44228 → log4shell_header_injection (misc/)   │
│    CVE-2021-26855 → exchange_proxylogon_rce              │
│    ... 188 CVEs mapped statik, + auto-discovered         │
│  → Auto post-exploit: hashdump, cred dump, enum users    │
└──────────────────────────────────────────────────────────┘
```

---

## Output Files

Semua hasil disimpan di `results/{target}_{timestamp}/`:

```
results/
└── 192_168_1_1_20260221_143022/
    ├── nmap.txt          ← port scan results (grepable format)
    ├── amass.txt         ← discovered subdomains/hosts
    ├── httpx.json        ← live URLs + title + tech stack
    ├── netexec.txt       ← SMB enum results
    ├── smbmap.txt        ← share listing + permissions
    ├── nuclei.json       ← vulnerability findings
    ├── feroxbuster.txt   ← discovered directories
    └── metasploit.txt    ← exploit output + post-exploit
```

---

## Management Commands

### Update (Aman — tidak hapus folder)

```bash
# ✅ UPDATE SEMUA SEKALIGUS (recommended cara update rutin)
# git pull source repos + update CVE mapping + update nuclei templates
bash install.sh --update

# Atau update satu per satu:

# Update CVE → Metasploit mapping (dari GitHub)
python3 crushgear.py --update-cves

# Update dengan GitHub token (rate limit lebih tinggi)
python3 crushgear.py --update-cves --github-token ghp_xxxxx

# git pull semua source repos saja
python3 crushgear.py --update-tools

# Update CrushGear script itu sendiri
python3 crushgear.py --update-script
```

### Diagnostik & Repair

```bash
# Lihat status semua binary
python3 crushgear.py --check

# Bandingkan versi installed vs GitHub latest
python3 crushgear.py --check-updates

# Re-install hanya tools yang MISSING (tidak menyentuh yang sudah OK)
bash install.sh --fix

# Reinstall/rebuild semua tools (pre-built binaries)
python3 crushgear.py --setup

# Help lengkap
python3 crushgear.py --help-full
```

### Re-clone (Gunakan hanya jika diperlukan)

> ⚠️  **Perintah di bawah ini MENGHAPUS folder git clone secara permanen!**
> Gunakan hanya jika folder corrupt, bukan untuk update rutin.

```bash
# Re-clone full source dari awal (HAPUS folder lama)
bash install.sh --full --force

# ATAU langsung via Python
python3 setup_tools.py --full --force
```

---

## CVE → Metasploit Mapping

CrushGear memiliki database CVE → MSF module:

| Kategori | CVEs Ter-cover |
|----------|----------------|
| Windows SMB (EternalBlue, MS08-067, dll) | 7 |
| Active Directory (ZeroLogon, PrintNightmare, dll) | 5 |
| Exchange (ProxyLogon, ProxyShell, ProxyNotShell) | 9 |
| Log4Shell | 4 |
| Spring Framework | 3 |
| Confluence | 5 |
| Apache HTTP / Struts | 9 |
| VMware vCenter / ESXi | 6 |
| Citrix / NetScaler | 5 |
| F5 BIG-IP | 5 |
| Fortinet | 5 |
| Pulse Secure / Ivanti | 6 |
| GitLab | 3 |
| PHP | 3 |
| WebLogic | 5 |
| Drupal | 3 |
| Redis, Elasticsearch | 3 |
| RDP (BlueKeep, DejaBlue) | 3 |
| ProFTPD / VSFTPD / SSH | 5 |
| Exim SMTP | 2 |
| JetBrains TeamCity | 3 |
| ConnectWise ScreenConnect | 2 |
| 2024–2025 CVEs (PAN-OS, Jenkins, PHP CGI, dll) | 10+ |
| + banyak lagi... | **188 static** + auto-discovered |

### Update CVE mapping

```bash
# Update CVE mapping + nuclei templates sekaligus
bash install.sh --update

# Atau hanya update CVE mapping
python3 crushgear.py --update-cves

# Output:
#   Static CVEs:    188
#   Discovered CVEs: 43  (+43 new)
#   Total coverage: 231 CVEs → MSF modules
```

---

## Troubleshooting

### Tool tidak ditemukan setelah `--setup`

```bash
# Lihat detail
python3 crushgear.py --check

# Re-run hanya tools yang MISSING
bash install.sh --fix

# Re-run setup penuh
python3 crushgear.py --setup

# Install manual (contoh httpx)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### NetExec: pip install gagal

NetExec membutuhkan **Rust compiler** untuk beberapa dependency-nya:

```bash
# Install Rust dulu
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Lalu install netexec
pipx install netexec
# atau
pip3 install netexec
```

### Metasploit: Ruby version terlalu lama (macOS)

macOS bawaan Ruby 2.6 — Metasploit butuh Ruby 3.0+:

```bash
# Install Ruby terbaru via Homebrew
brew install ruby

# Tambahkan ke PATH
export PATH="/opt/homebrew/opt/ruby/bin:$PATH"

# Install metasploit
brew install --cask metasploit
export PATH="/opt/metasploit-framework/bin:$PATH"
```

### nmap: Permission denied (raw socket)

```bash
# Linux: butuh sudo atau setcap
sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)
# atau jalankan crushgear dengan sudo
sudo python3 crushgear.py -t 192.168.1.0/24
```

### Nuclei: No templates

```bash
nuclei -update-templates
# atau
bin/nuclei -update-templates
```

### Rate limit GitHub saat `--update-cves`

```bash
# Buat token gratis di: https://github.com/settings/tokens
python3 crushgear.py --update-cves --github-token ghp_yourtokenhere
```

### Timeout terlalu pendek untuk network besar

Edit `config.json`:
```json
{
  "timeouts": {
    "nmap":   1800,
    "amass":  3600,
    "nuclei":  900
  }
}
```

---

## Struktur Folder

### Mode Default / Update (hanya tools-crushgear)

```
tools-crushgear/
├── crushgear.py          ← Main CLI entry point
├── setup_tools.py        ← Auto-installer (default + --full mode)
├── install.sh            ← One-command installer
├── requirements.txt      ← Python deps
├── config.json           ← Binary paths + timeouts + CVE cache
├── README.md             ← Dokumentasi ini
│
├── core/
│   ├── runner.py         ← Phased async executor
│   ├── target.py         ← Auto-detect target type
│   ├── reporter.py       ← Terminal output + summary table
│   ├── feed.py           ← Inter-phase data passing + CVE map
│   └── updater.py        ← GitHub version check + CVE updater
│
├── wrappers/
│   ├── base.py           ← BaseTool abstract class
│   ├── nmap.py           ← Phase 0
│   ├── amass.py          ← Phase 1
│   ├── httpx_tool.py     ← Phase 1
│   ├── netexec.py        ← Phase 2
│   ├── smbmap.py         ← Phase 2
│   ├── nuclei.py         ← Phase 2
│   ├── feroxbuster.py    ← Phase 2
│   └── metasploit.py     ← Phase 3
│
├── bin/                  ← Auto-populated oleh --setup
│   ├── amass
│   ├── httpx
│   ├── nuclei
│   └── feroxbuster
│
└── results/              ← Auto-created saat scan
    └── {target}_{timestamp}/
```

### Mode --full / --update (source clone di parent folder)

Setelah `bash install.sh --full`, struktur parent akan jadi:

```
Pentest-Tools/                        ← parent folder
├── tools-crushgear/                  ← folder ini (tetap cukup 1 folder ini ke team)
│   ├── bin/                          ← binaries di-build ke sini
│   │   ├── amass
│   │   ├── httpx
│   │   ├── nuclei
│   │   ├── feroxbuster
│   │   └── msfconsole -> ../../metasploit-framework-master/msfconsole
│   └── config.json                   ← path binary auto-updated
│
├── NetExec/                          ← git clone NetExec (pip install -e .)
├── smbmap-master/                    ← git clone smbmap (pip install -e .)
├── amass/                            ← git clone amass (go build)
├── httpx/                            ← git clone httpx (go build)
├── nuclei/                           ← git clone nuclei (go build)
├── feroxbuster/                      ← git clone feroxbuster (cargo build)
└── metasploit-framework-master/      ← git clone MSF (~1 GB)
    ├── msfconsole                    ← entry point
    ├── modules/
    │   ├── exploits/                 ← semua exploit modules
    │   ├── payloads/                 ← semua payloads (meterpreter, dll)
    │   ├── post/                     ← post-exploitation modules
    │   ├── auxiliary/                ← scanner/recon modules
    │   └── encoders/
    └── data/
        └── exploits/                 ← exploit data files
```

> **Catatan**: Untuk distribusi ke team, cukup share folder `tools-crushgear` saja.
> Saat team jalankan `bash install.sh --full`, otomatis clone semua source ke parent folder mereka.

---

## Legal & Ethics

> Tool ini dibuat untuk **authorized penetration testing** dan **security research** saja.
> Gunakan hanya pada sistem yang kamu miliki atau memiliki izin tertulis untuk melakukan pengujian.
> Penggunaan tanpa izin adalah ilegal.

---

*CrushGear — Built for pentesters, by pentesters.*
