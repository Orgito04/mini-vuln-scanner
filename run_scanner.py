#!/usr/bin/env python3
"""
========================================
     MINI SECURITY SCANNER v2.0
   Professional Network Recon Tool
========================================
Author  : Enhanced for CTF / Pentesting
License : MIT
Usage   : python scanner.py <target> [options]
"""

import argparse
import csv
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import struct
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

# ── Optional third-party imports (graceful degradation) ──────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scanner")


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS & KNOWLEDGE BASE
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "2.0"

# CVE / advisory hints per software banner keyword
CVE_HINTS: dict[str, list[str]] = {
    "apache/2.2":   ["CVE-2011-3192 (Range DoS)", "CVE-2012-0053 (Info Leak)"],
    "apache/2.4.49":["CVE-2021-41773 (Path Traversal / RCE)"],
    "apache/2.4.50":["CVE-2021-42013 (Path Traversal / RCE)"],
    "nginx/1.16":   ["CVE-2019-9511 (HTTP/2 DoS)"],
    "openssh_5":    ["CVE-2010-4478 (J-PAKE bypass)"],
    "openssh_7.2":  ["CVE-2016-6515 (Auth-passwd DoS)"],
    "vsftpd 2.3.4": ["CVE-2011-2523 (Backdoor RCE)"],
    "proftpd 1.3.3":["CVE-2010-4221 (Pre-auth stack overflow)"],
    "mysql":        ["Possible unauthenticated root if misconfigured"],
    "redis":        ["CVE-2022-0543 (Lua sandbox escape) – check AUTH"],
    "smb":          ["Check MS17-010 (EternalBlue) with nmap --script smb-vuln-ms17-010"],
    "rdp":          ["CVE-2019-0708 (BlueKeep) – unpatched Win hosts"],
    "vnc":          ["Check for no-auth mode; brute-forceable"],
}

# Risk table: port → (level, reason)
RISK_TABLE: dict[int, tuple[str, str]] = {
    21:   ("CRITICAL", "FTP – plaintext, often allows anon login"),
    22:   ("LOW",      "SSH – secure if patched; watch old versions"),
    23:   ("CRITICAL", "Telnet – plaintext credentials"),
    25:   ("HIGH",     "SMTP – open relay / user enum risk"),
    53:   ("MEDIUM",   "DNS – zone transfer / amplification"),
    79:   ("HIGH",     "Finger – user enumeration"),
    80:   ("MEDIUM",   "HTTP – inspect for web vulns"),
    110:  ("MEDIUM",   "POP3 – plaintext mail retrieval"),
    111:  ("HIGH",     "RPC portmapper – attack surface"),
    135:  ("HIGH",     "MS-RPC – lateral movement vector"),
    139:  ("HIGH",     "NetBIOS – legacy SMB"),
    143:  ("MEDIUM",   "IMAP – plaintext if no STARTTLS"),
    161:  ("HIGH",     "SNMP – community string leak"),
    389:  ("HIGH",     "LDAP – potential unauthenticated dump"),
    443:  ("LOW",      "HTTPS – check TLS version & cert"),
    445:  ("CRITICAL", "SMB – EternalBlue / ransomware pivot"),
    512:  ("HIGH",     "rexec – no encryption"),
    513:  ("HIGH",     "rlogin – legacy, no encryption"),
    514:  ("HIGH",     "rsh/syslog – no auth"),
    1433: ("HIGH",     "MSSQL – brute / injection target"),
    1521: ("HIGH",     "Oracle DB – default creds common"),
    2049: ("HIGH",     "NFS – check for unauthenticated shares"),
    3306: ("HIGH",     "MySQL – check for remote root"),
    3389: ("CRITICAL", "RDP – BlueKeep / brute-force"),
    4444: ("CRITICAL", "Metasploit default listener?"),
    5432: ("HIGH",     "PostgreSQL – check pg_hba.conf"),
    5900: ("HIGH",     "VNC – weak/no auth common"),
    6379: ("CRITICAL", "Redis – often unauthenticated, RCE risk"),
    8080: ("MEDIUM",   "Alt-HTTP – dev/proxy, may lack auth"),
    8443: ("MEDIUM",   "Alt-HTTPS – self-signed certs common"),
    9200: ("CRITICAL", "Elasticsearch – unauthenticated data dump"),
    27017:("CRITICAL", "MongoDB – unauthenticated by default"),
}

DEFAULT_PORTS = sorted({
    21,22,23,25,53,67,69,79,80,110,111,119,123,
    135,137,138,139,143,161,179,389,443,445,
    465,500,512,513,514,515,520,587,636,989,990,
    993,995,1433,1521,2049,2082,2083,2086,2087,
    2181,2222,2483,2484,3000,3128,3306,3389,3690,
    4444,4567,4662,4899,5000,5432,5601,5666,5800,
    5900,5985,5986,6000,6379,6667,7001,7002,7070,
    7100,7200,7443,7777,8000,8008,8009,8010,8080,
    8081,8086,8087,8088,8090,8091,8443,8888,9000,
    9001,9042,9080,9090,9200,9418,9999,10000,27017,
})

# ── ANSI colour codes ─────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def colour(text: str, *codes: str) -> str:
    if sys.platform == "win32":
        return text
    return "".join(codes) + text + C.RESET

def risk_colour(risk: str) -> str:
    lvl = risk.split()[0].upper()
    palette = {
        "CRITICAL": C.RED + C.BOLD,
        "HIGH":     C.RED,
        "MEDIUM":   C.YELLOW,
        "LOW":      C.GREEN,
    }
    return colour(risk, palette.get(lvl, C.RESET))


# ─────────────────────────────────────────────────────────────────────────────
#  INPUT VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def validate_target(raw: str) -> tuple[str, str | None]:
    """
    Validate and resolve the target.
    Returns (scan_ip, web_url_or_None).
    Raises ValueError on invalid input.
    """
    raw = raw.strip()

    # Block private / loopback ONLY when running against a URL hostname
    # (allow explicit IP scans for lab environments)
    web_target = None

    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"Cannot parse hostname from URL: {raw!r}")
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror as exc:
            raise ValueError(f"DNS resolution failed for {hostname!r}: {exc}") from exc
        web_target = raw
        return ip, web_target

    # Raw IP?
    try:
        addr = ipaddress.ip_address(raw)
        return str(addr), None
    except ValueError:
        pass

    # Hostname
    try:
        ip = socket.gethostbyname(raw)
        return ip, None
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve {raw!r}: {exc}") from exc


# ─────────────────────────────────────────────────────────────────────────────
#  BANNER GRABBING
# ─────────────────────────────────────────────────────────────────────────────

# Probes sent to specific ports to elicit a banner
_PROBES: dict[int, bytes] = {
    21:    b"",
    22:    b"",
    25:    b"EHLO scanner\r\n",
    80:    b"HEAD / HTTP/1.0\r\n\r\n",
    110:   b"",
    143:   b"",
    443:   b"HEAD / HTTP/1.0\r\n\r\n",   # sent over TLS
    3306:  b"",
    5432:  b"",
    6379:  b"INFO\r\n",
    9200:  b"GET / HTTP/1.0\r\n\r\n",
    27017: b"",
}

def grab_banner(target: str, port: int, timeout: float = 3.0) -> str:
    """Grab a service banner from target:port."""
    probe = _PROBES.get(port, b"")
    banner = ""

    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            # TLS wrap for known TLS ports
            if port in (443, 465, 636, 989, 990, 993, 995, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=target) as tls:
                    if probe:
                        tls.sendall(probe)
                    tls.settimeout(timeout)
                    raw = tls.recv(1024)
            else:
                if probe:
                    sock.sendall(probe)
                sock.settimeout(timeout)
                raw = sock.recv(1024)

            banner = raw.decode("utf-8", errors="replace").strip()

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    except Exception as exc:
        log.debug("Banner grab %s:%d – %s", target, port, exc)

    return banner


# ─────────────────────────────────────────────────────────────────────────────
#  DETECTION HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_VERSION_PATTERNS = [
    r"Apache/([\d\.]+)",
    r"nginx/([\d\.]+)",
    r"OpenSSH[_\s]?([\d\.p]+)",
    r"MySQL\s([\d\.]+)",
    r"ProFTPD\s([\d\.]+)",
    r"vsftpd\s([\d\.]+)",
    r"Redis\s([\d\.]+)",
    r"PostgreSQL\s([\d\.]+)",
    r"Microsoft-IIS/([\d\.]+)",
    r"lighttpd/([\d\.]+)",
    r"PHP/([\d\.]+)",
    r"OpenSSL/([\d\.]+[a-z]?)",
]

def detect_version(banner: str) -> str:
    if not banner:
        return "Unknown"
    for pat in _VERSION_PATTERNS:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return m.group(0)
    return "Unknown"


def detect_service_from_banner(banner: str) -> str | None:
    if not banner:
        return None
    bl = banner.lower()
    checks = [
        ("apache",    "Apache HTTP"),
        ("nginx",     "Nginx HTTP"),
        ("iis",       "Microsoft IIS"),
        ("lighttpd",  "lighttpd"),
        ("openssh",   "OpenSSH"),
        ("vsftpd",    "vsftpd"),
        ("proftpd",   "ProFTPD"),
        ("ftp",       "FTP"),
        ("smtp",      "SMTP"),
        ("pop3",      "POP3"),
        ("imap",      "IMAP"),
        ("mysql",     "MySQL"),
        ("postgresql","PostgreSQL"),
        ("redis",     "Redis"),
        ("mongodb",   "MongoDB"),
        ("elastic",   "Elasticsearch"),
    ]
    for keyword, label in checks:
        if keyword in bl:
            return label
    return None


def classify_risk(port: int) -> tuple[str, str]:
    """Return (risk_level, reason) for a port."""
    return RISK_TABLE.get(port, ("LOW", "No specific risk profile"))


def get_cve_hints(banner: str) -> list[str]:
    """Return CVE hints that match the banner."""
    if not banner:
        return []
    bl = banner.lower()
    hints: list[str] = []
    for keyword, advisories in CVE_HINTS.items():
        if keyword in bl:
            hints.extend(advisories)
    return hints


# ─────────────────────────────────────────────────────────────────────────────
#  SSL / TLS INSPECTOR
# ─────────────────────────────────────────────────────────────────────────────

def inspect_tls(target: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Connect with TLS and collect certificate & protocol info.
    Returns a dict with keys: protocol, cipher, subject, issuer,
    not_before, not_after, expired, self_signed, san.
    """
    info: dict = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=target) as tls:
                info["protocol"] = tls.version()
                info["cipher"]   = tls.cipher()[0] if tls.cipher() else "Unknown"
                cert             = tls.getpeercert()

                if cert:
                    def _fmt(rdns):
                        return ", ".join(
                            f"{k}={v}"
                            for rdn in rdns
                            for k, v in rdn
                        )
                    info["subject"]  = _fmt(cert.get("subject", []))
                    info["issuer"]   = _fmt(cert.get("issuer",  []))
                    info["not_before"] = cert.get("notBefore", "")
                    info["not_after"]  = cert.get("notAfter",  "")
                    # Expiry check
                    try:
                        exp = datetime.strptime(
                            info["not_after"], "%b %d %H:%M:%S %Y %Z"
                        )
                        info["expired"]     = exp < datetime.utcnow()
                        info["days_left"]   = (exp - datetime.utcnow()).days
                    except Exception:
                        info["expired"]   = False
                        info["days_left"] = -1
                    info["self_signed"] = info["subject"] == info["issuer"]
                    san = cert.get("subjectAltName", [])
                    info["san"] = [v for _, v in san]
    except Exception as exc:
        log.debug("TLS inspect %s:%d – %s", target, port, exc)
    return info


# ─────────────────────────────────────────────────────────────────────────────
#  DNS RECON
# ─────────────────────────────────────────────────────────────────────────────

def dns_recon(hostname: str) -> dict:
    """
    Perform basic DNS recon: A, MX, NS, TXT, zone-transfer attempt.
    Falls back to socket if dnspython not installed.
    """
    results: dict = {"hostname": hostname, "records": {}, "zone_transfer": []}

    if DNS_OK:
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            try:
                answers = dns.resolver.resolve(hostname, rtype, lifetime=4)
                results["records"][rtype] = [str(r) for r in answers]
            except Exception:
                pass

        # Zone transfer attempt
        ns_records = results["records"].get("NS", [])
        for ns in ns_records[:2]:
            ns = ns.rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, hostname, timeout=4))
                results["zone_transfer"].append(
                    {"ns": ns, "names": [str(n) for n in zone.nodes.keys()]}
                )
            except Exception:
                pass
    else:
        # Minimal fallback
        try:
            ip = socket.gethostbyname(hostname)
            results["records"]["A"] = [ip]
        except Exception:
            pass

    return results


# ─────────────────────────────────────────────────────────────────────────────
#  PORT SCANNING
# ─────────────────────────────────────────────────────────────────────────────

_print_lock = threading.Lock()

def _safe_print(msg: str):
    with _print_lock:
        print(msg)


def scan_port(target: str, port: int, timeout: float = 2.0) -> tuple[int, str] | None:
    """TCP connect scan. Returns (port, service_name) or None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            return (port, service)
    except OSError:
        pass
    return None


def port_scan(
    target: str,
    ports: list[int],
    workers: int = 150,
    timeout: float = 2.0,
) -> list[tuple[int, str]]:
    """Threaded port scan with live progress bar."""
    results: list[tuple[int, str]] = []
    total   = len(ports)
    done    = 0

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, target, p, timeout): p for p in ports}
        for future in as_completed(futures):
            done += 1
            pct   = done / total * 100
            bar   = "█" * int(pct / 2) + "░" * (50 - int(pct / 2))
            with _print_lock:
                print(f"\r  [{bar}] {pct:5.1f}%", end="", flush=True)
            r = future.result()
            if r:
                _safe_print(
                    f"\n  {colour('[OPEN]', C.GREEN, C.BOLD)} "
                    f"{colour(str(r[0]), C.CYAN)} / {r[1].upper()}"
                )
                results.append(r)

    print()
    return results


# ─────────────────────────────────────────────────────────────────────────────
#  WEB VULNERABILITY CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def _make_session(retries: int = 2, timeout: int = 6) -> "requests.Session":
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; MiniScanner/2.0)",
        "Accept":     "*/*",
    })
    retry = Retry(total=retries, backoff_factor=0.3,
                  status_forcelist=[429, 500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://",  adapter)
    s.mount("https://", adapter)
    s.verify = False   # intentional for pentest context
    return s


def check_xss(url: str, session) -> dict:
    """Reflected XSS probe."""
    payload  = "<script>alert('XSS')</script>"
    result   = {"vulnerable": False, "payload": payload, "url_tested": ""}
    try:
        test_url = f"{url}?q={requests.utils.quote(payload)}"
        result["url_tested"] = test_url
        r = session.get(test_url, timeout=6, allow_redirects=False)
        result["vulnerable"] = payload in r.text
    except Exception as exc:
        log.debug("XSS check: %s", exc)
    return result


def check_sqli(url: str, session) -> dict:
    """Error-based SQLi probe."""
    payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "1; DROP TABLE users--"]
    db_errors = [
        "you have an error in your sql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "syntax error",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL",
        "SQLite",
        "Microsoft OLE DB Provider for SQL",
    ]
    result = {"vulnerable": False, "payload": "", "error_matched": ""}
    for pl in payloads:
        try:
            r = session.get(f"{url}?id={requests.utils.quote(pl)}", timeout=6)
            for err in db_errors:
                if err.lower() in r.text.lower():
                    result.update({"vulnerable": True, "payload": pl,
                                   "error_matched": err})
                    return result
        except Exception as exc:
            log.debug("SQLi check: %s", exc)
    return result


def check_lfi(url: str, session) -> dict:
    """Local File Inclusion probe."""
    payloads = [
        "../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
    ]
    result = {"vulnerable": False, "payload": ""}
    for pl in payloads:
        try:
            r = session.get(f"{url}?file={pl}&page={pl}&path={pl}", timeout=6)
            if re.search(r"root:.*:0:0:", r.text):
                result = {"vulnerable": True, "payload": pl}
                return result
        except Exception as exc:
            log.debug("LFI check: %s", exc)
    return result


def check_open_redirect(url: str, session) -> dict:
    """Open redirect probe."""
    payload = "https://evil.example.com"
    result  = {"vulnerable": False, "payload": payload}
    try:
        r = session.get(
            f"{url}?redirect={payload}&url={payload}&next={payload}",
            timeout=6, allow_redirects=False,
        )
        loc = r.headers.get("Location", "")
        if "evil.example.com" in loc:
            result["vulnerable"] = True
    except Exception as exc:
        log.debug("Open redirect check: %s", exc)
    return result


def check_security_headers(url: str, session) -> dict:
    """Analyse HTTP response headers for missing security headers."""
    important = {
        "Strict-Transport-Security": "HSTS missing – susceptible to downgrade",
        "Content-Security-Policy":   "CSP missing – XSS risk increased",
        "X-Content-Type-Options":    "MIME sniffing not prevented",
        "X-Frame-Options":           "Clickjacking protection absent",
        "Referrer-Policy":           "Referrer leakage possible",
        "Permissions-Policy":        "Browser features unrestricted",
    }
    results: dict[str, str] = {}
    try:
        r = session.get(url, timeout=6)
        for header, warning in important.items():
            if header.lower() not in {k.lower() for k in r.headers}:
                results[header] = warning
        # Detect server version disclosure
        server = r.headers.get("Server", "")
        if server:
            results["Server header"] = f"Discloses: {server}"
        powered = r.headers.get("X-Powered-By", "")
        if powered:
            results["X-Powered-By"] = f"Discloses: {powered}"
    except Exception as exc:
        log.debug("Headers check: %s", exc)
    return results


def check_cors(url: str, session) -> dict:
    """Check for overly permissive CORS."""
    result = {"misconfigured": False, "acao": ""}
    try:
        r = session.get(
            url, timeout=6,
            headers={"Origin": "https://evil.example.com"},
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        result["acao"] = acao
        if acao in ("*", "https://evil.example.com"):
            result["misconfigured"] = True
        if acac.lower() == "true" and acao != "*":
            result["misconfigured"] = True
            result["note"] = "Credentials reflected with arbitrary origin"
    except Exception as exc:
        log.debug("CORS check: %s", exc)
    return result


def directory_scan(url: str, session) -> dict[str, int]:
    """Wordlist-based directory brute-force."""
    paths = [
        "/admin", "/administrator", "/admin.php", "/admin/login",
        "/login", "/signin", "/dashboard", "/panel", "/cpanel",
        "/phpmyadmin", "/pma", "/db", "/database",
        "/config", "/config.php", "/.env", "/.git/config",
        "/wp-admin", "/wp-login.php", "/wp-config.php",
        "/backup", "/backup.zip", "/backup.tar.gz",
        "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui",
        "/actuator", "/actuator/health", "/actuator/env",
        "/server-status", "/server-info",
        "/robots.txt", "/sitemap.xml", "/.htaccess",
        "/debug", "/test", "/temp", "/tmp",
    ]
    found: dict[str, int] = {}
    for p in paths:
        try:
            r = session.get(url + p, timeout=5, allow_redirects=False)
            if r.status_code in (200, 301, 302, 403):
                found[p] = r.status_code
        except Exception:
            pass
    return found


# ─────────────────────────────────────────────────────────────────────────────
#  REPORTS
# ─────────────────────────────────────────────────────────────────────────────

def sanitize_filename(name: str) -> str:
    return re.sub(r"[^\w\-_\.]", "_", name)


_HTML_STYLE = """
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #c9d1d9; --muted: #8b949e;
  --critical: #ff4444; --high: #ff8c00;
  --medium: #f0e040; --low: #3fb950; --info: #58a6ff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text);
       font-family: 'Segoe UI', system-ui, sans-serif;
       font-size: 14px; padding: 24px; }
h1 { color: var(--info); font-size: 1.8em; margin-bottom: 4px; }
h2 { color: var(--info); font-size: 1.2em; margin: 28px 0 10px;
     border-bottom: 1px solid var(--border); padding-bottom: 6px; }
.meta { color: var(--muted); font-size: 0.85em; margin-bottom: 20px; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(140px,1fr));
                gap: 12px; margin-bottom: 24px; }
.summary-card { background: var(--surface); border: 1px solid var(--border);
                border-radius: 8px; padding: 14px; text-align: center; }
.summary-card .num { font-size: 2em; font-weight: 700; }
.summary-card .lbl { font-size: 0.75em; color: var(--muted); margin-top: 4px; }
.critical .num { color: var(--critical); }
.high     .num { color: var(--high);     }
.medium   .num { color: var(--medium);   }
.low      .num { color: var(--low);      }
.info-card     { color: var(--info);     }
table { width: 100%; border-collapse: collapse;
        background: var(--surface); border-radius: 8px; overflow: hidden; }
th { background: #21262d; color: var(--muted); text-align: left;
     padding: 10px 12px; font-size: 0.8em; text-transform: uppercase;
     letter-spacing: .05em; }
td { padding: 9px 12px; border-top: 1px solid var(--border);
     vertical-align: top; }
tr:hover td { background: #1c2128; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
         font-size: 0.75em; font-weight: 700; }
.badge-critical { background:#ff444433; color: var(--critical); }
.badge-high     { background:#ff8c0033; color: var(--high);     }
.badge-medium   { background:#f0e04033; color: var(--medium);   }
.badge-low      { background:#3fb95033; color: var(--low);      }
.tag-open  { color: var(--low);      }
.tag-vuln  { color: var(--critical); }
.tag-ok    { color: var(--muted);    }
code { background: #21262d; padding: 1px 5px; border-radius: 4px;
       font-family: monospace; font-size: 0.9em; }
ul.hints { margin: 4px 0 0 16px; }
ul.hints li { color: var(--high); font-size: 0.85em; }
.section-card { background: var(--surface); border: 1px solid var(--border);
                border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.section-card p { margin: 4px 0; line-height: 1.6; }
.key { color: var(--muted); min-width: 180px; display: inline-block; }
.vuln-yes { color: var(--critical); font-weight: bold; }
.vuln-no  { color: var(--muted); }
"""

def _risk_badge(risk: str) -> str:
    lvl = risk.split()[0].upper()
    cls = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium"}.get(lvl,"low")
    return f'<span class="badge badge-{cls}">{lvl}</span>'


def save_html_report(
    target: str,
    scan_ip: str,
    port_results: list[dict],
    web_results: dict,
    tls_info: dict,
    dns_info: dict,
    scan_time: float,
) -> str:
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename  = f"reports/scan_{sanitize_filename(target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    # Summary counts
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in port_results:
        lvl = r["risk"].split()[0].upper()
        counts[lvl] = counts.get(lvl, 0) + 1

    # ── Port table rows
    port_rows = ""
    for r in sorted(port_results, key=lambda x: x["port"]):
        hints_html = ""
        if r.get("cve_hints"):
            items = "".join(f"<li>{h}</li>" for h in r["cve_hints"])
            hints_html = f'<ul class="hints">{items}</ul>'
        port_rows += f"""
        <tr>
          <td><code>{r['port']}</code></td>
          <td>{r['service']}</td>
          <td><code>{r['version']}</code></td>
          <td>{_risk_badge(r['risk'])}<br><small style="color:#8b949e">{r['risk_reason']}</small>{hints_html}</td>
          <td><small style="color:#8b949e">{r.get('banner','')[:120]}</small></td>
        </tr>"""

    # ── Web section
    web_html = ""
    if web_results:
        def _yesno(val):
            if isinstance(val, bool):
                return ('<span class="vuln-yes">⚠ YES</span>' if val
                        else '<span class="vuln-no">No</span>')
            if isinstance(val, dict):
                return ('<span class="vuln-yes">⚠ YES</span>' if val.get("vulnerable")
                        else '<span class="vuln-no">No</span>')
            return str(val)

        web_html += '<div class="section-card">'
        for k, v in web_results.items():
            if k == "Security Headers":
                web_html += f'<p><span class="key">{k}:</span>'
                if v:
                    items = "".join(f"<li style='color:#ff8c00'>{hk}: {hv}</li>"
                                    for hk, hv in v.items())
                    web_html += f'<ul>{items}</ul></p>'
                else:
                    web_html += '<span class="vuln-no"> All present ✓</span></p>'
            elif k == "Directories":
                if v:
                    items = "".join(
                        f"<li><code>{path}</code> → HTTP {code}</li>"
                        for path, code in v.items()
                    )
                    web_html += (f'<p><span class="key">{k}:</span>'
                                 f'<ul>{items}</ul></p>')
                else:
                    web_html += (f'<p><span class="key">{k}:</span>'
                                 f'<span class="vuln-no"> None found</span></p>')
            elif isinstance(v, dict):
                web_html += (f'<p><span class="key">{k}:</span>'
                             f' {_yesno(v)}'
                             f'<small style="color:#8b949e"> '
                             f'{v.get("payload","") or v.get("note","")}'
                             f'</small></p>')
            else:
                web_html += f'<p><span class="key">{k}:</span> {_yesno(v)}</p>'
        web_html += '</div>'

    # ── TLS section
    tls_html = ""
    if tls_info:
        expired_label = (
            '<span class="vuln-yes">EXPIRED</span>' if tls_info.get("expired")
            else f'<span class="vuln-no">Valid ({tls_info.get("days_left","?")} days left)</span>'
        )
        self_signed = (
            '<span class="vuln-yes">Self-signed!</span>' if tls_info.get("self_signed")
            else '<span class="vuln-no">CA-signed</span>'
        )
        san = ", ".join(tls_info.get("san", [])) or "N/A"
        tls_html = f"""
        <div class="section-card">
          <p><span class="key">Protocol:</span> <code>{tls_info.get('protocol','?')}</code></p>
          <p><span class="key">Cipher:</span> <code>{tls_info.get('cipher','?')}</code></p>
          <p><span class="key">Subject:</span> {tls_info.get('subject','?')}</p>
          <p><span class="key">Issuer:</span> {tls_info.get('issuer','?')}</p>
          <p><span class="key">Expiry:</span> {tls_info.get('not_after','?')} — {expired_label}</p>
          <p><span class="key">Trust:</span> {self_signed}</p>
          <p><span class="key">SANs:</span> {san}</p>
        </div>"""

    # ── DNS section
    dns_html = ""
    if dns_info and dns_info.get("records"):
        dns_html = '<div class="section-card">'
        for rtype, vals in dns_info["records"].items():
            dns_html += (f'<p><span class="key">{rtype}:</span> '
                         + " · ".join(f"<code>{v}</code>" for v in vals) + "</p>")
        if dns_info.get("zone_transfer"):
            dns_html += '<p style="color:var(--critical)">⚠ Zone transfer succeeded!</p>'
        dns_html += "</div>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Scanner Report – {target}</title>
  <style>{_HTML_STYLE}</style>
</head>
<body>
  <h1>🔍 Security Scan Report</h1>
  <div class="meta">
    Target: <strong>{target}</strong> &nbsp;|&nbsp;
    IP: <strong>{scan_ip}</strong> &nbsp;|&nbsp;
    {timestamp} &nbsp;|&nbsp;
    Duration: {scan_time:.2f}s &nbsp;|&nbsp;
    Scanner v{VERSION}
  </div>

  <div class="summary-grid">
    <div class="summary-card critical"><div class="num">{counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
    <div class="summary-card high">   <div class="num">{counts['HIGH']}</div>   <div class="lbl">High</div></div>
    <div class="summary-card medium"> <div class="num">{counts['MEDIUM']}</div> <div class="lbl">Medium</div></div>
    <div class="summary-card low">    <div class="num">{counts['LOW']}</div>    <div class="lbl">Low</div></div>
    <div class="summary-card info-card"><div class="num">{len(port_results)}</div><div class="lbl">Open Ports</div></div>
  </div>

  <h2>Port Scan Results</h2>
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Risk &amp; Advisory</th><th>Banner</th></tr></thead>
    <tbody>{port_rows if port_rows else "<tr><td colspan='5'>No open ports found</td></tr>"}</tbody>
  </table>

  {"<h2>TLS / SSL Analysis</h2>" + tls_html if tls_html else ""}
  {"<h2>DNS Recon</h2>" + dns_html if dns_html else ""}
  {"<h2>Web Vulnerability Scan</h2>" + web_html if web_html else ""}

  <p style="color:#8b949e;font-size:0.75em;margin-top:40px">
    ⚠ This report is for authorised testing only. Do not use against systems you do not own or have permission to test.
  </p>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename


def save_json_report(
    target: str,
    scan_ip: str,
    port_results: list[dict],
    web_results: dict,
    tls_info: dict,
    dns_info: dict,
    scan_time: float,
) -> str:
    os.makedirs("reports", exist_ok=True)
    filename = (f"reports/scan_{sanitize_filename(target)}_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    payload = {
        "scanner_version": VERSION,
        "target":          target,
        "ip":              scan_ip,
        "timestamp":       datetime.now().isoformat(),
        "duration_s":      round(scan_time, 2),
        "ports":           port_results,
        "web":             web_results,
        "tls":             tls_info,
        "dns":             dns_info,
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    return filename


def save_csv_report(target: str, port_results: list[dict]) -> str:
    os.makedirs("reports", exist_ok=True)
    filename = (f"reports/scan_{sanitize_filename(target)}_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    fields = ["port", "service", "version", "risk", "risk_reason", "banner", "cve_hints"]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for r in port_results:
            row = dict(r)
            row["cve_hints"] = "; ".join(r.get("cve_hints", []))
            writer.writerow(row)
    return filename


# ─────────────────────────────────────────────────────────────────────────────
#  TERMINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

def print_banner():
    print(colour(f"""
╔══════════════════════════════════════════╗
║        MINI SECURITY SCANNER v{VERSION}       ║
║      Professional Network Recon Tool     ║
╚══════════════════════════════════════════╝
""", C.CYAN, C.BOLD))


def print_summary(port_results: list[dict], web_results: dict, scan_time: float):
    print(colour("\n╔═══════════════ SCAN SUMMARY ═══════════════╗", C.CYAN))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in port_results:
        lvl = r["risk"].split()[0].upper()
        counts[lvl] = counts.get(lvl, 0) + 1

    print(f"  Open ports  : {colour(str(len(port_results)), C.CYAN, C.BOLD)}")
    print(f"  Critical    : {colour(str(counts['CRITICAL']), C.RED,    C.BOLD)}")
    print(f"  High        : {colour(str(counts['HIGH']),     C.RED)}")
    print(f"  Medium      : {colour(str(counts['MEDIUM']),   C.YELLOW)}")
    print(f"  Low         : {colour(str(counts['LOW']),      C.GREEN)}")
    print(f"  Duration    : {scan_time:.2f}s")

    if web_results:
        print(colour("\n  Web findings:", C.CYAN))
        for k, v in web_results.items():
            if k in ("Security Headers", "Directories"):
                count = len(v) if v else 0
                flag  = colour(f"  {count} issues", C.YELLOW) if count else colour("  OK", C.GREEN)
                print(f"    {k:30s}: {flag}")
            elif isinstance(v, dict):
                vuln = v.get("vulnerable", False)
                flag = colour("  ⚠ VULNERABLE", C.RED, C.BOLD) if vuln else colour("  OK", C.GREEN)
                print(f"    {k:30s}: {flag}")

    print(colour("╚════════════════════════════════════════════╝\n", C.CYAN))


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Mini Security Scanner – CTF / Pentest edition",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target",
        help="Target IP, hostname, or URL (e.g. 192.168.1.1 / https://example.com)")
    parser.add_argument("-p", "--ports",
        help="Comma-separated ports or 'top100' / 'full' (default: built-in list)",
        default=None)
    parser.add_argument("-t", "--timeout",
        help="Per-port connect timeout in seconds (default: 2)",
        type=float, default=2.0)
    parser.add_argument("-w", "--workers",
        help="Thread pool size (default: 150)",
        type=int, default=150)
    parser.add_argument("--no-web",
        help="Skip web vulnerability checks",
        action="store_true")
    parser.add_argument("--no-dns",
        help="Skip DNS recon",
        action="store_true")
    parser.add_argument("--no-tls",
        help="Skip TLS/SSL inspection",
        action="store_true")
    parser.add_argument("-v", "--verbose",
        help="Enable debug logging",
        action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("scanner").setLevel(logging.DEBUG)

    # ── Validate target ───────────────────────────────────────────────────────
    try:
        scan_ip, web_target = validate_target(args.target)
    except ValueError as exc:
        print(colour(f"\n[ERROR] {exc}\n", C.RED, C.BOLD))
        sys.exit(1)

    print(f"  Target  : {colour(args.target, C.CYAN)}")
    print(f"  Resolved: {colour(scan_ip,     C.CYAN)}")

    # ── Port list ─────────────────────────────────────────────────────────────
    if args.ports == "full":
        ports = list(range(1, 65536))
    elif args.ports == "top100":
        ports = list(DEFAULT_PORTS)[:100]
    elif args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print(colour("[ERROR] Invalid port spec. Use comma-separated ints or 'top100'/'full'.", C.RED))
            sys.exit(1)
    else:
        ports = list(DEFAULT_PORTS)

    start = time.time()

    # ── DNS recon ─────────────────────────────────────────────────────────────
    dns_info: dict = {}
    if not args.no_dns:
        hostname = urlparse(args.target).hostname if args.target.startswith("http") else args.target
        if not hostname.replace(".", "").isdigit():   # skip for raw IPs
            print(colour("\n[*] DNS Recon", C.MAGENTA, C.BOLD))
            dns_info = dns_recon(hostname)
            for rtype, vals in dns_info.get("records", {}).items():
                print(f"    {rtype:6s}: {', '.join(vals)}")
            if dns_info.get("zone_transfer"):
                print(colour("    ⚠  Zone transfer succeeded!", C.RED, C.BOLD))

    # ── Port scan ─────────────────────────────────────────────────────────────
    print(colour(f"\n[*] Port Scan  ({len(ports)} ports, {args.workers} threads)\n", C.MAGENTA, C.BOLD))
    open_ports = port_scan(scan_ip, ports, workers=args.workers, timeout=args.timeout)

    # ── Banner / version / risk enrichment ───────────────────────────────────
    print(colour("\n[*] Enriching open ports (banners, versions, risk)\n", C.MAGENTA, C.BOLD))
    port_results: list[dict] = []
    for port, service in open_ports:
        banner  = grab_banner(scan_ip, port, timeout=3.0)
        version = detect_version(banner)
        risk_lvl, risk_reason = classify_risk(port)
        detected = detect_service_from_banner(banner)
        if detected:
            service = detected
        cve_hints = get_cve_hints(banner)

        port_results.append({
            "port":        port,
            "service":     service,
            "version":     version,
            "risk":        risk_lvl,
            "risk_reason": risk_reason,
            "banner":      banner,
            "cve_hints":   cve_hints,
        })

        # Live output
        hint_str = colour(" → " + cve_hints[0], C.YELLOW) if cve_hints else ""
        print(f"  {colour(str(port), C.CYAN):>7} / {service:<20} {risk_colour(risk_lvl):<12}"
              f" {colour(version, C.DIM)}{hint_str}")

    # ── TLS inspection ────────────────────────────────────────────────────────
    tls_info: dict = {}
    tls_ports = [p for p, _ in open_ports if p in (443, 8443, 465, 993, 995, 636)]
    if tls_ports and not args.no_tls:
        print(colour(f"\n[*] TLS Inspection (port {tls_ports[0]})\n", C.MAGENTA, C.BOLD))
        tls_info = inspect_tls(scan_ip, tls_ports[0])
        if tls_info:
            print(f"    Protocol : {tls_info.get('protocol','?')}")
            print(f"    Cipher   : {tls_info.get('cipher','?')}")
            print(f"    Subject  : {tls_info.get('subject','?')}")
            exp_str = (colour("EXPIRED", C.RED, C.BOLD)
                       if tls_info.get("expired")
                       else colour(f"OK ({tls_info.get('days_left','?')} days)", C.GREEN))
            print(f"    Expiry   : {tls_info.get('not_after','?')} [{exp_str}]")
            if tls_info.get("self_signed"):
                print(colour("    ⚠  Self-signed certificate!", C.YELLOW))

    # ── Web checks ────────────────────────────────────────────────────────────
    web_results: dict = {}
    if web_target and not args.no_web:
        if not REQUESTS_OK:
            print(colour("\n[!] requests not installed – skipping web checks\n", C.YELLOW))
        else:
            import urllib3
            urllib3.disable_warnings()
            print(colour("\n[*] Web Vulnerability Scan\n", C.MAGENTA, C.BOLD))
            sess = _make_session()

            checks = [
                ("XSS",           check_xss,             (web_target, sess)),
                ("SQL Injection",  check_sqli,            (web_target, sess)),
                ("LFI",           check_lfi,              (web_target, sess)),
                ("Open Redirect", check_open_redirect,    (web_target, sess)),
                ("CORS",          check_cors,             (web_target, sess)),
                ("Security Headers", check_security_headers, (web_target, sess)),
                ("Directories",   directory_scan,         (web_target, sess)),
            ]

            for name, fn, fn_args in checks:
                try:
                    result = fn(*fn_args)
                    web_results[name] = result
                    # Print status
                    if name == "Security Headers":
                        cnt = len(result)
                        flag = colour(f"⚠  {cnt} missing", C.YELLOW) if cnt else colour("OK", C.GREEN)
                    elif name == "Directories":
                        cnt = len(result)
                        flag = colour(f"⚠  {cnt} found", C.YELLOW) if cnt else colour("None", C.GREEN)
                    elif name == "CORS":
                        flag = (colour("⚠  Misconfigured", C.RED, C.BOLD)
                                if result.get("misconfigured")
                                else colour("OK", C.GREEN))
                    elif isinstance(result, dict):
                        flag = (colour("⚠  VULNERABLE", C.RED, C.BOLD)
                                if result.get("vulnerable")
                                else colour("OK", C.GREEN))
                    else:
                        flag = str(result)
                    print(f"    {name:<25} {flag}")
                except Exception as exc:
                    log.debug("Web check %s failed: %s", name, exc)
                    web_results[name] = {"error": str(exc)}

    # ── Reports ───────────────────────────────────────────────────────────────
    scan_time = time.time() - start
    print_summary(port_results, web_results, scan_time)

    html_file = save_html_report(
        args.target, scan_ip, port_results,
        web_results, tls_info, dns_info, scan_time,
    )
    json_file = save_json_report(
        args.target, scan_ip, port_results,
        web_results, tls_info, dns_info, scan_time,
    )
    csv_file  = save_csv_report(args.target, port_results)

    print(colour("  Reports saved:", C.CYAN, C.BOLD))
    print(f"    HTML : {html_file}")
    print(f"    JSON : {json_file}")
    print(f"    CSV  : {csv_file}")
    print(colour("\n  Scan complete.\n", C.GREEN, C.BOLD))


if __name__ == "__main__":
    main()
