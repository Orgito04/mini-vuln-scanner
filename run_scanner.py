import argparse
import csv
import os
import re
import socket
import time
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from scanner.banner_grabber import grab_banner


# ---------------- Banner ----------------

def print_banner():

    print("""
========================================
        MINI SECURITY SCANNER
     Network Vulnerability Tool
========================================
""")


# ---------------- Utils ----------------

def sanitize_filename(name):
    return re.sub(r'[^\w\-_\.]', '_', name)


# ---------------- Risk Classification ----------------

def classify_risk(port):

    high = [21, 23, 3389]
    medium = [80, 8080, 445]

    if port in high:
        return "HIGH"
    elif port in medium:
        return "MEDIUM"
    return "LOW"


# ---------------- Version Detection ----------------

def detect_version(banner):

    if not banner:
        return "Unknown"

    patterns = [
        r"Apache\/([\d\.]+)",
        r"nginx\/([\d\.]+)",
        r"OpenSSH[_\s]?([\d\.]+)",
        r"MySQL\s([\d\.]+)"
    ]

    for p in patterns:
        match = re.search(p, banner)
        if match:
            return match.group(0)

    return "Unknown"


# ---------------- Port Scan ----------------

def scan_port(target, port):

    try:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:

            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown"

            sock.close()
            return (port, service)

        sock.close()

    except:
        pass

    return None


def port_scan(target, ports):

    results = []
    total_ports = len(ports)
    scanned = 0

    with ThreadPoolExecutor(max_workers=100) as executor:

        futures = [executor.submit(scan_port, target, p) for p in ports]

        for f in futures:

            r = f.result()
            scanned += 1

            percent = (scanned / total_ports) * 100
            print(f"\rScanning progress: {percent:.1f}%", end="")

            if r:
                print(f"\n[OPEN] {r[0]} ({r[1].upper()})")
                results.append(r)

    print("\n")

    return results


# ---------------- Web Checks ----------------

def check_xss(url):

    payload = "<script>alert(1)</script>"

    try:
        r = requests.get(f"{url}?q={payload}", timeout=5)
        return payload in r.text
    except:
        return False


def check_sqli(url):

    payload = "' OR '1'='1"

    errors = ["sql", "mysql", "syntax", "database"]

    try:
        r = requests.get(f"{url}?id={payload}", timeout=5)
        return any(e in r.text.lower() for e in errors)
    except:
        return False


def directory_scan(url):

    paths = ["/admin", "/login", "/dashboard", "/config", "/administrator"]

    found = []

    for p in paths:
        try:
            r = requests.get(url + p, timeout=5)
            if r.status_code == 200:
                found.append(p)
        except:
            pass

    return found


# ---------------- HTML Report ----------------

def save_html_report(target, results, web_results, scan_time):

    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    file = f"reports/scan_{sanitize_filename(target)}.html"

    html = f"""
    <html>
    <head>
    <title>Security Scan Report</title>
    <style>
    body{{font-family:Arial;background:#f4f4f4;padding:20px}}
    table{{border-collapse:collapse;width:100%;background:white}}
    th,td{{border:1px solid #ddd;padding:10px}}
    th{{background:#333;color:white}}
    .high{{color:red;font-weight:bold}}
    .medium{{color:orange;font-weight:bold}}
    .low{{color:green;font-weight:bold}}
    </style>
    </head>
    <body>

    <h1>Mini Vulnerability Scanner Report</h1>

    <p><b>Target:</b> {target}</p>
    <p><b>Scan Date:</b> {timestamp}</p>
    <p><b>Scan Duration:</b> {scan_time:.2f} seconds</p>

    <h2>Port Scan Results</h2>

    <table>
    <tr>
    <th>Port</th>
    <th>Service</th>
    <th>Version</th>
    <th>Risk</th>
    </tr>
    """

    for r in results:

        risk_class = r["risk"].lower()

        html += f"""
        <tr>
        <td>{r['port']}</td>
        <td>{r['service']}</td>
        <td>{r['version']}</td>
        <td class="{risk_class}">{r['risk']}</td>
        </tr>
        """

    html += "</table>"

    if web_results:

        html += "<h2>Web Vulnerability Results</h2><ul>"

        for k, v in web_results.items():
            html += f"<li><b>{k}</b>: {v}</li>"

        html += "</ul>"

    html += "</body></html>"

    with open(file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] HTML report saved: {file}")


# ---------------- MAIN ----------------

def main():

    print_banner()

    parser = argparse.ArgumentParser(
        description="Mini Vulnerability Scanner"
    )

    parser.add_argument("target", help="Target IP or URL")

    args = parser.parse_args()

    target = args.target

    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        scan_target = parsed.hostname
        web_target = target
    else:
        scan_target = target
        web_target = None

    ports = list(range(1, 1025))

    print(f"\n[*] Starting scan on {target}\n")

    start = time.time()

    open_ports = port_scan(scan_target, ports)

    results = []

    for port, service in open_ports:

        banner = grab_banner(scan_target, port)

        version = detect_version(banner)

        risk = classify_risk(port)

        results.append({
            "port": port,
            "service": service,
            "version": version,
            "risk": risk
        })

    web_results = {}

    if web_target:

        print("\n[*] Running web tests\n")

        web_results["XSS"] = check_xss(web_target)
        web_results["SQL Injection"] = check_sqli(web_target)
        web_results["Directories"] = directory_scan(web_target)

    scan_time = time.time() - start

    os.makedirs("reports", exist_ok=True)

    csv_file = f"reports/scan_{sanitize_filename(target)}.csv"

    with open(csv_file, "w", newline="", encoding="utf-8") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=["port", "service", "version", "risk"]
        )

        writer.writeheader()

        for r in results:
            writer.writerow(r)

    print(f"\n[+] CSV report saved: {csv_file}")

    save_html_report(target, results, web_results, scan_time)

    high = sum(1 for r in results if r["risk"] == "HIGH")
    medium = sum(1 for r in results if r["risk"] == "MEDIUM")
    low = sum(1 for r in results if r["risk"] == "LOW")

    print("\nScan Summary")
    print("---------------------------")
    print(f"Open Ports: {len(results)}")
    print(f"High Risk Services: {high}")
    print(f"Medium Risk Services: {medium}")
    print(f"Low Risk Services: {low}")

    print("\n===== SCAN COMPLETE =====\n")


if __name__ == "__main__":
    main()