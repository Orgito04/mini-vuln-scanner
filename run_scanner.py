import argparse
import csv
import os
import re
import socket
import threading
import requests
from urllib.parse import urlparse

from scanner.banner_grabber import grab_banner
from scanner.vuln_checks import check_port_risk


def sanitize_filename(name):
    return re.sub(r'[^\w\-_\.]', '_', name)


# ---------------- Multithreaded Port Scan ----------------

def multithreaded_scan(target, ports):
    results = []
    threads = []
    lock = threading.Lock()

    def worker(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((target, port))

            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"

                with lock:
                    print(f"[OPEN] {port} ({service.upper()})")
                    results.append((port, service))

            sock.close()

        except:
            pass

    for port in ports:
        t = threading.Thread(target=worker, args=(port,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return results


# ---------------- HTML Report ----------------

def save_html_report(target, results, web_results=None):

    os.makedirs("reports", exist_ok=True)

    report_file = f"reports/scan_{sanitize_filename(target)}.html"

    html = f"""
    <html>
    <head>
    <title>Scan Report</title>
    <style>
    body {{font-family: Arial;}}
    table {{border-collapse: collapse; width:100%;}}
    th, td {{border:1px solid black; padding:8px;}}
    th {{background:#f2f2f2}}
    </style>
    </head>
    <body>

    <h2>Scan Report for {target}</h2>

    <h3>Port Scan Results</h3>

    <table>
    <tr>
    <th>Port</th>
    <th>Service</th>
    <th>Version</th>
    <th>Risk</th>
    <th>Banner</th>
    </tr>
    """

    for r in results:

        banner = r["banner"][:80] if r["banner"] else ""

        html += f"""
        <tr>
        <td>{r['port']}</td>
        <td>{r['service']}</td>
        <td>{r['version']}</td>
        <td>{r['risk']}</td>
        <td>{banner}</td>
        </tr>
        """

    html += "</table>"

    if web_results:

        html += "<h3>Web Vulnerability Results</h3><ul>"

        for k, v in web_results.items():
            if isinstance(v, list):
                v_str = ', '.join(v)
            else:
                v_str = str(v)
            html += f"<li><b>{k}</b>: {v_str}</li>"

        html += "</ul>"

    html += "</body></html>"

    with open(report_file, "w") as f:
        f.write(html)

    print(f"[+] HTML report saved to: {report_file}")


# ---------------- Web Vulnerability Checks ----------------

def check_xss(url):

    payload = "<script>alert(1)</script>"

    test_url = f"{url}?q={payload}"

    try:
        r = requests.get(test_url, timeout=5)

        return payload in r.text

    except:
        return False


def check_sqli(url):

    payload = "' OR '1'='1"

    test_url = f"{url}?id={payload}"

    errors = [
        "sql syntax",
        "mysql",
        "syntax error",
        "database error"
    ]

    try:
        r = requests.get(test_url, timeout=5)

        return any(e in r.text.lower() for e in errors)

    except:
        return False


def check_admin_pages(url):

    paths = [
        "/admin",
        "/login",
        "/administrator",
        "/admin.php",
        "/admin/login"
    ]

    found = []

    for p in paths:

        try:

            r = requests.get(url + p, timeout=5)

            if r.status_code == 200:
                found.append(p)

        except:
            pass

    return found


# ---------------- MAIN ----------------

def main():

    parser = argparse.ArgumentParser(
        description="Mini Vulnerability Scanner (Educational)"
    )

    parser.add_argument(
        "target",
        help="Target IP or URL"
    )

    args = parser.parse_args()

    target = args.target

    # Parse target for scanning
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        scan_target = parsed.hostname
        web_target = target
    else:
        scan_target = target
        web_target = None

    ports = list(range(1, 1025))

    print(f"\n[*] Scanning target: {target}\n")

    # -------- Port Scan --------

    open_ports = multithreaded_scan(scan_target, ports)

    results = []

    for port, service in open_ports:

        banner = grab_banner(scan_target, port)

        risk = check_port_risk(port)

        version = "Unknown"

        if banner:

            lines = banner.split("\n")

            if lines:
                version = lines[0]

        results.append({
            "port": port,
            "service": service,
            "version": version,
            "banner": banner,
            "risk": risk if risk else "Low"
        })

    # -------- Web Checks --------

    web_results = {}

    if web_target:

        print("\n[*] Running web vulnerability checks...\n")

        web_results["XSS Vulnerable"] = check_xss(web_target)

        web_results["SQL Injection Vulnerable"] = check_sqli(web_target)

        web_results["Admin Pages Found"] = check_admin_pages(web_target)

    else:

        print("\n[*] Target is not a web URL. Skipping web tests.\n")

    # -------- Save CSV --------

    os.makedirs("reports", exist_ok=True)

    csv_file = f"reports/scan_{sanitize_filename(target)}.csv"

    with open(csv_file, "w", newline="", encoding="utf-8") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=["port", "service", "version", "risk", "banner"]
        )

        writer.writeheader()

        for r in results:
            writer.writerow(r)

    print("\n========== SCAN COMPLETE ==========\n")

    print(f"[+] CSV report saved: {csv_file}")

    # -------- Save HTML --------

    save_html_report(target, results, web_results)

    # -------- Print summary --------

    for r in results:

        print(
            f"Port {r['port']} | {r['service']} | Version: {r['version']} | Risk: {r['risk']}"
        )

        if r["banner"]:
            print(f"   Banner: {r['banner'][:80]}")

    if web_results:

        print("\n--- Web Vulnerability Summary ---\n")

        for k, v in web_results.items():
            print(f"{k}: {v}")


if __name__ == "__main__":
    main()