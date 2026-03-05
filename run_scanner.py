import argparse
import csv
import os
import threading
import requests
from scanner.port_scanner import scan_host
from scanner.banner_grabber import grab_banner
from scanner.vuln_checks import check_port_risk

# ---------------- Multithreaded port scanning ----------------
def scan_port_thread(target, port, results):
    open_ports = scan_host(target, [port])
    if open_ports:
        results.extend(open_ports)

def multithreaded_scan(target, ports):
    threads = []
    results = []

    for port in ports:
        t = threading.Thread(target=scan_port_thread, args=(target, port, results))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return results

# ---------------- HTML Report ----------------
def save_html_report(target, results, web_results=None):
    os.makedirs("reports", exist_ok=True)
    report_file = f"reports/scan_{target.replace('.', '_')}.html"

    html_content = f"""
    <html>
    <head>
    <title>Scan Report for {target}</title>
    <style>
        body {{ font-family: Arial; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid black; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
    </head>
    <body>
    <h2>Scan Report for {target}</h2>
    <h3>Port Scan Results</h3>
    <table>
        <tr><th>Port</th><th>Service</th><th>Version</th><th>Risk</th><th>Banner</th></tr>
    """

    for r in results:
        banner = r['banner'][:80] if r['banner'] else ''
        html_content += f"<tr><td>{r['port']}</td><td>{r['service']}</td><td>{r['version']}</td><td>{r['risk']}</td><td>{banner}</td></tr>"

    html_content += "</table>"

    if web_results:
        html_content += "<h3>Web Vulnerability Results</h3><ul>"
        for key, value in web_results.items():
            html_content += f"<li><b>{key}:</b> {value}</li>"
        html_content += "</ul>"

    html_content += "</body></html>"

    with open(report_file, "w") as f:
        f.write(html_content)

    print(f"HTML report saved to: {report_file}")

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
    errors = ["sql syntax", "mysql", "syntax error", "database error"]
    try:
        r = requests.get(test_url, timeout=5)
        return any(error in r.text.lower() for error in errors)
    except:
        return False

def check_admin_pages(url):
    paths = ["/admin", "/login", "/administrator", "/admin.php", "/admin/login"]
    found = []
    for path in paths:
        try:
            r = requests.get(url + path, timeout=5)
            if r.status_code == 200:
                found.append(path)
        except:
            pass
    return found

# ---------------- Main ----------------
def main():
    parser = argparse.ArgumentParser(description="Mini Vulnerability Scanner (Educational)")
    parser.add_argument("target", help="Target IP or hostname (or web URL http://...)")
    args = parser.parse_args()

    target = args.target
    ports_to_scan = list(range(1, 1025))

    # ---------- Port scanning ----------
    print(f"[*] Scanning target: {target}")
    open_ports = multithreaded_scan(target, ports_to_scan)

    results = []
    for port, service in open_ports:
        banner = grab_banner(target, port)
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

    # ---------- Web vulnerability checks ----------
    web_results = {}
    if target.startswith("http://") or target.startswith("https://"):
        print("[*] Running web vulnerability checks...")
        web_results['XSS Vulnerable'] = check_xss(target)
        web_results['SQL Injection Vulnerable'] = check_sqli(target)
        web_results['Admin Pages Found'] = check_admin_pages(target)
    else:
        print("[*] Target is not a web URL, skipping web vulnerability checks.")

    # ---------- Save CSV report ----------
    os.makedirs("reports", exist_ok=True)
    csv_file = f"reports/scan_{target.replace('.', '_').replace(':', '_')}.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "service", "version", "risk", "banner"])
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print("\n========== SCAN COMPLETE ==========")
    print(f"CSV report saved to: {csv_file}")

    # ---------- Save HTML report ----------
    save_html_report(target, results, web_results)

    # ---------- Print summary ----------
    for r in results:
        print(f"Port {r['port']} | {r['service']} | Version: {r['version']} | Risk: {r['risk']}")
        if r['banner']:
            print(f"   Banner: {r['banner'][:80]}")

    if web_results:
        print("\n--- Web Vulnerability Summary ---")
        for k, v in web_results.items():
            print(f"{k}: {v}")

if __name__ == "__main__":
    main()