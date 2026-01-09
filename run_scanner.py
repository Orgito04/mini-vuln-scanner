import argparse
from scanner.port_scanner import scan_host
from scanner.banner_grabber import grab_banner
from scanner.vuln_checks import check_port_risk
from datetime import datetime
import csv
import os

def main():
    parser = argparse.ArgumentParser(description="Mini Vulnerability Scanner (Educational)")
    parser.add_argument("target", help="Target IP or hostname")
    args = parser.parse_args()

    target = args.target

    ports_to_scan = list(range(1, 1025))  # scan first 1024 ports

    print(f"[*] Scanning target: {target}")
    open_ports = scan_host(target, ports_to_scan)

    results = []

    for port, service in open_ports:
        banner = grab_banner(target, port)
        risk = check_port_risk(port)

        results.append({
            "port": port,
            "service": service,
            "banner": banner,
            "risk": risk if risk else "Low"
        })

    os.makedirs("reports", exist_ok=True)

    report_name = f"reports/scan_{target.replace('.', '_')}.csv"

    with open(report_name, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "service", "banner", "risk"])
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print("\n========== SCAN COMPLETE ==========")
    print(f"Report saved to: {report_name}\n")

    for r in results:
        print(f"Port {r['port']} | {r['service']} | Risk: {r['risk']}")
        if r['banner']:
            print(f"   Banner: {r['banner'][:80]}")

if __name__ == "__main__":
    main()
