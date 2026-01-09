import socket
from datetime import datetime

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}

def scan_port(host, port, timeout=1):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            return True
        return False
    except:
        return False
    finally:
        sock.close()

def scan_host(host, ports):
    print(f"[+] Starting scan on {host}")
    open_ports = []

    for port in ports:
        if scan_port(host, port):
            service = COMMON_PORTS.get(port, "Unknown")
            print(f"[OPEN] {port} ({service})")
            open_ports.append((port, service))

    return open_ports
