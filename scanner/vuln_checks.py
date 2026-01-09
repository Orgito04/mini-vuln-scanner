DANGEROUS_PORTS = {
    21: "FTP sends credentials in plaintext",
    23: "Telnet is insecure (no encryption)",
    3389: "RDP exposed to internet is dangerous",
    3306: "Database port exposed",
}

def check_port_risk(port):
    return DANGEROUS_PORTS.get(port, None)
