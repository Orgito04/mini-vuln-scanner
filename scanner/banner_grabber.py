import socket

def grab_banner(host, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((host, port))
        banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip()
    except:
        return ""
    finally:
        sock.close()
