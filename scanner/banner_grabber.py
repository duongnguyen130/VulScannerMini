import socket


def grab_banner(target: str, port: int) -> str:
    banner = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.5)
            sock.connect((target, port))

            if port in (80, 8080, 8000, 443):
                probe = b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % target.encode()
            else:
                probe = b"\r\n"

            sock.sendall(probe)
            data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()
    except Exception:
        pass
    return banner


def grab_banners(target: str, ports):
    print(f"[+] Grabbing banners from {len(ports)} TCP services...")
    banners = {}
    for port in ports:
        banner = grab_banner(target, port)
        if banner:
            banners[port] = banner
    return banners
