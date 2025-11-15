import socket

UDP_TIMEOUT = 1.0
COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 161, 500]


# -----------------------------
# NORMAL UDP SCAN
# -----------------------------
def scan_udp_ports(target: str, ports=None):
    if ports is None:
        ports = COMMON_UDP_PORTS

    print(f"[+] Scanning UDP ports {ports} on {target}...")

    open_or_filtered = []

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(UDP_TIMEOUT)
                sock.sendto(b"\x00", (target, port))

                try:
                    sock.recvfrom(1024)
                    open_or_filtered.append(port)
                except socket.timeout:
                    open_or_filtered.append(port)

        except Exception:
            pass

    return sorted(open_or_filtered)


# -----------------------------
# STREAMING UDP SCAN (REAL PROGRESS)
# -----------------------------
def scan_udp_ports_streamed(target: str, ports=None):
    if ports is None:
        ports = COMMON_UDP_PORTS

    total = len(ports)
    scanned = 0
    open_or_filtered = []
    last_percent = -1

    for port in ports:
        scanned += 1

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(UDP_TIMEOUT)
                sock.sendto(b"\x00", (target, port))

                try:
                    sock.recvfrom(1024)
                    open_or_filtered.append(port)
                except socket.timeout:
                    open_or_filtered.append(port)

        except Exception:
            pass

        percent = int((scanned * 100) / total)
        if percent != last_percent:
            yield {
                "phase": "udp",
                "percent": percent
            }
            last_percent = percent

    yield {
        "phase": "udp_done",
        "percent": 100,
        "open_udp": sorted(open_or_filtered),
    }
