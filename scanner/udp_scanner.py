import socket

UDP_TIMEOUT = 1.0

# Common UDP ports worth probing
COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 161, 500]


def scan_udp_ports(target: str, ports=None):
    if ports is None:
        ports = COMMON_UDP_PORTS

    print(f"[+] Scanning UDP ports {ports} on {target}...")
    open_or_filtered = []

    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(UDP_TIMEOUT)
            try:
                sock.sendto(b"\x00", (target, port))

                try:
                    data, _ = sock.recvfrom(1024)
                    # Any response → something is there
                    open_or_filtered.append(port)
                except socket.timeout:
                    # Could be open or filtered – mark it as open/filtered
                    open_or_filtered.append(port)
            except Exception:
                pass

    return sorted(open_or_filtered)
