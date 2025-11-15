import socket
import threading
import queue

TCP_TIMEOUT = 0.5
MAX_THREADS = 100


# -----------------------------
# INTERNAL THREAD WORKER
# -----------------------------
def _tcp_worker(target, port_queue, results):
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TCP_TIMEOUT)
            try:
                if sock.connect_ex((target, port)) == 0:
                    results["open_tcp"].append(port)
            except Exception:
                pass

        results["scanned"] += 1  # update progress
        port_queue.task_done()


# -----------------------------
# NORMAL TCP SCAN
# -----------------------------
def scan_tcp_ports(target: str, start_port: int = 1, end_port: int = 1024):
    print(f"[+] Scanning TCP ports {start_port}-{end_port} on {target}...")

    port_queue = queue.Queue()
    total_ports = end_port - start_port + 1

    results = {"open_tcp": [], "scanned": 0}

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    num_threads = min(MAX_THREADS, total_ports)
    for _ in range(num_threads):
        t = threading.Thread(target=_tcp_worker, args=(target, port_queue, results))
        t.daemon = True
        t.start()

    port_queue.join()
    return sorted(results["open_tcp"])


# -----------------------------
# STREAMING TCP SCAN (REAL-TIME PROGRESS)
# -----------------------------
def scan_tcp_ports_streamed(target: str, start_port: int, end_port: int):
    total_ports = end_port - start_port + 1

    port_queue = queue.Queue()
    results = {"open_tcp": [], "scanned": 0}

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    num_threads = min(MAX_THREADS, total_ports)

    # Start threads
    for _ in range(num_threads):
        t = threading.Thread(target=_tcp_worker, args=(target, port_queue, results))
        t.daemon = True
        t.start()

    # Stream progress
    last_percent = -1
    while results["scanned"] < total_ports:
        percent = int((results["scanned"] * 100) / total_ports)
        if percent != last_percent:
            yield {
                "phase": "tcp",
                "percent": percent
            }
            last_percent = percent

    port_queue.join()

    yield {
        "phase": "tcp_done",
        "percent": 100,
        "open_tcp": sorted(results["open_tcp"]),
    }
