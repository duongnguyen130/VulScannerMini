import socket
import threading
import queue

TCP_TIMEOUT = 0.5
MAX_THREADS = 100


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
        port_queue.task_done()


def scan_tcp_ports(target: str, start_port: int = 1, end_port: int = 1024):
    print(f"[+] Scanning TCP ports {start_port}-{end_port} on {target}...")
    port_queue = queue.Queue()
    results = {"open_tcp": []}

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    threads = []
    num_threads = min(MAX_THREADS, end_port - start_port + 1)
    for _ in range(num_threads):
        t = threading.Thread(target=_tcp_worker, args=(target, port_queue, results))
        t.daemon = True
        t.start()
        threads.append(t)

    port_queue.join()
    return sorted(results["open_tcp"])
