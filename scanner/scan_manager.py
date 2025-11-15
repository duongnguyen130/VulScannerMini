import time
from .tcp_scanner import scan_tcp_ports
from .udp_scanner import scan_udp_ports
from .banner_grabber import grab_banners
from .cve_lookup import lookup_cves_for_banner
from .misconfig import detect_misconfig
from .report import generate_html_report


def run_full_scan(target: str, tcp_start: int = 1, tcp_end: int = 1024):
    start_time = time.time()

    open_tcp = scan_tcp_ports(target, tcp_start, tcp_end)
    open_udp = scan_udp_ports(target)

    banners = grab_banners(target, open_tcp)

    cve_map = {}
    print("[+] Looking up CVEs based on banners (this may be slow)...")
    for port, banner in banners.items():
        cve_map[port] = lookup_cves_for_banner(banner)

    misconfigs = detect_misconfig(open_tcp, open_udp)

    # Save full report into static so it can be opened from the UI
    report_path = "static/report.html"
    generate_html_report(target, open_tcp, open_udp, banners, cve_map, misconfigs, report_path)

    elapsed = time.time() - start_time
    print(f"[+] Scan complete in {elapsed:.1f} seconds.")

    return {
        "target": target,
        "open_tcp": open_tcp,
        "open_udp": open_udp,
        "banners": banners,
        "cves": cve_map,
        "misconfigs": misconfigs,
        "report_url": "/static/report.html",
        "elapsed_sec": round(elapsed, 1),
    }
