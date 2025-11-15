"""
scan_manager.py
High-level orchestration for the vulnerability scanner.
"""

import time
import json

from .tcp_scanner import scan_tcp_ports, scan_tcp_ports_streamed
from .udp_scanner import scan_udp_ports, scan_udp_ports_streamed
from .banner_grabber import grab_banners
from .cve_lookup import lookup_cves_for_banner
from .misconfig import detect_misconfig
from .report import generate_html_report
from .os_detect import guess_os
from .ssl_checker import check_ssl
from .web_scanner import scan_web
from .vuln_scripts import run_extra_checks


# ============================================================================
# NORMAL FULL SCAN (used by /scan)
# ============================================================================
def run_full_scan(target, tcp_start=1, tcp_end=1024, profile="quick"):
    start = time.time()
    profile = (profile or "quick").lower()

    # Override for full-range scans
    if profile in ("deep", "oscp"):
        tcp_start, tcp_end = 1, 65535

    print(f"[+] Starting {profile.upper()} scan on {target} ({tcp_start}-{tcp_end})")

    # 1) TCP Scan
    open_tcp = scan_tcp_ports(target, tcp_start, tcp_end)

    # 2) UDP Scan
    if profile == "oscp":
        open_udp = scan_udp_ports(target, ports=None)
    else:
        open_udp = scan_udp_ports(target)

    # 3) Banners
    banners = grab_banners(target, open_tcp)

    # 4) CVEs
    cve_map = {}
    for port, banner in banners.items():
        try:
            cve_map[port] = lookup_cves_for_banner(banner)
        except:
            cve_map[port] = []

    # 5) Misconfig
    misconfigs = detect_misconfig(open_tcp, open_udp)

    # 6) OS Guess
    os_guess = guess_os(open_tcp, banners)

    # 7) Advanced checks (OSCP)
    ssl_findings = []
    web_info = {}
    extra_findings = []

    if profile == "oscp":
        ssl_findings = check_ssl(target, open_tcp)
        web_info = scan_web(target, open_tcp)
        extra_findings = run_extra_checks(open_tcp, banners, web_info, ssl_findings)
    else:
        if 445 in open_tcp:
            extra_findings.append("SMB (445) exposed — check EternalBlue risk.")
        if 3389 in open_tcp:
            extra_findings.append("RDP (3389) exposed — restrict external access.")
        if 80 in open_tcp and 443 not in open_tcp:
            extra_findings.append("HTTP without HTTPS — enforce TLS.")

    # 8) Report
    report_path = "static/report.html"
    generate_html_report(
        target=target,
        open_tcp=open_tcp,
        open_udp=open_udp,
        banners=banners,
        cve_map=cve_map,
        misconfigs=misconfigs,
        output_file=report_path,
        os_guess=os_guess,
        ssl_findings=ssl_findings,
        web_info=web_info,
        extra_findings=extra_findings,
        profile=profile,
    )

    elapsed = round(time.time() - start, 1)

    return {
        "target": target,
        "open_tcp": open_tcp,
        "open_udp": open_udp,
        "banners": banners,
        "cves": cve_map,
        "misconfigs": misconfigs,
        "report_url": "/static/report.html",
        "elapsed_sec": elapsed,
        "os_guess": os_guess,
        "extra_findings": extra_findings,
        "profile": profile,
    }


# ============================================================================
# STREAMING VERSION (used by /progress)
# Returns JSON messages that script.js handles in real time.
# ============================================================================
def run_full_scan_streamed(target, tcp_start, tcp_end, profile):
    profile = (profile or "quick").lower()

    # Apply full-range overrides
    if profile in ("deep", "oscp"):
        tcp_start, tcp_end = 1, 65535

    print(f"[STREAM] Scan started on {target}")

    # -------------------------------------------------------
    # PHASE 1: TCP STREAMING
    # -------------------------------------------------------
    open_tcp = []

    for update in scan_tcp_ports_streamed(target, tcp_start, tcp_end):
        # update = {"phase": "tcp", "percent": X} or {"phase": "tcp_done", "percent": 100, "open_tcp": [...]}
        yield json.dumps(update)

        if update["phase"] == "tcp_done":
            open_tcp = update["open_tcp"]

    # -------------------------------------------------------
    # PHASE 2: UDP STREAMING
    # -------------------------------------------------------
    open_udp = []

    if profile == "oscp":
        udp_stream = scan_udp_ports_streamed(target, ports=None)
    else:
        udp_stream = scan_udp_ports_streamed(target)

    for update in udp_stream:
        # update = {"phase": "udp", "percent": X} or {"phase": "udp_done", "percent": 100, "open_udp": [...]}
        yield json.dumps(update)

        if update["phase"] == "udp_done":
            open_udp = update["open_udp"]

    # -------------------------------------------------------
    # PHASE 3: ANALYSIS (simulated %)
    # -------------------------------------------------------
    yield json.dumps({"phase": "analysis", "percent": 10})

    banners = grab_banners(target, open_tcp)
    yield json.dumps({"phase": "analysis", "percent": 40})

    cve_map = {p: lookup_cves_for_banner(b) for p, b in banners.items()}
    yield json.dumps({"phase": "analysis", "percent": 70})

    misconfigs = detect_misconfig(open_tcp, open_udp)
    os_guess = guess_os(open_tcp, banners)
    yield json.dumps({"phase": "analysis", "percent": 90})

    # -------------------------------------------------------
    # PHASE 4: REPORT GENERATION
    # -------------------------------------------------------
    report_path = "static/report.html"
    generate_html_report(
        target=target,
        open_tcp=open_tcp,
        open_udp=open_udp,
        banners=banners,
        cve_map=cve_map,
        misconfigs=misconfigs,
        output_file=report_path,
        os_guess=os_guess,
        ssl_findings=[],
        web_info={},
        extra_findings=[]
    )

    # -------------------------------------------------------
    # COMPLETE
    # -------------------------------------------------------
    yield json.dumps({"phase": "complete", "percent": 100})
