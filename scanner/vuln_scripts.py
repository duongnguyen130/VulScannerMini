def run_extra_checks(open_tcp, banners, web_info, ssl_findings):
    findings = []

    # Old / risky protocols
    if 21 in open_tcp:
        findings.append("FTP (21) open – check for anonymous login and clear-text credentials.")
    if 23 in open_tcp:
        findings.append("Telnet (23) open – legacy plain-text protocol; consider disabling.")
    if 3389 in open_tcp:
        findings.append("RDP (3389) open – ensure strong auth, lockout, and MFA if exposed.")

    # Banner-based hints
    for port, banner in banners.items():
        low = banner.lower()
        if "apache/2.2" in low:
            findings.append(f"Apache 2.2 detected on port {port} – end of life, consider upgrading.")
        if "openssh_5" in low or "openssh_6" in low:
            findings.append(f"Old OpenSSH version on port {port} – review for known CVEs.")
        if "php/5." in low:
            findings.append(f"PHP 5.x detected on port {port} – end of life, many known vulnerabilities.")

    # Web info hints
    for port, info in web_info.items():
        if info.get("title"):
            title = info["title"].lower()
            if "login" in title or "admin" in title:
                findings.append(f"Web login portal detected on port {port} – brute-force / auth hardening in scope.")
        for path in info.get("interesting_paths", []):
            findings.append(f"Interesting web path: {path}")

        if info.get("robots"):
            findings.append(f"robots.txt on port {port} discloses crawler rules – review for sensitive paths.")

    # Reuse SSL findings as "extra" items too
    for f in ssl_findings:
        findings.append(f"SSL/TLS: {f}")

    return findings
