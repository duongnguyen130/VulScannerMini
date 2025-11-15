def detect_misconfig(open_tcp, open_udp):
    """
    Simple, heuristic-based misconfiguration / risk detection.
    Extend this over time with more rules.
    """
    issues = []

    risky_ports = {
        21: "FTP exposed (port 21) – consider SFTP instead.",
        22: "SSH exposed (port 22) – ensure strong auth and no password login.",
        23: "Telnet exposed (port 23) – insecure, avoid plain-text.",
        25: "SMTP exposed (port 25) – check for open relay.",
        80: "HTTP exposed (port 80) – consider enforcing HTTPS.",
        445: "SMB exposed (port 445) – check for EternalBlue-style exposure.",
        3389: "RDP exposed (port 3389) – ensure strong auth + lockout policies.",
    }

    for p, msg in risky_ports.items():
        if p in open_tcp:
            issues.append(msg)

    if 161 in open_udp:
        issues.append("SNMP exposed (UDP 161) – check community strings and access controls.")

    if not open_tcp and not open_udp:
        issues.append("No open ports detected – host may be offline or behind a strict firewall.")

    return issues
