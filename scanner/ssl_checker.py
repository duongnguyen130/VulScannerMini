import socket
import ssl
from datetime import datetime


SSL_PORTS = [443, 8443, 9443]


def check_ssl(target, open_tcp):
    findings = []
    for port in SSL_PORTS:
        if port not in open_tcp:
            continue
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    proto = ssock.version()
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter")
                    exp_str = ""
                    if not_after:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.utcnow()).days
                        exp_str = f" (expires in {days} days)"
                    findings.append(
                        f"Port {port} uses {proto} with certificate subject={cert.get('subject')} {exp_str}"
                    )
        except Exception as e:
            findings.append(f"Port {port}: SSL/TLS check failed ({e})")
    return findings
