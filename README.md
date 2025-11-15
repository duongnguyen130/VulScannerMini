# Vulnerability Scanner  
A modern Python-based vulnerability scanner with a sleek web dashboard.  
This tool performs:

- TCP port scanning  
- Smart UDP probing  
- Banner grabbing  
- CVE lookup using the NVD API (with your own API key)  
- Misconfiguration detection  
- HTML report generation  

---

## Features

### Network & Port Scanning
- Fast multithreaded TCP port scanning  
- Smart UDP scanning for high-value ports (DNS, NTP, DHCP, SNMP, etc.)  
- Socket-based probing (no external dependencies like Nmap required)  

### Service Enumeration
- Banner grabbing for open ports  
- Identifies service types (HTTP, SSH, SMB, etc.)  
- Extracts fingerprint data for vulnerability matching  

### CVE Lookup (NVD API 2.0)
- Queries the official National Vulnerability Database  
- Requires your own NVD API key (free)  
- Returns CVE IDs + vulnerability descriptions  
- Integrates results into HTML reports  

### Misconfiguration Detection
Built-in checks identify common security issues:
- HTTP exposed without HTTPS  
- SMB port 445 exposed (EternalBlue-style risk)  
- FTP/Telnet plaintext exposure  
- SNMP exposure  
- And more  

### HTML Reporting
Automatically generates a professional report including:
- Open TCP/UDP ports  
- Service banners  
- CVEs  
- Misconfigurations  
- Scanning metadata (timestamps, target, elapsed time)  

---

Accessible at: http://127.0.0.1:5000/


