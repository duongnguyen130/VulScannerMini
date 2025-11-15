def guess_os(open_tcp, banners):
    """
    Very lightweight OS guesser.
    Not real TCP fingerprinting, but good enough for a high-level hint.
    """
    ports = set(open_tcp)

    # Windows-like: RPC/NetBIOS/SMB
    if any(p in ports for p in (135, 139, 445)):
        if 3389 in ports:
            return "Windows (likely server / RDP enabled)"
        return "Windows"

    # Linux / Unix-y: SSH + web + no SMB
    if 22 in ports and (80 in ports or 443 in ports):
        return "Linux/Unix (SSH + Web)"

    # Network appliances – just a hint
    if 22 in ports and 161 in ports:
        return "Network device / appliance (SSH + SNMP)"

    # Fallback: use banners
    banners_text = " ".join(banners.values()).lower()
    if "ubuntu" in banners_text or "debian" in banners_text:
        return "Linux (Ubuntu/Debian)"
    if "centos" in banners_text or "red hat" in banners_text:
        return "Linux (RHEL/CentOS)"
    if "microsoft" in banners_text or "win" in banners_text:
        return "Windows (detected from banners)"

    return "Unknown"
