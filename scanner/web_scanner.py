import re
import requests

HTTP_PORTS = [80, 8080, 8000, 8888]


def _get_scheme(port):
    if port == 443:
        return "https"
    return "http"


def scan_web(target, open_tcp):
    results = {}
    for port in sorted(open_tcp):
        if port in HTTP_PORTS or port == 443:
            scheme = _get_scheme(port)
            base = f"{scheme}://{target}:{port}"
            info = {"title": None, "robots": None, "interesting_paths": []}
            try:
                r = requests.get(base, timeout=5, verify=False)
                # crude title extraction
                m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                if m:
                    info["title"] = m.group(1).strip()
            except Exception:
                pass

            # robots.txt
            try:
                r = requests.get(base + "/robots.txt", timeout=3, verify=False)
                if r.status_code == 200 and len(r.text) < 5000:
                    info["robots"] = r.text[:500]
            except Exception:
                pass

            # tiny directory brute-force
            wordlist = ["admin", "login", "test", "backup", "old", "dev", "phpmyadmin"]
            for w in wordlist:
                try:
                    url = base + "/" + w
                    r = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                    if r.status_code in (200, 301, 302, 401, 403):
                        info["interesting_paths"].append(f"{url} -> {r.status_code}")
                except Exception:
                    continue

            results[port] = info
    return results
