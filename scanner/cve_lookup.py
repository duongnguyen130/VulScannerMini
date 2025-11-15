import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = "x" #add your own key  ^.^


def lookup_cves_for_banner(banner: str):
    """
    Takes a banner string from a service and searches the NVD API for related CVEs.
    """

    if not banner or banner.lower() == "unknown":
        return []

    try:
        headers = {
            "apiKey": NVD_API_KEY
        }

        params = {
            "keywordSearch": banner,
            "resultsPerPage": 10
        }

        response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=8)

        if response.status_code != 200:
            return [f"Error querying NVD API (status {response.status_code})"]

        data = response.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            description = item["cve"]["descriptions"][0]["value"][:200] + "..."
            cves.append(f"{cve_id}: {description}")

        return cves

    except Exception as e:
        return [f"Lookup error: {str(e)}"]
