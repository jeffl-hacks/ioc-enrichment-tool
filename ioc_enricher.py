import json
import sys
import requests
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY

def check_virustotal_ip(ip):
    """Query VirusTotal for IP reputation."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {"error": f"VirusTotal returned {response.status_code}"}
    data = response.json()
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "malicious_votes": stats.get("malicious", 0),
        "suspicious_votes": stats.get("suspicious", 0),
        "harmless_votes": stats.get("harmless", 0),
        "country": attrs.get("country", "N/A"),
        "asn_owner": attrs.get("as_owner", "N/A"),
    }

def check_abuseipdb(ip):
    """Query AbuseIPDB for IP abuse reports."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        return {"error": f"AbuseIPDB returned {response.status_code}"}
    data = response.json()["data"]
    return {
        "source": "AbuseIPDB",
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "last_reported": data.get("lastReportedAt", "Never"),
        "isp": data.get("isp", "N/A"),
        "usage_type": data.get("usageType", "N/A"),
    }


def detect_ioc_type(ioc):
    """Determine if input is an IP, domain, or file hash."""
    # File hash check first — MD5(32), SHA-1(40), SHA-256(64) hex chars
    hex_chars = set("0123456789abcdefABCDEF")
    if len(ioc) in (32, 40, 64) and all(c in hex_chars for c in ioc):
        return "hash"
    parts = ioc.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ip"
    return "domain"


def check_virustotal_domain(domain):
    """Query VirusTotal for domain reputation."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {"error": f"VirusTotal returned {response.status_code}"}
    data = response.json()
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    resolved_ip = None
    for record in attrs.get("last_dns_records", []):
        if record.get("type") == "A":
            resolved_ip = record.get("value")
            break
    return {
        "source": "VirusTotal",
        "malicious_votes": stats.get("malicious", 0),
        "suspicious_votes": stats.get("suspicious", 0),
        "harmless_votes": stats.get("harmless", 0),
        "registrar": attrs.get("registrar", "N/A"),
        "reputation": attrs.get("reputation", "N/A"),
        "resolved_ip": resolved_ip,
    }

def display_domain_results(domain, vt_result, ip_results=None):
    """Print unified domain enrichment report."""
    print(f"\n{'='*60}")
    print(f"IOC ENRICHMENT REPORT — {domain} (DOMAIN)")
    print(f"{'='*60}")

    print(f"\n--- VirusTotal ---")
    if "error" in vt_result:
        print(f"  Error: {vt_result['error']}")
    else:
        print(f"  Malicious votes:  {vt_result['malicious_votes']}")
        print(f"  Suspicious votes: {vt_result['suspicious_votes']}")
        print(f"  Harmless votes:   {vt_result['harmless_votes']}")
        print(f"  Registrar:        {vt_result['registrar']}")
        print(f"  Reputation score: {vt_result['reputation']}")
        print(f"  Resolved IP:      {vt_result['resolved_ip'] or 'None found'}")

    if ip_results:
        vt_ip, abuse_ip = ip_results
        print(f"\n--- Resolved IP Enrichment ({vt_result['resolved_ip']}) ---")
        if "error" not in abuse_ip:
            print(f"  Abuse confidence: {abuse_ip['abuse_confidence']}%")
            print(f"  Total reports:    {abuse_ip['total_reports']}")
            print(f"  ISP:              {abuse_ip['isp']}")

    print(f"\n{'='*60}\n")

def check_virustotal_hash(file_hash):
    """Query VirusTotal for file hash reputation."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 404:
        return {"error": "Hash not found in VirusTotal database"}
    if response.status_code != 200:
        return {"error": f"VirusTotal returned {response.status_code}"}
    data = response.json()
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    names = attrs.get("names", [])
    return {
        "source": "VirusTotal",
        "malicious_votes": stats.get("malicious", 0),
        "suspicious_votes": stats.get("suspicious", 0),
        "harmless_votes": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "file_type": attrs.get("type_description", "N/A"),
        "file_size": attrs.get("size", "N/A"),
        "common_name": names[0] if names else "N/A",
    }

def display_hash_results(file_hash, vt_result):
    """Print file hash enrichment report."""
    print(f"\n{'='*60}")
    print(f"IOC ENRICHMENT REPORT — FILE HASH")
    print(f"{'='*60}")
    print(f"Hash: {file_hash}")

    print(f"\n--- VirusTotal ---")
    if "error" in vt_result:
        print(f"  {vt_result['error']}")
    else:
        total = (vt_result['malicious_votes'] + vt_result['suspicious_votes'] +
                 vt_result['harmless_votes'] + vt_result['undetected'])
        print(f"  Detection:        {vt_result['malicious_votes']}/{total} engines flagged malicious")
        print(f"  Suspicious votes: {vt_result['suspicious_votes']}")
        print(f"  Undetected:       {vt_result['undetected']}")
        print(f"  File type:        {vt_result['file_type']}")
        print(f"  File size:        {vt_result['file_size']} bytes")
        print(f"  Common name:      {vt_result['common_name']}")

    print(f"\n{'='*60}\n")

def display_results(ip, vt_result, abuse_result):
    """Print unified enrichment report."""
    print(f"\n{'='*60}")
    print(f"IOC ENRICHMENT REPORT — {ip}")
    print(f"{'='*60}")

    print(f"\n--- VirusTotal ---")
    if "error" in vt_result:
        print(f"  Error: {vt_result['error']}")
    else:
        print(f"  Malicious votes:  {vt_result['malicious_votes']}")
        print(f"  Suspicious votes: {vt_result['suspicious_votes']}")
        print(f"  Harmless votes:   {vt_result['harmless_votes']}")
        print(f"  Country:          {vt_result['country']}")
        print(f"  ASN Owner:        {vt_result['asn_owner']}")

    print(f"\n--- AbuseIPDB ---")
    if "error" in abuse_result:
        print(f"  Error: {abuse_result['error']}")
    else:
        print(f"  Abuse confidence: {abuse_result['abuse_confidence']}%")
        print(f"  Total reports:    {abuse_result['total_reports']}")
        print(f"  Last reported:    {abuse_result['last_reported']}")
        print(f"  ISP:              {abuse_result['isp']}")
        print(f"  Usage type:       {abuse_result['usage_type']}")

    print(f"\n{'='*60}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 ioc_enricher.py <ip_or_domain_or_hash>")
        sys.exit(1)
    ioc = sys.argv[1]
    ioc_type = detect_ioc_type(ioc)
    print(f"Enriching {ioc} (detected type: {ioc_type})...")

    if ioc_type == "ip":
        vt = check_virustotal_ip(ioc)
        abuse = check_abuseipdb(ioc)
        display_results(ioc, vt, abuse)
    elif ioc_type == "hash":
        vt = check_virustotal_hash(ioc)
        display_hash_results(ioc, vt)
    else:
        vt = check_virustotal_domain(ioc)
        ip_results = None
        if "error" not in vt and vt.get("resolved_ip"):
            vt_ip = check_virustotal_ip(vt["resolved_ip"])
            abuse_ip = check_abuseipdb(vt["resolved_ip"])
            ip_results = (vt_ip, abuse_ip)
        display_domain_results(ioc, vt, ip_results)
