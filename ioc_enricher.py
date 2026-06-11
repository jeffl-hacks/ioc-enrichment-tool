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
        print("Usage: python3 ioc_enricher.py <ip_address>")
        sys.exit(1)
    ip = sys.argv[1]
    print(f"Enriching {ip}...")
    vt = check_virustotal_ip(ip)
    abuse = check_abuseipdb(ip)
    display_results(ip, vt, abuse)
