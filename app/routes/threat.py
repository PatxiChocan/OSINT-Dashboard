from flask import Blueprint, jsonify
import requests
import concurrent.futures
from datetime import datetime, timezone

threat_bp = Blueprint("threat", __name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; AletheiaOSINT/1.0)"}


# ─── CVEs ──────────────────────────────────────────────────────────────────────

def fetch_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    resp = requests.get(url, timeout=15, headers=HEADERS)
    resp.raise_for_status()
    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    # Return dict keyed by cveID for fast lookup
    return {v["cveID"]: v for v in vulns}


def fetch_nvd_recent(kev_ids):
    """Fetch recent critical/high CVEs from NVD, mark KEV ones."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": 40,
        "startIndex": 0,
    }
    resp = requests.get(url, params=params, timeout=20, headers=HEADERS)
    resp.raise_for_status()
    data = resp.json()

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_data = None
        score = None
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        published = cve.get("published", "")[:10]
        kev_info = kev_ids.get(cve_id)

        results.append({
            "id": cve_id,
            "description": desc_en[:300],
            "score": score,
            "severity": severity,
            "published": published,
            "actively_exploited": bool(kev_info),
            "vendor": kev_info.get("vendorProject", "") if kev_info else "",
            "product": kev_info.get("product", "") if kev_info else "",
            "kev_date_added": kev_info.get("dateAdded", "") if kev_info else "",
            "ransomware": kev_info.get("knownRansomwareCampaignUse", "") if kev_info else "",
        })

    return results


def fetch_kev_only(kev_dict):
    """Return most recent KEV entries as fallback/supplement."""
    entries = list(kev_dict.values())
    entries.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    results = []
    for v in entries[:30]:
        results.append({
            "id": v.get("cveID", ""),
            "description": v.get("shortDescription", "")[:300],
            "score": None,
            "severity": "CRITICAL",
            "published": v.get("dateAdded", ""),
            "actively_exploited": True,
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "kev_date_added": v.get("dateAdded", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", ""),
        })
    return results


@threat_bp.route("/api/cves")
def get_cves():
    try:
        kev_dict = fetch_cisa_kev()
    except Exception:
        kev_dict = {}

    try:
        cves = fetch_nvd_recent(kev_dict)
    except Exception:
        cves = []

    # Supplement with KEV-only entries not already in NVD results
    nvd_ids = {c["id"] for c in cves}
    kev_extras = [c for c in fetch_kev_only(kev_dict) if c["id"] not in nvd_ids]

    all_cves = cves + kev_extras
    # Sort: actively exploited first, then by score desc
    all_cves.sort(key=lambda x: (not x["actively_exploited"], -(x["score"] or 0)))

    return jsonify({
        "count": len(all_cves),
        "kev_total": len(kev_dict),
        "cves": all_cves,
    })


# ─── IOCs ──────────────────────────────────────────────────────────────────────

def fetch_urlhaus():
    """Parse URLhaus CSV recent download (public, no auth).
    Columns: id, date_added, url, url_status, last_online, threat, tags, urlhaus_link, reporter
    """
    import csv
    resp = requests.get(
        "https://urlhaus.abuse.ch/downloads/csv_recent/",
        timeout=15,
        headers=HEADERS,
    )
    resp.raise_for_status()
    lines = [l for l in resp.text.splitlines() if not l.startswith("#") and l.strip()]
    reader = csv.reader(lines)
    results = []
    for row in reader:
        if len(row) < 7:
            continue
        tags_raw = row[6] if len(row) > 6 else ""
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        results.append({
            "type": "url",
            "indicator": row[2],
            "threat": row[5],
            "tags": tags,
            "date": row[1],
            "status": row[3],
            "source": "URLhaus",
        })
        if len(results) >= 100:
            break
    return results


def fetch_feodo():
    """Feodo Tracker C2 IP blocklist JSON (public, no auth)."""
    resp = requests.get(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        timeout=15,
        headers=HEADERS,
    )
    resp.raise_for_status()
    data = resp.json()
    results = []
    for item in data[:80]:
        malware = item.get("malware", "")
        results.append({
            "type": "ip",
            "indicator": item.get("ip_address", ""),
            "threat": malware,
            "tags": [malware] if malware else [],
            "date": item.get("first_seen", ""),
            "status": item.get("last_online", ""),
            "source": "Feodo Tracker",
        })
    return results


def fetch_malwarebazaar():
    """MalwareBazaar recent samples CSV (public, no auth).
    Columns: first_seen, sha256, md5, sha1, reporter, first_seen2, file_type,
             mime_type, signature, origin, imphash, tlsh, telfhash
    """
    import csv
    resp = requests.get(
        "https://bazaar.abuse.ch/export/csv/recent/",
        timeout=15,
        headers=HEADERS,
    )
    resp.raise_for_status()
    lines = [l for l in resp.text.splitlines() if not l.startswith("#") and l.strip()]
    reader = csv.reader(lines, skipinitialspace=True)
    results = []
    for row in reader:
        if len(row) < 7:
            continue
        sha256 = row[1].strip().strip('"')
        file_type = row[6].strip().strip('"')
        signature = row[8].strip().strip('"') if len(row) > 8 else ""
        threat = signature if signature and signature not in ("n/a", "") else file_type
        tags = [file_type] if file_type and file_type != "n/a" else []
        results.append({
            "type": "hash",
            "indicator": sha256,
            "threat": threat,
            "tags": tags,
            "date": row[0].strip().strip('"'),
            "status": file_type,
            "source": "MalwareBazaar",
        })
        if len(results) >= 80:
            break
    return results


@threat_bp.route("/api/iocs")
def get_iocs():
    iocs = []
    errors = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            ex.submit(fetch_urlhaus): "URLhaus",
            ex.submit(fetch_feodo): "Feodo",
            ex.submit(fetch_malwarebazaar): "MalwareBazaar",
        }
        for future, name in futures.items():
            try:
                iocs.extend(future.result())
            except Exception as e:
                errors.append(f"{name}: {str(e)[:60]}")

    iocs.sort(key=lambda x: x.get("date", ""), reverse=True)

    return jsonify({
        "count": len(iocs),
        "errors": errors,
        "iocs": iocs,
    })
