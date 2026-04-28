from flask import Blueprint, jsonify
import requests
import concurrent.futures
import csv
import re
from datetime import datetime, timezone, timedelta

overview_bp = Blueprint("overview", __name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; AletheiaOSINT/1.0)"}


def _get_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = requests.get(url, timeout=15, headers=HEADERS)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])

    now = datetime.now(timezone.utc)
    cutoff_7d = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    cutoff_30d = (now - timedelta(days=30)).strftime("%Y-%m-%d")

    recent_7d = [v for v in vulns if v.get("dateAdded", "") >= cutoff_7d]
    recent_30d = [v for v in vulns if v.get("dateAdded", "") >= cutoff_30d]
    ransomware = [v for v in vulns if v.get("knownRansomwareCampaignUse", "Unknown") != "Unknown"]

    latest = sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:5]

    return {
        "ok": True,
        "total": len(vulns),
        "new_7d": len(recent_7d),
        "new_30d": len(recent_30d),
        "ransomware_count": len(ransomware),
        "latest": [
            {
                "id": v["cveID"],
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "date": v.get("dateAdded", ""),
                "ransomware": v.get("knownRansomwareCampaignUse", "Unknown") != "Unknown",
            }
            for v in latest
        ],
    }


def _get_urlhaus_count():
    r = requests.get(
        "https://urlhaus.abuse.ch/downloads/csv_recent/",
        timeout=12,
        headers=HEADERS,
    )
    r.raise_for_status()
    lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
    # grab first 5 for the feed
    reader = csv.reader(lines[:5])
    recent = []
    for row in reader:
        if len(row) >= 6:
            recent.append({"indicator": row[2], "threat": row[5], "date": row[1]})
    return {"ok": True, "count": len(lines), "recent": recent}


def _get_feodo_count():
    r = requests.get(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        timeout=12,
        headers=HEADERS,
    )
    r.raise_for_status()
    data = r.json()
    recent = [
        {"indicator": d.get("ip_address", ""), "threat": d.get("malware", ""), "date": d.get("first_seen", "")}
        for d in data[:3]
    ]
    return {"ok": True, "count": len(data), "recent": recent}


def _get_bazaar_count():
    r = requests.get(
        "https://bazaar.abuse.ch/export/csv/recent/",
        timeout=12,
        headers=HEADERS,
    )
    r.raise_for_status()
    lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
    reader = csv.reader(lines[:5], skipinitialspace=True)
    recent = []
    for row in reader:
        if len(row) >= 7:
            sha256 = row[1].strip().strip('"')
            ftype = row[6].strip().strip('"')
            sig = row[8].strip().strip('"') if len(row) > 8 else ""
            threat = sig if sig and sig != "n/a" else ftype
            recent.append({"indicator": sha256[:20] + "…", "threat": threat, "date": row[0].strip().strip('"')})
    return {"ok": True, "count": len(lines), "recent": recent}


def _get_news_count():
    import feedparser
    feeds = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
    ]
    count = 0
    recent = []
    for url in feeds:
        try:
            resp = requests.get(url, timeout=8, headers=HEADERS)
            parsed = feedparser.parse(resp.content)
            items = parsed.entries[:3]
            count += len(parsed.entries)
            for e in items:
                recent.append({
                    "title": (e.get("title") or "")[:80],
                    "source": parsed.feed.get("title", "News")[:20],
                    "date": e.get("published", ""),
                })
        except Exception:
            pass
    return {"ok": True, "count": count, "recent": recent[:4]}


def _calc_risk_score(kev, urlhaus, feodo, bazaar):
    score = 30  # base
    # KEV new additions in last 7 days
    new_7d = kev.get("new_7d", 0)
    if new_7d >= 5:
        score += 25
    elif new_7d >= 2:
        score += 15
    elif new_7d >= 1:
        score += 8
    # Ransomware CVEs
    ransom = kev.get("ransomware_count", 0)
    if ransom > 100:
        score += 20
    elif ransom > 50:
        score += 12
    elif ransom > 10:
        score += 6
    # Active malware URLs
    url_count = urlhaus.get("count", 0)
    if url_count > 2000:
        score += 15
    elif url_count > 500:
        score += 8
    elif url_count > 100:
        score += 4
    # C2 IPs
    if feodo.get("count", 0) > 10:
        score += 5
    # Recent malware samples
    if bazaar.get("count", 0) > 50:
        score += 5

    score = min(score, 100)
    if score >= 80:
        level = "CRÍTICO"
    elif score >= 60:
        level = "ALTO"
    elif score >= 40:
        level = "MEDIO"
    else:
        level = "BAJO"

    return {"score": score, "level": level}


@overview_bp.route("/api/overview")
def get_overview():
    results = {}
    errors = {}

    tasks = {
        "kev": _get_kev,
        "urlhaus": _get_urlhaus_count,
        "feodo": _get_feodo_count,
        "bazaar": _get_bazaar_count,
        "news": _get_news_count,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {name: ex.submit(fn) for name, fn in tasks.items()}
        for name, future in futures.items():
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = {"ok": False, "count": 0, "recent": []}
                errors[name] = str(e)[:80]

    kev = results["kev"]
    urlhaus = results["urlhaus"]
    feodo = results["feodo"]
    bazaar = results["bazaar"]
    news = results["news"]

    risk = _calc_risk_score(kev, urlhaus, feodo, bazaar)

    total_iocs = urlhaus.get("count", 0) + feodo.get("count", 0) + bazaar.get("count", 0)

    return jsonify({
        "risk": risk,
        "kev": kev,
        "iocs": {
            "total": total_iocs,
            "urlhaus": urlhaus.get("count", 0),
            "feodo": feodo.get("count", 0),
            "bazaar": bazaar.get("count", 0),
        },
        "news": {"count": news.get("count", 0), "recent": news.get("recent", [])},
        "sources": {
            "NVD / CISA KEV": kev.get("ok", False),
            "URLhaus": urlhaus.get("ok", False),
            "Feodo Tracker": feodo.get("ok", False),
            "MalwareBazaar": bazaar.get("ok", False),
            "News RSS": news.get("ok", False),
        },
        "recent_kev": kev.get("latest", []),
        "recent_iocs": urlhaus.get("recent", [])[:3] + feodo.get("recent", [])[:2],
        "recent_news": news.get("recent", []),
        "errors": errors,
    })
