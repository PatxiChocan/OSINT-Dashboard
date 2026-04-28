from flask import Blueprint, jsonify
import requests
import time
import concurrent.futures
from datetime import datetime, timezone

sources_bp = Blueprint("sources", __name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; AletheiaOSINT/1.0)"}

SOURCES = [
    # ── CVE ──────────────────────────────────────────────────────────────────
    {
        "id": "cisa_kev",
        "name": "CISA KEV",
        "category": "CVE",
        "description": "Known Exploited Vulnerabilities catalog (US-CERT/CISA)",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    },
    {
        "id": "nvd",
        "name": "NVD API",
        "category": "CVE",
        "description": "National Vulnerability Database REST API v2 (NIST)",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1",
    },
    # ── IOC ──────────────────────────────────────────────────────────────────
    {
        "id": "urlhaus",
        "name": "URLhaus",
        "category": "IOC",
        "description": "Malicious URL tracking feed (abuse.ch)",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    },
    {
        "id": "feodo",
        "name": "Feodo Tracker",
        "category": "IOC",
        "description": "C2 IP blocklist — botnet tracking (abuse.ch)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    },
    {
        "id": "bazaar",
        "name": "MalwareBazaar",
        "category": "IOC",
        "description": "Recent malware sample hashes (abuse.ch)",
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
    },
    # ── Exposición ───────────────────────────────────────────────────────────
    {
        "id": "shodan_internetdb",
        "name": "Shodan InternetDB",
        "category": "Exposure",
        "description": "Información de puertos, servicios y CVEs por IP (Shodan, sin auth)",
        "url": "https://internetdb.shodan.io/1.1.1.1",
    },
    # ── Filtraciones ─────────────────────────────────────────────────────────
    {
        "id": "intelx",
        "name": "Intelligence X",
        "category": "Breaches",
        "description": "Búsqueda en pastes, dark web y filtraciones — intelx.io (API key requerida)",
        "url": "https://2.intelx.io/hello",
    },
    {
        "id": "h8mail_leaklookup",
        "name": "h8mail / Leak-Lookup",
        "category": "Breaches",
        "description": "Brechas por email vía h8mail + Leak-Lookup public API (sin auth)",
        "url": "https://leak-lookup.com",
    },
    # ── News RSS ──────────────────────────────────────────────────────────────
    {
        "id": "incibe",
        "name": "INCIBE-AVISOS",
        "category": "News",
        "description": "Alertas tempranas de ciberseguridad — España (INCIBE-CERT)",
        "url": "https://www.incibe.es/index.php/incibe-cert/alerta-temprana/avisos/feed",
    },
    {
        "id": "hackplayers",
        "name": "HackPlayers",
        "category": "News",
        "description": "Blog de ciberseguridad en español",
        "url": "https://www.hackplayers.com/feeds/posts/default?alt=rss",
    },
    {
        "id": "hispasec",
        "name": "Hispasec",
        "category": "News",
        "description": "Una-al-día — noticias de seguridad en español",
        "url": "https://unaaldia.hispasec.com/feed",
    },
    {
        "id": "cybersecuritynews_es",
        "name": "CyberSecurity News ES",
        "category": "News",
        "description": "Noticias de ciberseguridad en español",
        "url": "https://cybersecuritynews.es/feed/",
    },
    {
        "id": "theregister",
        "name": "The Register",
        "category": "News",
        "description": "UK technology and security news",
        "url": "https://www.theregister.com/security/headlines.atom",
    },
    {
        "id": "grahamcluley",
        "name": "Graham Cluley",
        "category": "News",
        "description": "Independent cybersecurity blogger",
        "url": "https://grahamcluley.com/feed/",
    },
    {
        "id": "infosecurity",
        "name": "Infosecurity Magazine",
        "category": "News",
        "description": "European information security magazine",
        "url": "https://www.infosecurity-magazine.com/rss/news/",
    },
    {
        "id": "thehackernews",
        "name": "The Hacker News",
        "category": "News",
        "description": "Global cybersecurity news and analysis",
        "url": "https://feeds.feedburner.com/TheHackersNews",
    },
    {
        "id": "bleepingcomputer",
        "name": "BleepingComputer",
        "category": "News",
        "description": "Security and technology news",
        "url": "https://www.bleepingcomputer.com/feed/",
    },
    {
        "id": "krebsonsecurity",
        "name": "Krebs on Security",
        "category": "News",
        "description": "In-depth security news by Brian Krebs",
        "url": "https://krebsonsecurity.com/feed/",
    },
    {
        "id": "darkreading",
        "name": "Dark Reading",
        "category": "News",
        "description": "Cybersecurity news and expert analysis",
        "url": "https://www.darkreading.com/rss.xml",
    },
    {
        "id": "cisa_alerts",
        "name": "CISA Alerts",
        "category": "News",
        "description": "Official CISA cybersecurity advisories feed",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    },
]


def _check_source(source):
    url = source["url"]
    start = time.monotonic()
    ok = False
    status_code = None
    error = None

    try:
        r = requests.head(url, timeout=8, headers=HEADERS, allow_redirects=True)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        if r.status_code == 405:
            # HEAD not supported — try GET with stream to avoid downloading body
            start2 = time.monotonic()
            r2 = requests.get(url, timeout=8, headers=HEADERS, stream=True)
            r2.close()
            elapsed_ms = int((time.monotonic() - start2) * 1000)
            ok = r2.status_code < 400
            status_code = r2.status_code
        else:
            ok = r.status_code < 400
            status_code = r.status_code

    except requests.exceptions.Timeout:
        elapsed_ms = 8000
        error = "Timeout (>8s)"
    except requests.exceptions.ConnectionError:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        error = "Connection error"
    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        error = str(e)[:60]

    return {
        "id": source["id"],
        "name": source["name"],
        "category": source["category"],
        "description": source["description"],
        "url": source["url"],
        "ok": ok,
        "status_code": status_code,
        "response_ms": elapsed_ms,
        "error": error,
        "checked_at": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
    }


@sources_bp.route("/api/sources")
def get_sources():
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        results = list(ex.map(_check_source, SOURCES))

    online = sum(1 for r in results if r["ok"])
    ok_times = [r["response_ms"] for r in results if r["ok"]]
    avg_ms = int(sum(ok_times) / len(ok_times)) if ok_times else 0

    return jsonify({
        "sources": results,
        "summary": {
            "total": len(results),
            "online": online,
            "offline": len(results) - online,
            "avg_response_ms": avg_ms,
        },
        "checked_at": datetime.now(timezone.utc).isoformat(),
    })
