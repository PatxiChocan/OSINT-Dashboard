from flask import Blueprint, jsonify
import feedparser
import concurrent.futures
import re
import requests
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

news_bp = Blueprint("news", __name__)

FEEDS = [
    {"name": "INCIBE-AVISOS", "url": "https://www.incibe.es/index.php/incibe-cert/alerta-temprana/avisos/feed", "region": "spain"},
    {"name": "HackPlayers", "url": "https://www.hackplayers.com/feeds/posts/default?alt=rss", "region": "spain"},
    {"name": "Hispasec", "url": "https://unaaldia.hispasec.com/feed", "region": "spain"},
    {"name": "CyberSecurity News ES", "url": "https://cybersecuritynews.es/feed/", "region": "spain"},
    {"name": "The Register", "url": "https://www.theregister.com/security/headlines.atom", "region": "europe"},
    {"name": "Graham Cluley", "url": "https://grahamcluley.com/feed/", "region": "europe"},
    {"name": "Infosecurity Magazine", "url": "https://www.infosecurity-magazine.com/rss/news/", "region": "europe"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "region": "world"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "region": "world"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "region": "world"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "region": "world"},
    {"name": "CISA Alerts", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "region": "world"},
]

CATEGORIES = [
    ("vulnerability", r"cve|vulnerabilidad|exploit|zero.?day|0-day|rce|patch|parche|buffer overflow|sql injection|xss"),
    ("malware", r"ransomware|malware|trojan|backdoor|botnet|spyware|rootkit|worm|virus|stealer"),
    ("phishing", r"phishing|smishing|vishing|estafa|fraude|suplantaci|ingeni.+social|credential|spear"),
    ("breach", r"breach|filtrac|data leak|datos expuestos|robo de datos|hackeo|compromiso|exfiltrac"),
    ("apt", r"apt|threat actor|nation.?state|espionaje|advanced persistent|campaign"),
    ("compliance", r"gdpr|rgpd|cumplimiento|normativa|regulaci|nis2|ens|compliance|iso 27001"),
    ("tools", r"herramienta|tool|framework|pentest|red team|ctf|poc|exploit kit|scanner"),
]


def categorize(title, desc):
    text = f"{title} {desc}".lower()
    for cat, pattern in CATEGORIES:
        if re.search(pattern, text):
            return cat
    return "general"


def parse_date_safe(d):
    if not d:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return parsedate_to_datetime(d)
    except Exception:
        try:
            return datetime.fromisoformat(d.replace("Z", "+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)


def fetch_feed(feed_info):
    try:
        resp = requests.get(feed_info["url"], timeout=10, headers={
            "User-Agent": "Mozilla/5.0 (compatible; AletheiaOSINT/1.0)"
        })
        resp.raise_for_status()
        parsed = feedparser.parse(resp.content)
        items = []
        for entry in parsed.entries[:20]:
            title = entry.get("title", "").strip()
            raw_desc = ""
            if entry.get("content"):
                raw_desc = entry["content"][0].get("value", "")
            elif entry.get("summary"):
                raw_desc = entry["summary"]
            desc = re.sub(r"<[^>]+>", "", raw_desc)[:300].strip()
            link = entry.get("link", "#")
            date = entry.get("published", entry.get("updated", ""))
            if title:
                items.append({
                    "title": title,
                    "description": desc,
                    "link": link,
                    "date": date,
                    "source": feed_info["name"],
                    "region": feed_info["region"],
                    "category": categorize(title, desc),
                })
        return items
    except Exception:
        return []


@news_bp.route("/api/news")
def get_news():
    all_news = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        for items in executor.map(fetch_feed, FEEDS):
            all_news.extend(items)

    seen = set()
    unique_news = []
    for item in all_news:
        key = item["title"].lower()[:60]
        if key not in seen:
            seen.add(key)
            unique_news.append(item)

    unique_news.sort(key=lambda x: parse_date_safe(x["date"]), reverse=True)

    return jsonify({"count": len(unique_news), "news": unique_news})
