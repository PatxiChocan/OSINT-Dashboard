from flask import Blueprint, jsonify, request
from app.routes.auth import role_required
from app.models import ROLE_ADMIN, ROLE_ANALYST
import requests
import os

urlscan_bp = Blueprint("urlscan", __name__)

API_KEY = os.getenv("URLSCAN_API_KEY", "")
BASE = "https://urlscan.io/api/v1"
HEADERS = {"User-Agent": "AletheiaOSINT/1.0", "Content-Type": "application/json"}


@urlscan_bp.route("/api/urlscan/search")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Parámetro q requerido"}), 400

    # Build search query: if it looks like a domain, use domain: prefix
    if not q.startswith("domain:") and not q.startswith("page."):
        query = f"domain:{q}"
    else:
        query = q

    try:
        r = requests.get(
            f"{BASE}/search/",
            params={"q": query, "size": 20},
            headers=HEADERS,
            timeout=15
        )
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502

    results = []
    for item in data.get("results", []):
        page = item.get("page", {})
        task = item.get("task", {})
        results.append({
            "id": item.get("_id", ""),
            "url": page.get("url", ""),
            "domain": page.get("domain", ""),
            "ip": page.get("ip", ""),
            "country": page.get("country", ""),
            "server": page.get("server", ""),
            "asn": page.get("asn", ""),
            "asnname": page.get("asnname", ""),
            "date": task.get("time", ""),
            "screenshot": f"https://urlscan.io/screenshots/{item.get('_id', '')}.png",
            "result_url": f"https://urlscan.io/result/{item.get('_id', '')}/",
            "malicious": item.get("verdicts", {}).get("overall", {}).get("malicious", False),
            "score": item.get("verdicts", {}).get("overall", {}).get("score", 0),
            "tags": item.get("verdicts", {}).get("overall", {}).get("tags", []),
        })

    return jsonify({
        "total": data.get("total", 0),
        "results": results
    })


@urlscan_bp.route("/api/urlscan/scan", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def scan():
    if not API_KEY:
        return jsonify({"error": "URLSCAN_API_KEY no configurada en .env"}), 403

    body = request.get_json(silent=True) or {}
    url = body.get("url", "").strip()
    if not url:
        return jsonify({"error": "Campo url requerido"}), 400

    if not url.startswith("http"):
        url = f"https://{url}"

    try:
        r = requests.post(
            f"{BASE}/scan/",
            json={"url": url, "visibility": "public"},
            headers={**HEADERS, "API-Key": API_KEY},
            timeout=20
        )
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502

    return jsonify({
        "uuid": data.get("uuid", ""),
        "result_url": data.get("result", ""),
        "api_url": data.get("api", ""),
        "message": data.get("message", "Escaneo enviado")
    })
