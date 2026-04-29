from flask import Blueprint, jsonify, request
import requests
import os
import re
import base64

vt_bp = Blueprint("virustotal", __name__)

API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
BASE = "https://www.virustotal.com/api/v3"

_IP_RE   = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_HASH_RE = re.compile(r'^[0-9a-fA-F]{32,64}$')
_URL_RE  = re.compile(r'^https?://', re.IGNORECASE)


def _headers():
    return {"x-apikey": API_KEY}


def _detect_type(target):
    if _IP_RE.match(target):
        return "ip"
    if _HASH_RE.match(target):
        return "hash"
    if _URL_RE.match(target):
        return "url"
    return "domain"


def _verdict(stats):
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    if mal >= 3:
        return "malicious"
    if mal >= 1 or sus >= 3:
        return "suspicious"
    return "clean"


def _parse(data):
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    flagged = [
        {"engine": eng, "category": r.get("category"), "result": r.get("result", "")}
        for eng, r in results.items()
        if r.get("category") in ("malicious", "suspicious")
    ]

    ts = attrs.get("last_analysis_date")
    date_str = ""
    if ts:
        from datetime import datetime, timezone
        date_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return {
        "stats": stats,
        "verdict": _verdict(stats),
        "total_engines": sum(stats.values()),
        "flagged": sorted(flagged, key=lambda x: x["category"] == "malicious", reverse=True)[:30],
        "reputation": attrs.get("reputation", 0),
        "last_analysis_date": date_str,
        "categories": attrs.get("categories", {}),
        "tags": attrs.get("tags", [])[:10],
        "country": attrs.get("country", ""),
        "as_owner": attrs.get("as_owner", ""),
        "registrar": attrs.get("registrar", ""),
        "creation_date": attrs.get("creation_date", ""),
        "meaningful_name": attrs.get("meaningful_name", ""),
        "type_description": attrs.get("type_description", ""),
        "size": attrs.get("size"),
    }


@vt_bp.route("/api/virustotal")
def vt_lookup():
    if not API_KEY:
        return jsonify({"error": "VIRUSTOTAL_API_KEY no configurada en .env"}), 400

    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "Introduce un objetivo"}), 400

    ttype = _detect_type(target)

    try:
        if ttype == "ip":
            r = requests.get(f"{BASE}/ip_addresses/{target}", headers=_headers(), timeout=12)
        elif ttype == "domain":
            r = requests.get(f"{BASE}/domains/{target}", headers=_headers(), timeout=12)
        elif ttype == "hash":
            r = requests.get(f"{BASE}/files/{target}", headers=_headers(), timeout=12)
        else:
            # URL: use base64url ID to avoid submitting
            url_id = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
            r = requests.get(f"{BASE}/urls/{url_id}", headers=_headers(), timeout=12)
            if r.status_code == 404:
                # Submit and return pending state
                resp = requests.post(f"{BASE}/urls", headers=_headers(),
                                     data={"url": target}, timeout=12)
                resp.raise_for_status()
                analysis_id = resp.json()["data"]["id"]
                r2 = requests.get(f"{BASE}/analyses/{analysis_id}",
                                  headers=_headers(), timeout=12)
                r2.raise_for_status()
                a = r2.json().get("data", {}).get("attributes", {})
                if a.get("status") == "queued":
                    return jsonify({"pending": True, "message": "URL enviada para análisis. Vuelve a consultar en 30s."})
                r = r2

        r.raise_for_status()
        data = r.json().get("data", {})
        result = _parse(data)
        result["target"] = target
        result["type"] = ttype
        return jsonify(result)

    except requests.HTTPError as e:
        code = e.response.status_code
        if code == 404:
            return jsonify({"error": "No encontrado en VirusTotal"}), 404
        if code == 401:
            return jsonify({"error": "API key inválida"}), 401
        if code == 429:
            return jsonify({"error": "Límite de requests alcanzado (4/min en free tier)"}), 429
        return jsonify({"error": f"Error VirusTotal: {code}"}), code
    except Exception as e:
        return jsonify({"error": str(e)}), 500
