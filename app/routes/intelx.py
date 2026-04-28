import os
import time
import requests
from flask import Blueprint, jsonify, request

intelx_bp = Blueprint("intelx", __name__)

_API_KEY = os.getenv("INTELX_API_KEY", "")
_BASE = "https://free.intelx.io"

_STYPES = {
    1: "dominio", 2: "email", 3: "URL", 8: "teléfono",
    10: "IP", 22: "Bitcoin", 32: "IBAN",
}


@intelx_bp.route("/api/intelx")
def search_intelx():
    term = request.args.get("target", "").strip()
    if not term:
        return jsonify({"error": "No target provided"}), 400

    if not _API_KEY:
        return jsonify({"error": "INTELX_API_KEY no configurada — añádela al .env"}), 503

    headers = {"x-key": _API_KEY, "Content-Type": "application/json"}
    payload = {"term": term, "maxresults": 100, "media": 0, "sort": 4, "terminate": []}

    try:
        r = requests.post(
            f"{_BASE}/intelligent/search",
            headers=headers,
            json=payload,
            timeout=15,
        )
        r.raise_for_status()
        search_id = r.json().get("id")
        if not search_id:
            return jsonify({"error": f"IntelX no devolvió ID — respuesta: {r.text[:200]}"}), 502
    except requests.RequestException as e:
        return jsonify({"error": f"Error al contactar IntelX: {str(e)[:200]}"}), 502

    time.sleep(2)

    try:
        r = requests.get(
            f"{_BASE}/intelligent/search/result",
            headers={"x-key": _API_KEY},
            params={"id": search_id, "limit": 100, "offset": 0},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        return jsonify({"error": f"Error al obtener resultados: {str(e)[:200]}"}), 502

    records = data.get("records") or []
    results = [
        {
            "name":      rec.get("name", ""),
            "bucket":    rec.get("bucket", ""),
            "date":      (rec.get("date") or rec.get("added") or "")[:10],
            "size":      rec.get("size", 0),
            "storageid": rec.get("storageid", ""),
        }
        for rec in records
    ]

    return jsonify({
        "term":    term,
        "total":   data.get("total", len(results)),
        "results": results,
    })
