import os
import requests
import urllib3
from flask import Blueprint, jsonify, request

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

misp_bp = Blueprint("misp", __name__)

_MISP_URL = lambda: os.getenv("MISP_URL", "").rstrip("/")
_MISP_KEY = lambda: os.getenv("MISP_API_KEY", "")


def _headers():
    return {
        "Authorization": _MISP_KEY(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


@misp_bp.route("/api/misp/status")
def misp_status():
    url = _MISP_URL()
    key = _MISP_KEY()
    if not url or not key:
        return jsonify({"configured": False})
    try:
        r = requests.get(
            f"{url}/servers/getPyMISPVersion.json",
            headers=_headers(),
            timeout=8,
            verify=False,
        )
        ok = r.status_code == 200
        return jsonify({"configured": True, "reachable": ok, "url": url})
    except Exception:
        return jsonify({"configured": True, "reachable": False, "url": url})


@misp_bp.route("/api/misp/push", methods=["POST"])
def push_to_misp():
    url = _MISP_URL()
    key = _MISP_KEY()
    if not url or not key:
        return jsonify({"ok": False, "error": "MISP_URL o MISP_API_KEY no configuradas en .env"}), 503

    bundle = request.get_json(silent=True)
    if not bundle:
        return jsonify({"ok": False, "error": "No se recibió bundle JSON"}), 400

    try:
        r = requests.post(
            f"{url}/events/stix2",
            json=bundle,
            headers=_headers(),
            timeout=30,
            verify=False,
        )
        data = r.json() if r.content else {}

        if r.status_code not in (200, 201):
            msg = data.get("message") or data.get("errors") or r.text[:300]
            return jsonify({"ok": False, "error": f"MISP respondió {r.status_code}: {msg}"}), 502

        # Extract created event IDs/URLs
        events = []
        if isinstance(data, list):
            for item in data:
                eid = item.get("Event", {}).get("id") or item.get("id")
                if eid:
                    events.append({"id": eid, "url": f"{url}/events/view/{eid}"})
        elif isinstance(data, dict):
            eid = data.get("Event", {}).get("id") or data.get("id")
            if eid:
                events.append({"id": eid, "url": f"{url}/events/view/{eid}"})

        return jsonify({"ok": True, "events": events, "misp_url": url})

    except requests.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": f"No se puede conectar con {url} — ¿está MISP arriba?"}), 502
    except requests.exceptions.Timeout:
        return jsonify({"ok": False, "error": "MISP tardó demasiado en responder (>30s)"}), 504
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
