import os
import requests
import urllib3
from datetime import datetime, timezone
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


# ── STIX type → MISP attribute (type, category, to_ids) ──────────────────────
DEFAULT_TAGS = ["tlp:white", "osint", "type:OSINT"]

# ── STIX type → MISP attribute (type, category, to_ids) ──────────────────────
_STIX_TO_MISP = {
    "ipv4-addr":   ("ip-dst",   "Network activity", True),
    "ipv6-addr":   ("ip-dst",   "Network activity", True),
    "domain-name": ("domain",   "Network activity", True),
    "url":         ("url",      "Network activity", True),
    "email-addr":  ("email-src","Payload delivery",  False),
}

_HASH_TYPE_MAP = {
    "MD5":     "md5",
    "SHA-1":   "sha1",
    "SHA-256": "sha256",
    "SHA-512": "sha512",
}


def _stix_bundle_to_misp_event(bundle):
    """Convierte un bundle STIX 2.1 en un evento MISP con atributos."""
    objects = {o["id"]: o for o in bundle.get("objects", [])}

    # Extraer el report para nombre y descripción
    report = next((o for o in objects.values() if o.get("type") == "report"), {})
    event_name = report.get("name") or "OSINT Aletheia Export"
    description = report.get("description", "")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    attributes = []

    for obj in objects.values():
        otype = obj.get("type", "")

        # SCOs simples
        if otype in _STIX_TO_MISP:
            misp_type, category, to_ids = _STIX_TO_MISP[otype]
            value = obj.get("value")
            if value:
                attributes.append({
                    "type": misp_type,
                    "category": category,
                    "value": value,
                    "to_ids": to_ids,
                    "comment": f"Imported from STIX 2.1 ({otype})",
                })

        # Vulnerability → CVE
        elif otype == "vulnerability":
            name = obj.get("name", "")
            if name.upper().startswith("CVE-"):
                attributes.append({
                    "type": "vulnerability",
                    "category": "External analysis",
                    "value": name.upper(),
                    "to_ids": False,
                    "comment": "Imported from STIX 2.1",
                })

        # Indicator → extraer patrón STIX como atributo de texto
        elif otype == "indicator":
            pattern = obj.get("pattern", "")
            iname = obj.get("name", "")
            desc = obj.get("description", "")
            if pattern:
                attributes.append({
                    "type": "stix2-pattern",
                    "category": "External analysis",
                    "value": pattern,
                    "to_ids": True,
                    "comment": f"{iname} — {desc}"[:255],
                })

        # File hash
        elif otype == "file":
            hashes = obj.get("hashes", {})
            for stix_alg, misp_type in _HASH_TYPE_MAP.items():
                h = hashes.get(stix_alg)
                if h:
                    attributes.append({
                        "type": misp_type,
                        "category": "Payload delivery",
                        "value": h,
                        "to_ids": True,
                        "comment": f"File hash from STIX 2.1 ({obj.get('name', '')})",
                    })

    return {
        "Event": {
            "info": event_name,
            "date": today,
            "threat_level_id": "2",   # medium
            "analysis": "1",           # ongoing
            "distribution": "0",       # org only
            "Attribute": attributes,
            **({"description": description} if description else {}),
        }
    }


def _attach_tags(url, event_id, tags):
    """Añade tags a un evento MISP por nombre. Devuelve lista de tags fallidos."""
    failed = []
    for tag in tags:
        try:
            r = requests.post(
                f"{url}/events/addTag",
                json={"event": str(event_id), "tag": tag},
                headers=_headers(),
                timeout=8,
                verify=False,
            )
            if r.status_code not in (200, 201):
                failed.append(tag)
        except Exception:
            failed.append(tag)
    return failed


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

    misp_event = _stix_bundle_to_misp_event(bundle)
    attr_count = len(misp_event["Event"]["Attribute"])

    try:
        r = requests.post(
            f"{url}/events/add",
            json=misp_event,
            headers=_headers(),
            timeout=30,
            verify=False,
        )
        data = r.json() if r.content else {}

        if r.status_code not in (200, 201):
            msg = (data.get("message") or data.get("errors") or r.text)[:300]
            return jsonify({"ok": False, "error": f"MISP respondió {r.status_code}: {msg}"}), 502

        event = data.get("Event", data)
        eid = event.get("id")
        euuid = event.get("uuid")

        events = []
        if eid:
            events.append({"id": str(eid), "url": f"{url}/events/view/{eid}"})
        elif euuid:
            events.append({"id": euuid, "url": f"{url}/events/view/{euuid}"})

        # Añadir tags por defecto
        tags_failed = []
        if eid:
            tags_failed = _attach_tags(url, eid, DEFAULT_TAGS)

        tags_ok = [t for t in DEFAULT_TAGS if t not in tags_failed]

        return jsonify({
            "ok": True,
            "events": events,
            "misp_url": url,
            "attr_count": attr_count,
            "tags": tags_ok,
            "tags_failed": tags_failed,
        })

    except requests.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": f"No se puede conectar con {url}"}), 502
    except requests.exceptions.Timeout:
        return jsonify({"ok": False, "error": "MISP tardó demasiado en responder (>30s)"}), 504
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
