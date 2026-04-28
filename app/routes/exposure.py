from flask import Blueprint, jsonify, request
import requests
import socket
import re
import concurrent.futures

exposure_bp = Blueprint("exposure", __name__)

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; AletheiaOSINT/1.0)"}
_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def _resolve(domain):
    try:
        results = socket.getaddrinfo(domain, None)
        return list({r[4][0] for r in results if ':' not in r[4][0]})
    except Exception:
        return []


def _internetdb(ip):
    try:
        r = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=10,
            headers=HEADERS,
        )
        if r.status_code == 404:
            return {"ip": ip, "found": False, "ports": [], "hostnames": [], "vulns": [], "tags": [], "cpes": []}
        r.raise_for_status()
        d = r.json()
        return {
            "ip": ip,
            "found": True,
            "ports": d.get("ports", []),
            "hostnames": d.get("hostnames", []),
            "vulns": d.get("vulns", []),
            "tags": d.get("tags", []),
            "cpes": d.get("cpes", []),
        }
    except Exception as e:
        return {"ip": ip, "found": False, "ports": [], "hostnames": [], "vulns": [], "tags": [], "cpes": [], "error": str(e)[:80]}


@exposure_bp.route("/api/exposure")
def get_exposure():
    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400

    if _IP_RE.match(target):
        ips = [target]
    else:
        ips = _resolve(target)
        if not ips:
            return jsonify({"error": f"No se pudo resolver: {target}"}), 404

    ips = ips[:5]

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        results = list(ex.map(_internetdb, ips))

    all_ports = sorted({p for r in results for p in r.get("ports", [])})
    all_vulns = list({v for r in results for v in r.get("vulns", [])})
    all_tags  = list({t for r in results for t in r.get("tags", [])})

    return jsonify({
        "target": target,
        "ips": results,
        "summary": {
            "total_ips":   len(results),
            "found_ips":   sum(1 for r in results if r.get("found")),
            "total_ports": len(all_ports),
            "total_vulns": len(all_vulns),
            "all_ports":   all_ports,
            "all_vulns":   all_vulns[:30],
            "all_tags":    all_tags,
        },
    })
