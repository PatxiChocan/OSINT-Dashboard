from flask import Blueprint, jsonify, request
import requests
import socket
import os
import re
import concurrent.futures

shodan_full_bp = Blueprint("shodan_full", __name__)

API_KEY = os.getenv("SHODAN_API_KEY", "")
BASE    = "https://api.shodan.io"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; AletheiaOSINT/1.0)"}

_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def _resolve(domain):
    try:
        results = socket.getaddrinfo(domain, None)
        return list({r[4][0] for r in results if ':' not in r[4][0]})
    except Exception:
        return []


def _parse_cert(cert):
    if not cert:
        return {}
    subj = cert.get("subject", {})
    iss  = cert.get("issuer", {})
    exp  = cert.get("expires", "")
    exp_fmt = f"{exp[:4]}-{exp[4:6]}-{exp[6:8]}" if len(exp) >= 8 else exp
    return {
        "subject_cn": subj.get("CN", "") or subj.get("O", ""),
        "issuer_cn":  iss.get("CN", "") or iss.get("O", ""),
        "expires":    exp_fmt,
    }


def _parse_service(item):
    svc = {
        "port":      item.get("port"),
        "transport": item.get("transport", "tcp"),
        "module":    item.get("_shodan", {}).get("module", ""),
        "product":   item.get("product", ""),
        "version":   item.get("version", ""),
        "cpe":       item.get("cpe", []),
        "timestamp": (item.get("timestamp", "") or "")[:10],
        "banner":    "",
        "http":      None,
        "ssl":       None,
    }
    raw = (item.get("data") or "").strip()
    lines = [l for l in raw.splitlines() if l.strip()][:3]
    svc["banner"] = "\n".join(lines)

    http = item.get("http")
    if http:
        svc["http"] = {
            "status": http.get("status"),
            "server": http.get("server", ""),
            "title":  (http.get("title") or "")[:80],
        }

    ssl = item.get("ssl")
    if ssl:
        svc["ssl"] = {
            "cert":     _parse_cert(ssl.get("cert", {})),
            "cipher":   ssl.get("cipher", {}),
            "versions": [v for v in ssl.get("versions", []) if not v.startswith("-")],
        }

    return svc


def _shodan_api(ip):
    r = requests.get(
        f"{BASE}/shodan/host/{ip}",
        params={"key": API_KEY},
        timeout=15,
        headers=HEADERS,
    )
    r.raise_for_status()
    data = r.json()
    services = sorted([_parse_service(i) for i in data.get("data", [])],
                      key=lambda x: x["port"] or 0)
    vulns = list(data.get("vulns", {}).keys()) if data.get("vulns") else []
    return {
        "source":   "shodan",
        "ip":       data.get("ip_str", ip),
        "org":      data.get("org", ""),
        "isp":      data.get("isp", ""),
        "asn":      data.get("asn", ""),
        "country":  data.get("country_name", ""),
        "city":     data.get("city", ""),
        "region":   data.get("region_code", ""),
        "os":       data.get("os") or "",
        "hostnames":data.get("hostnames", [])[:10],
        "domains":  data.get("domains", [])[:10],
        "tags":     data.get("tags", []),
        "ports":    sorted(data.get("ports", [])),
        "last_update": (data.get("last_update") or "")[:10],
        "services": services,
        "vulns":    vulns,
    }


def _internetdb(ip):
    r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10, headers=HEADERS)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    d = r.json()
    # Build minimal service stubs from port list
    services = [{"port": p, "transport": "tcp", "module": "", "product": "",
                 "version": "", "cpe": [], "timestamp": "", "banner": "",
                 "http": None, "ssl": None}
                for p in sorted(d.get("ports", []))]
    return {
        "source":    "internetdb",
        "ports":     sorted(d.get("ports", [])),
        "hostnames": d.get("hostnames", [])[:10],
        "domains":   [],
        "vulns":     d.get("vulns", []),
        "tags":      d.get("tags", []),
        "cpes":      d.get("cpes", []),
        "services":  services,
    }


def _ipapi(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,isp,org,as,query"},
            timeout=8, headers=HEADERS,
        )
        d = r.json()
        if d.get("status") != "success":
            return {}
        return {
            "country": d.get("country", ""),
            "city":    d.get("city", ""),
            "isp":     d.get("isp", ""),
            "org":     d.get("org", ""),
            "asn":     d.get("as", ""),
        }
    except Exception:
        return {}


@shodan_full_bp.route("/api/shodan-full")
def shodan_lookup():
    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "Introduce un objetivo"}), 400

    if _IP_RE.match(target):
        ips = [target]
    else:
        ips = _resolve(target)
        if not ips:
            return jsonify({"error": f"No se pudo resolver {target}"}), 404

    ip = ips[0]

    # Try full Shodan API first; fall back to InternetDB + ip-api
    if API_KEY:
        try:
            return jsonify({"target": target, **_shodan_api(ip)})
        except requests.HTTPError as e:
            if e.response.status_code not in (403, 404):
                return jsonify({"error": f"Error Shodan: {e.response.status_code}"}), e.response.status_code
        except Exception:
            pass

    # Fallback
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f_idb = ex.submit(_internetdb, ip)
            f_geo = ex.submit(_ipapi, ip)
            idb = f_idb.result()
            geo = f_geo.result() if not f_geo.exception() else {}
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if idb is None:
        idb = {"source": "internetdb", "ports": [], "hostnames": [], "domains": [],
               "vulns": [], "tags": [], "cpes": [], "services": []}

    return jsonify({
        "target":    target,
        "source":    "internetdb",
        "ip":        ip,
        "org":       geo.get("org", ""),
        "isp":       geo.get("isp", ""),
        "asn":       geo.get("asn", ""),
        "country":   geo.get("country", ""),
        "city":      geo.get("city", ""),
        "region":    "",
        "os":        "",
        "hostnames": idb.get("hostnames", []),
        "domains":   idb.get("domains", []),
        "tags":      idb.get("tags", []),
        "ports":     idb.get("ports", []),
        "last_update": "",
        "services":  idb.get("services", []),
        "vulns":     idb.get("vulns", []),
        "cpes":      idb.get("cpes", []),
    })
