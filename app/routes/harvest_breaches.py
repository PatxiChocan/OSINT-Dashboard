import os
import re
import json
import subprocess
import tempfile
from flask import Blueprint, jsonify, request

harvest_bp = Blueprint("harvest", __name__)

_CONFIG   = os.path.join(os.path.dirname(__file__), "../../h8mail.ini")
_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_SOURCES  = "crtsh,certspotter,hackertarget,duckduckgo"
_MAX_EMAILS = 10


@harvest_bp.route("/api/harvest-breaches")
def harvest_breaches():
    domain = request.args.get("target", "").strip().lower()
    if not domain:
        return jsonify({"error": "No target provided"}), 400

    # Step 1: theHarvester — find emails for the domain
    try:
        proc = subprocess.run(
            ["theHarvester", "-d", domain, "-b", _SOURCES],
            capture_output=True, text=True, timeout=50,
        )
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return jsonify({"error": "theHarvester tardó demasiado (>50s)"}), 408
    except FileNotFoundError:
        return jsonify({"error": "theHarvester no encontrado en el sistema"}), 503
    except Exception as e:
        return jsonify({"error": f"Error ejecutando theHarvester: {str(e)[:120]}"}), 500

    emails = list({e.lower() for e in _EMAIL_RE.findall(output) if domain in e.lower()})[:_MAX_EMAILS]

    if not emails:
        return jsonify({
            "domain":       domain,
            "emails_found": 0,
            "results":      [],
            "note":         "theHarvester no encontró emails en crtsh, certspotter, hackertarget ni DuckDuckGo",
        })

    # Step 2: h8mail — breach lookup for each email
    results = []
    for email in emails:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        try:
            subprocess.run(
                ["h8mail", "-t", email, "-c", _CONFIG, "-j", json_path],
                capture_output=True, text=True, timeout=30,
            )
            with open(json_path) as f:
                raw = json.load(f)
            for entry in raw.get("targets", []):
                sources = []
                for group in entry.get("data", []):
                    for item in group:
                        if ":" in item:
                            src, breach = item.split(":", 1)
                            sources.append({"source": src, "breach": breach})
                        else:
                            sources.append({"source": item, "breach": ""})
                results.append({
                    "target":  entry.get("target", email),
                    "pwn_num": entry.get("pwn_num", 0),
                    "sources": sources,
                })
        except Exception:
            results.append({"target": email, "pwn_num": 0, "sources": [], "skipped": True})
        finally:
            try:
                os.unlink(json_path)
            except OSError:
                pass

    return jsonify({
        "domain":       domain,
        "emails_found": len(emails),
        "results":      results,
    })
