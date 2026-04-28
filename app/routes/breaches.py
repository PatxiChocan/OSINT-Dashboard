from flask import Blueprint, jsonify, request
import subprocess
import tempfile
import json
import os
import re

breaches_bp = Blueprint("breaches", __name__)

_CONFIG   = os.path.join(os.path.dirname(__file__), "../../h8mail.ini")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@breaches_bp.route("/api/breaches")
def get_breaches():
    target = request.args.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400

    if not _EMAIL_RE.match(target):
        return jsonify({"error": "h8mail solo acepta emails (ej: usuario@empresa.com). Para buscar por dominio prueba con emails específicos de ese dominio."}), 400

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        json_path = f.name

    try:
        subprocess.run(
            ["h8mail", "-t", target, "-c", _CONFIG, "-j", json_path],
            capture_output=True,
            text=True,
            timeout=30,
        )

        with open(json_path) as f:
            raw = json.load(f)

        results = []
        for entry in raw.get("targets", []):
            sources = []
            for group in entry.get("data", []):
                for item in group:
                    # Format: "SOURCE:breach_name"
                    if ":" in item:
                        src, breach = item.split(":", 1)
                        sources.append({"source": src, "breach": breach})
                    else:
                        sources.append({"source": item, "breach": ""})
            results.append({
                "target":  entry.get("target", ""),
                "pwn_num": entry.get("pwn_num", 0),
                "sources": sources,
            })

        return jsonify({"results": results})

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout — h8mail tardó demasiado"}), 408
    except Exception as e:
        return jsonify({"error": str(e)[:120]}), 500
    finally:
        try:
            os.unlink(json_path)
        except OSError:
            pass
