from flask import Blueprint, jsonify, request
from app.routes.auth import role_required
from app.models import ROLE_ADMIN, ROLE_ANALYST
import subprocess
import threading
import signal
import os
import re
import uuid

nmap_discover_bp = Blueprint("nmap_discover", __name__)

CIDR_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$')

_scans = {}
_lock  = threading.Lock()


@nmap_discover_bp.route("/api/nmap/discover", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def discover():
    body   = request.get_json(silent=True) or {}
    ranges = [r.strip() for r in body.get("ranges", []) if r.strip()]

    if not ranges:
        return jsonify({"error": "No se han proporcionado rangos IP"}), 400

    for r in ranges:
        if not CIDR_RE.match(r):
            return jsonify({"error": f"Formato CIDR inválido: {r}"}), 400

    scan_id = str(uuid.uuid4())

    with _lock:
        _scans[scan_id] = {"status": "running", "hosts": [], "process": None, "error": None}

    def run_scan():
        for cidr in ranges:
            with _lock:
                if _scans[scan_id]["status"] in ("stopped", "error"):
                    return

            try:
                proc = subprocess.Popen(
                    ["/usr/bin/nmap", "-sn", "-oG", "-", cidr],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, start_new_session=True
                )
                with _lock:
                    _scans[scan_id]["process"] = proc

                stdout, _ = proc.communicate(timeout=180)

                with _lock:
                    if _scans[scan_id]["status"] == "stopped":
                        return

                for line in stdout.splitlines():
                    m = re.match(r'^Host:\s+([\d.]+)', line)
                    if m:
                        ip = m.group(1)
                        with _lock:
                            if ip not in _scans[scan_id]["hosts"]:
                                _scans[scan_id]["hosts"].append(ip)

            except subprocess.TimeoutExpired:
                proc.kill()
                with _lock:
                    _scans[scan_id]["status"] = "error"
                    _scans[scan_id]["error"]  = f"Timeout escaneando {cidr} (>180s)"
                return
            except Exception as e:
                with _lock:
                    _scans[scan_id]["status"] = "error"
                    _scans[scan_id]["error"]  = str(e)
                return

        with _lock:
            if _scans[scan_id]["status"] == "running":
                _scans[scan_id]["status"] = "done"

    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"scan_id": scan_id})


@nmap_discover_bp.route("/api/nmap/status/<scan_id>")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def status(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Escaneo no encontrado"}), 404
    return jsonify({
        "status": scan["status"],
        "hosts":  scan["hosts"],
        "count":  len(scan["hosts"]),
        "error":  scan["error"],
    })


@nmap_discover_bp.route("/api/nmap/stop/<scan_id>", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def stop(scan_id):
    with _lock:
        scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"ok": False, "error": "Escaneo no encontrado"}), 404

    with _lock:
        scan["status"] = "stopped"
        proc = scan.get("process")

    if proc:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    return jsonify({"ok": True})
