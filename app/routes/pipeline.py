import json
import time
from flask import Blueprint, request, jsonify, Response, stream_with_context, session, render_template, make_response
from app.routes.auth import role_required
from app.models import ROLE_ADMIN, ROLE_ANALYST, PipelineAnalysis, ManualAnalysis, User
from app.extensions import db
from app.services.pipeline_service import create_pipeline, create_pipeline_single, get_events, get_findings, get_pipeline_data, score_label
from app.utils import to_local

pipeline_bp = Blueprint("pipeline", __name__)

_SEV_ORDER   = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}
_OT_PORTS    = {102, 502, 789, 1911, 1962, 2404, 4000, 4840, 9600, 18245, 20000, 44818, 47808}
_OT_KEYWORDS = {
    "modbus", "siemens s7", "iso-tsap", "ethernet/ip", "enip", "bacnet", "dnp3",
    "omron fins", "ge srtp", "opc ua", "opc da", "niagara", "tridium", "ignition",
    "wonderware", "scada", "hmi expuesta", "plc expuesto", "sistema de control industrial",
    "dcs", "rtu expuesto", "ems ", "bms expuesto", "historian industrial",
}
_CSF_BY_TOOL = {
    "whois": "GV", "dns": "ID", "subfinder": "ID", "crt.sh": "ID",
    "nmap": "PR", "shodan": "PR", "exposure": "PR", "virustotal": "DE",
    "urlscan": "DE", "intelx": "ID", "harvester": "ID", "blackbird": "ID",
    "sherlock": "ID", "maigret": "ID", "variants": "ID",
}
_SKIP_RECS = {
    "Sin alertas. Monitoriza periódicamente.",
    "Continúa monitorizando periódicamente.",
    "Mantén la privacy protection activa.",
}


def build_report_pdf_bytes(seeds, assets, findings, score, date_str, analysis_type="pipeline"):
    """Generate PDF bytes from analysis data. Shared by pipeline, manual and published reports."""
    from weasyprint import HTML as WeasyHTML

    findings = sorted(findings, key=lambda f: (
        _SEV_ORDER.get(f.get("severity", "info"), 99),
        (f.get("asset") or "").lower(),
    ))

    ot_findings = []
    for f in findings:
        title_lower = (f.get("title") or "").lower()
        is_ot = any(kw in title_lower for kw in _OT_KEYWORDS)
        if not is_ot:
            for p in _OT_PORTS:
                if f"puerto {p}/" in title_lower or f":{p} " in title_lower:
                    is_ot = True
                    break
        if is_ot:
            ot_findings.append({"asset": f.get("asset", ""), "title": f.get("title", ""), "severity": f.get("severity", "")})

    def _csf(f):
        t = (f.get("title") or "").lower()
        if "cve-" in t:
            return "PR"
        if any(x in t for x in ["malicioso", "malware"]):
            return "DE"
        return _CSF_BY_TOOL.get(f.get("tool", ""), "ID")

    findings = [{**f, "csf": _csf(f)} for f in findings]

    counts = {
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "high":     sum(1 for f in findings if f.get("severity") == "high"),
        "medium":   sum(1 for f in findings if f.get("severity") == "medium"),
        "info":     sum(1 for f in findings if f.get("severity") == "info"),
    }

    if score >= 90:   score_color = "#ef4444"
    elif score >= 76: score_color = "#f97316"
    elif score >= 61: score_color = "#eab308"
    elif score >= 41: score_color = "#60a5fa"
    else:             score_color = "#4ade80"

    lbl, _ = score_label(score)
    seeds_str = ", ".join(seeds)
    n = len(seeds)
    kind = "manual " if analysis_type == "manual" else ""
    exec_summary = (
        f"Se ha realizado un análisis {kind}de superficie de ataque sobre {n} objetivo{'s' if n != 1 else ''}: {seeds_str}. "
        f"El análisis identificó un total de {len(findings)} hallazgos de seguridad, "
        f"de los cuales {counts['critical']} son críticos, {counts['high']} de alta severidad, "
        f"{counts['medium']} de severidad media y {counts['info']} informativos. "
        f"El score de exposición calculado es {score}/100 — {lbl}."
    )

    rec_groups: dict = {}
    for f in findings:
        rec = (f.get("recommendation") or "").strip()
        if not rec or rec in _SKIP_RECS:
            continue
        if rec not in rec_groups:
            rec_groups[rec] = {"recommendation": rec, "severity": f["severity"], "assets": []}
        entry = f"{f['asset']} · {f['tool'].upper()}"
        if entry not in rec_groups[rec]["assets"]:
            rec_groups[rec]["assets"].append(entry)
        if _SEV_ORDER.get(f["severity"], 99) < _SEV_ORDER.get(rec_groups[rec]["severity"], 99):
            rec_groups[rec]["severity"] = f["severity"]
    grouped_recs = sorted(rec_groups.values(), key=lambda x: _SEV_ORDER.get(x["severity"], 99))

    html_str = render_template(
        "report_pdf.html",
        seeds         = seeds,
        assets        = assets,
        score         = score,
        score_color   = score_color,
        score_label   = lbl,
        date          = date_str,
        finding_count = len(findings),
        critical_count= counts["critical"],
        high_count    = counts["high"],
        counts        = counts,
        exec_summary  = exec_summary,
        findings      = findings,
        grouped_recs  = grouped_recs,
        ot_findings   = ot_findings,
    )
    return WeasyHTML(string=html_str).write_pdf()


def _owns_or_admin(record):
    """Returns a 403 response if the current user doesn't own the record, None otherwise."""
    if session.get("user_role") == ROLE_ADMIN:
        return None
    if record.user_id is not None and record.user_id != session.get("user_id"):
        return jsonify({"error": "Acceso denegado"}), 403
    return None


@pipeline_bp.route("/api/pipeline/start", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def start():
    data  = request.get_json(silent=True) or {}
    seeds = [s.strip() for s in data.get("seeds", []) if s.strip()]
    if not seeds:
        return jsonify({"error": "Proporciona al menos un dominio, IP o email"}), 400
    pid = create_pipeline(seeds)
    return jsonify({"pipeline_id": pid})


@pipeline_bp.route("/api/pipeline/run_tool", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def run_tool_module():
    data   = request.get_json(silent=True) or {}
    tool   = data.get("tool", "").strip()
    target = data.get("target", "").strip()
    if not tool or not target:
        return jsonify({"error": "tool y target son requeridos"}), 400
    pid = create_pipeline_single(tool, target)
    return jsonify({"pipeline_id": pid})


@pipeline_bp.route("/api/pipeline/stream/<pid>")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def stream(pid):
    def generate():
        idx = 0
        while True:
            events, status = get_events(pid, idx)
            if events is None:
                yield f"data: {json.dumps({'type': 'error', 'msg': 'Pipeline no encontrado'})}\n\n"
                return
            for ev in events:
                yield f"data: {json.dumps(ev)}\n\n"
            idx += len(events)
            if status == "done" and not events:
                return
            time.sleep(0.5)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@pipeline_bp.route("/api/pipeline/findings/<pid>")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def findings(pid):
    return jsonify(get_findings(pid))


# ── Análisis guardados ─────────────────────────────────────────────────────────

@pipeline_bp.route("/api/analyses/save", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def save_analysis():
    body = request.get_json(silent=True) or {}
    pid  = body.get("pipeline_id")
    if not pid:
        return jsonify({"error": "pipeline_id requerido"}), 400

    data = get_pipeline_data(pid)
    if not data or data["status"] != "done":
        return jsonify({"error": "Pipeline no completado o no encontrado"}), 404

    analysis = PipelineAnalysis(
        user_id  = session.get("user_id"),
        seeds    = data["seeds"],
        assets   = data["assets"],
        score    = data["score"],
        findings = data["findings"],
    )
    db.session.add(analysis)
    db.session.commit()
    return jsonify({"id": analysis.id, "ok": True})


@pipeline_bp.route("/api/analyses")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def list_analyses():
    q = PipelineAnalysis.query
    if session.get("user_role") != ROLE_ADMIN:
        q = q.filter_by(user_id=session.get("user_id"))
    rows = q.order_by(PipelineAnalysis.created_at.desc()).limit(30).all()
    return jsonify([{
        "id":            a.id,
        "seeds":         a.seeds,
        "score":         a.score,
        "finding_count": len(a.findings),
        "critical":      sum(1 for f in a.findings if f.get("severity") == "critical"),
        "high":          sum(1 for f in a.findings if f.get("severity") == "high"),
        "created_at":    to_local(a.created_at).isoformat(),
    } for a in rows])


@pipeline_bp.route("/api/analyses/<int:aid>")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def load_analysis(aid):
    a = db.session.get(PipelineAnalysis, aid)
    if not a:
        return jsonify({"error": "No encontrado"}), 404
    denied = _owns_or_admin(a)
    if denied:
        return denied
    return jsonify({
        "id":         a.id,
        "seeds":      a.seeds,
        "assets":     a.assets,
        "score":      a.score,
        "findings":   a.findings,
        "created_at": to_local(a.created_at).isoformat(),
    })


@pipeline_bp.route("/api/analyses/<int:aid>", methods=["DELETE"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def delete_analysis(aid):
    a = db.session.get(PipelineAnalysis, aid)
    if not a:
        return jsonify({"error": "No encontrado"}), 404
    denied = _owns_or_admin(a)
    if denied:
        return denied
    db.session.delete(a)
    db.session.commit()
    return jsonify({"ok": True})


@pipeline_bp.route("/api/analyses/<int:aid>/export/pdf")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def export_pdf(aid):
    try:
        import weasyprint  # noqa: F401
    except ImportError:
        return jsonify({"error": "WeasyPrint no instalado. Ejecuta: pip install weasyprint"}), 500

    a = db.session.get(PipelineAnalysis, aid)
    if not a:
        return jsonify({"error": "No encontrado"}), 404
    denied = _owns_or_admin(a)
    if denied:
        return denied

    pdf_bytes  = build_report_pdf_bytes(
        seeds      = a.seeds or [],
        assets     = a.assets or [],
        findings   = a.findings or [],
        score      = a.score or 0,
        date_str   = to_local(a.created_at).strftime("%d/%m/%Y %H:%M"),
        analysis_type = "pipeline",
    )
    seeds_slug = "_".join((a.seeds or ["report"])[:2]).replace(".", "_").replace("@", "_")
    filename   = f"aletheia_{seeds_slug}_{to_local(a.created_at).strftime('%Y%m%d')}.pdf"

    resp = make_response(pdf_bytes)
    resp.headers["Content-Type"]        = "application/pdf"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


# ── Análisis manuales ──────────────────────────────────────────────────────────

@pipeline_bp.route("/api/manual_analyses/save", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def save_manual_analysis():
    body     = request.get_json(silent=True) or {}
    targets  = body.get("targets", [])
    tools    = body.get("tools", [])
    findings = body.get("findings", [])
    score    = int(body.get("score", 0))

    if not targets:
        return jsonify({"error": "targets requerido"}), 400

    user_id = None
    user_id_session = session.get("user_id")
    if user_id_session:
        user_id = user_id_session

    analysis = ManualAnalysis(
        user_id  = user_id,
        targets  = targets,
        tools    = tools,
        findings = findings,
        score    = score,
    )
    db.session.add(analysis)
    db.session.commit()
    return jsonify({"id": analysis.id, "ok": True})


@pipeline_bp.route("/api/manual_analyses")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def list_manual_analyses():
    q = ManualAnalysis.query
    if session.get("user_role") != ROLE_ADMIN:
        q = q.filter_by(user_id=session.get("user_id"))
    rows = q.order_by(ManualAnalysis.created_at.desc()).limit(30).all()
    return jsonify([{
        "id":            a.id,
        "targets":       a.targets,
        "tools":         a.tools,
        "score":         a.score,
        "finding_count": len(a.findings),
        "critical":      sum(1 for f in a.findings if f.get("severity") == "critical"),
        "high":          sum(1 for f in a.findings if f.get("severity") == "high"),
        "created_at":    to_local(a.created_at).isoformat(),
    } for a in rows])


@pipeline_bp.route("/api/manual_analyses/<int:aid>")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def load_manual_analysis(aid):
    a = db.session.get(ManualAnalysis, aid)
    if not a:
        return jsonify({"error": "No encontrado"}), 404
    denied = _owns_or_admin(a)
    if denied:
        return denied
    return jsonify({
        "id":         a.id,
        "targets":    a.targets,
        "tools":      a.tools,
        "findings":   a.findings,
        "score":      a.score,
        "created_at": to_local(a.created_at).isoformat(),
    })


@pipeline_bp.route("/api/manual_analyses/<int:aid>", methods=["DELETE"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def delete_manual_analysis(aid):
    a = db.session.get(ManualAnalysis, aid)
    if not a:
        return jsonify({"error": "No encontrado"}), 404
    denied = _owns_or_admin(a)
    if denied:
        return denied
    db.session.delete(a)
    db.session.commit()
    return jsonify({"ok": True})


@pipeline_bp.route("/api/manual_analyses/<int:aid>/export/pdf")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def export_manual_pdf(aid):
    try:
        import weasyprint  # noqa: F401
    except ImportError:
        return jsonify({"error": "WeasyPrint no instalado. Ejecuta: pip install weasyprint"}), 500

    a = db.session.get(ManualAnalysis, aid)
    if not a:
        return jsonify({"error": "No encontrado"}), 404
    denied = _owns_or_admin(a)
    if denied:
        return denied

    targets    = a.targets or []
    assets     = list({f.get("asset", "") for f in (a.findings or []) if f.get("asset")})
    pdf_bytes  = build_report_pdf_bytes(
        seeds         = targets,
        assets        = assets,
        findings      = a.findings or [],
        score         = a.score or 0,
        date_str      = to_local(a.created_at).strftime("%d/%m/%Y %H:%M"),
        analysis_type = "manual",
    )
    seeds_slug = "_".join((targets or ["manual"])[:2]).replace(".", "_").replace("@", "_")
    filename   = f"aletheia_manual_{seeds_slug}_{to_local(a.created_at).strftime('%Y%m%d')}.pdf"

    resp = make_response(pdf_bytes)
    resp.headers["Content-Type"]        = "application/pdf"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
