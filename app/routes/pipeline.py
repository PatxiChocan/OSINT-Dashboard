import json
import time
from flask import Blueprint, request, jsonify, Response, stream_with_context, session, render_template, make_response
from app.routes.auth import role_required
from app.models import ROLE_ADMIN, ROLE_ANALYST, PipelineAnalysis, User
from app.extensions import db
from app.services.pipeline_service import create_pipeline, get_events, get_findings, get_pipeline_data, score_label

pipeline_bp = Blueprint("pipeline", __name__)


@pipeline_bp.route("/api/pipeline/start", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def start():
    data  = request.get_json(silent=True) or {}
    seeds = [s.strip() for s in data.get("seeds", []) if s.strip()]
    if not seeds:
        return jsonify({"error": "Proporciona al menos un dominio, IP o email"}), 400
    pid = create_pipeline(seeds)
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

    # Buscar user_id por email de sesión
    user_id = None
    email = session.get("user_email")
    if email:
        u = User.query.filter_by(email=email).first()
        if u:
            user_id = u.id

    analysis = PipelineAnalysis(
        user_id  = user_id,
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
    rows = (PipelineAnalysis.query
            .order_by(PipelineAnalysis.created_at.desc())
            .limit(30).all())
    return jsonify([{
        "id":            a.id,
        "seeds":         a.seeds,
        "score":         a.score,
        "finding_count": len(a.findings),
        "critical":      sum(1 for f in a.findings if f.get("severity") == "critical"),
        "high":          sum(1 for f in a.findings if f.get("severity") == "high"),
        "created_at":    a.created_at.isoformat(),
    } for a in rows])


@pipeline_bp.route("/api/analyses/<int:aid>")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def load_analysis(aid):
    a = db.session.get(PipelineAnalysis, aid)
    if not a:
        return jsonify({"error": "No encontrado"}), 404
    return jsonify({
        "id":         a.id,
        "seeds":      a.seeds,
        "assets":     a.assets,
        "score":      a.score,
        "findings":   a.findings,
        "created_at": a.created_at.isoformat(),
    })


@pipeline_bp.route("/api/analyses/<int:aid>", methods=["DELETE"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def delete_analysis(aid):
    a = db.session.get(PipelineAnalysis, aid)
    if not a:
        return jsonify({"error": "No encontrado"}), 404
    db.session.delete(a)
    db.session.commit()
    return jsonify({"ok": True})


@pipeline_bp.route("/api/analyses/<int:aid>/export/pdf")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def export_pdf(aid):
    try:
        from weasyprint import HTML as WeasyHTML
    except ImportError:
        return jsonify({"error": "WeasyPrint no instalado. Ejecuta: pip install weasyprint"}), 500

    a = db.session.get(PipelineAnalysis, aid)
    if not a:
        return jsonify({"error": "No encontrado"}), 404

    findings = a.findings or []
    counts = {
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "high":     sum(1 for f in findings if f.get("severity") == "high"),
        "medium":   sum(1 for f in findings if f.get("severity") == "medium"),
        "info":     sum(1 for f in findings if f.get("severity") == "info"),
    }
    score = a.score or 0

    if score >= 90:   score_color = "#ef4444"
    elif score >= 76: score_color = "#f97316"
    elif score >= 61: score_color = "#eab308"
    elif score >= 41: score_color = "#60a5fa"
    else:             score_color = "#4ade80"

    lbl, _ = score_label(score)

    seeds_str   = ", ".join(a.seeds or [])
    n_seeds     = len(a.seeds or [])
    exec_summary = (
        f"Se ha realizado un análisis de superficie de ataque sobre {n_seeds} objetivo{'s' if n_seeds != 1 else ''}: {seeds_str}. "
        f"El análisis identificó un total de {len(findings)} hallazgos de seguridad, "
        f"de los cuales {counts['critical']} son críticos, {counts['high']} de alta severidad, "
        f"{counts['medium']} de severidad media y {counts['info']} informativos. "
        f"El score de exposición calculado es {score}/100 — {lbl}."
    )

    html_str = render_template(
        "report_pdf.html",
        seeds        = a.seeds or [],
        assets       = a.assets or [],
        score        = score,
        score_color  = score_color,
        score_label  = lbl,
        date         = a.created_at.strftime("%d/%m/%Y %H:%M"),
        finding_count= len(findings),
        critical_count= counts["critical"],
        high_count   = counts["high"],
        counts       = counts,
        exec_summary = exec_summary,
        findings     = findings,
    )

    pdf_bytes  = WeasyHTML(string=html_str).write_pdf()
    seeds_slug = "_".join((a.seeds or ["report"])[:2]).replace(".", "_").replace("@", "_")
    filename   = f"aletheia_{seeds_slug}_{a.created_at.strftime('%Y%m%d')}.pdf"

    resp = make_response(pdf_bytes)
    resp.headers["Content-Type"]        = "application/pdf"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
