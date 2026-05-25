from flask import Blueprint, session, jsonify, send_file, abort
from app.routes.auth import login_required
from app.models import Report, PipelineAnalysis, ManualAnalysis, ROLE_ADMIN, ROLE_ANALYST
from app.extensions import db
from app.utils import to_local
import os

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


def _can_access_report(report):
    """Return True if the current session can read this report."""
    role   = session.get("user_role", "")
    org_id = session.get("org_id")
    if role == ROLE_ADMIN:
        return True
    return report.org_id == org_id and bool(report.is_visible)


@reports_bp.route("/")
@login_required
def list_reports():
    org_id = session.get("org_id")
    if not org_id:
        return jsonify([])
    reports = (
        Report.query
        .filter_by(org_id=org_id, is_visible=1)
        .order_by(Report.created_at.desc())
        .all()
    )
    return jsonify([
        {
            "id":          r.id,
            "titulo":      r.titulo,
            "descripcion": r.descripcion or "",
            "created_at":  r.created_at.strftime("%d/%m/%Y %H:%M") if r.created_at else "—",
            "has_pdf":     bool(r.output_path and os.path.isfile(r.output_path)),
        }
        for r in reports
    ])


@reports_bp.route("/<int:report_id>/pdf")
@login_required
def download_pdf(report_id):
    report = Report.query.get_or_404(report_id)
    if not _can_access_report(report):
        abort(403)
    if not report.output_path or not os.path.isfile(report.output_path):
        abort(404)
    return send_file(report.output_path, as_attachment=True,
                     download_name=f"informe_{report_id}.pdf")


@reports_bp.route("/<int:report_id>/data")
@login_required
def report_data(report_id):
    """Return full findings data for web viewer. Accessible to the report's org and to admins/analysts."""
    report = Report.query.get_or_404(report_id)
    if not _can_access_report(report):
        abort(403)

    resultados    = report.resultados or {}
    analysis_type = resultados.get("type")
    analysis_id   = resultados.get("analysis_id")

    seeds    = []
    score    = 0
    findings = []

    if analysis_type == "pipeline" and analysis_id:
        a = db.session.get(PipelineAnalysis, analysis_id)
        if a:
            seeds    = a.seeds or []
            score    = a.score or 0
            findings = a.findings or []
    elif analysis_type == "manual" and analysis_id:
        a = db.session.get(ManualAnalysis, analysis_id)
        if a:
            seeds    = a.targets or []
            score    = a.score or 0
            findings = a.findings or []

    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}
    findings = sorted(findings, key=lambda f: (
        _SEV_ORDER.get(f.get("severity", "info"), 99),
        (f.get("asset") or "").lower(),
    ))

    counts = {
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "high":     sum(1 for f in findings if f.get("severity") == "high"),
        "medium":   sum(1 for f in findings if f.get("severity") == "medium"),
        "info":     sum(1 for f in findings if f.get("severity") == "info"),
    }

    _SKIP_RECS = {
        "Sin alertas. Monitoriza periódicamente.",
        "Continúa monitorizando periódicamente.",
        "Mantén la privacy protection activa.",
    }
    rec_groups: dict = {}
    for f in findings:
        rec = (f.get("recommendation") or "").strip()
        if not rec or rec in _SKIP_RECS:
            continue
        if rec not in rec_groups:
            rec_groups[rec] = {"recommendation": rec, "severity": f["severity"], "assets": []}
        entry = f"{f.get('asset','')} · {f.get('tool','').upper()}"
        if entry not in rec_groups[rec]["assets"]:
            rec_groups[rec]["assets"].append(entry)
        if _SEV_ORDER.get(f["severity"], 99) < _SEV_ORDER.get(rec_groups[rec]["severity"], 99):
            rec_groups[rec]["severity"] = f["severity"]
    recommendations = sorted(rec_groups.values(), key=lambda x: _SEV_ORDER.get(x["severity"], 99))

    return jsonify({
        "id":              report.id,
        "titulo":          report.titulo,
        "descripcion":     report.descripcion or "",
        "created_at":      to_local(report.created_at).strftime("%d/%m/%Y %H:%M") if report.created_at else "—",
        "seeds":           seeds,
        "score":           score,
        "counts":          counts,
        "findings":        findings,
        "recommendations": recommendations,
        "has_pdf":         bool(report.output_path and os.path.isfile(report.output_path)),
    })
