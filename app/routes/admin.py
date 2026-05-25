import os
from flask import Blueprint, render_template, request, jsonify, session, current_app
from app.routes.auth import role_required
from app.models import ROLE_ADMIN, ROLE_ANALYST, ROLE_CLIENT, User, Organisation, Report, PipelineAnalysis, ManualAnalysis
from app.extensions import db

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@role_required(ROLE_ADMIN)
def index():
    users   = User.query.order_by(User.created_at.desc()).all()
    orgs    = Organisation.query.order_by(Organisation.nombre).all()
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template("admin.html", users=users, orgs=orgs, reports=reports,
                           ROLE_ADMIN=ROLE_ADMIN, ROLE_ANALYST=ROLE_ANALYST, ROLE_CLIENT=ROLE_CLIENT)


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@role_required(ROLE_ADMIN)
def set_role(user_id):
    data = request.get_json(silent=True) or {}
    new_role = data.get("role", "").strip()
    if new_role not in (ROLE_ADMIN, ROLE_ANALYST, ROLE_CLIENT):
        return jsonify({"error": "Rol inválido"}), 400
    user = User.query.get_or_404(user_id)
    if user.id == session.get("user_id") and new_role != ROLE_ADMIN:
        return jsonify({"error": "No puedes degradar tu propio rol de administrador"}), 400
    user.role = new_role
    db.session.commit()
    return jsonify({"ok": True, "role": user.role})


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@role_required(ROLE_ADMIN)
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == session.get("user_id"):
        return jsonify({"error": "No puedes desactivar tu propia cuenta"}), 400
    user.is_active = 0 if user.is_active else 1
    db.session.commit()
    return jsonify({"ok": True, "is_active": user.is_active})


@admin_bp.route("/users", methods=["POST"])
@role_required(ROLE_ADMIN)
def create_user():
    data = request.get_json(silent=True) or {}
    required = ("keycloak_id", "email", "nombre", "apellido")
    if not all(data.get(k, "").strip() for k in required):
        return jsonify({"error": "Campos obligatorios: keycloak_id, email, nombre, apellido"}), 400
    if User.query.filter_by(email=data["email"].strip()).first():
        return jsonify({"error": "Email ya registrado"}), 409
    if User.query.filter_by(keycloak_id=data["keycloak_id"].strip()).first():
        return jsonify({"error": "keycloak_id ya registrado"}), 409
    role = data.get("role", ROLE_CLIENT).strip()
    if role not in (ROLE_ADMIN, ROLE_ANALYST, ROLE_CLIENT):
        role = ROLE_CLIENT
    user = User(
        keycloak_id=data["keycloak_id"].strip(),
        email=data["email"].strip(),
        nombre=data["nombre"].strip(),
        apellido=data["apellido"].strip(),
        role=role,
        org_id=data.get("org_id") or None,
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"ok": True, "id": user.id}), 201


@admin_bp.route("/users/<int:user_id>/org", methods=["POST"])
@role_required(ROLE_ADMIN)
def set_org(user_id):
    data = request.get_json(silent=True) or {}
    org_id = data.get("org_id")
    user = User.query.get_or_404(user_id)
    if org_id is None or org_id == "" or org_id == 0:
        user.org_id = None
    else:
        org = Organisation.query.get(int(org_id))
        if not org:
            return jsonify({"error": "Organización no encontrada"}), 404
        user.org_id = org.id
    db.session.commit()
    return jsonify({"ok": True, "org_id": user.org_id})


@admin_bp.route("/orgs", methods=["POST"])
@role_required(ROLE_ADMIN)
def create_org():
    data = request.get_json(silent=True) or {}
    nombre = data.get("nombre", "").strip()
    nif    = data.get("nif", "").strip()
    if not nombre or not nif:
        return jsonify({"error": "nombre y nif son obligatorios"}), 400
    if Organisation.query.filter_by(nif=nif).first():
        return jsonify({"error": "NIF ya registrado"}), 409
    org = Organisation(
        nombre=nombre,
        nif=nif,
        pais=data.get("pais", "").strip() or None,
        industria=data.get("industria", "").strip() or None,
        email_contacto=data.get("email_contacto", "").strip() or None,
        web=data.get("web", "").strip() or None,
        plan=data.get("plan", "basic").strip(),
    )
    db.session.add(org)
    db.session.commit()
    return jsonify({"ok": True, "id": org.id, "nombre": org.nombre}), 201


@admin_bp.route("/orgs/<int:org_id>/toggle", methods=["POST"])
@role_required(ROLE_ADMIN)
def toggle_org(org_id):
    org = Organisation.query.get_or_404(org_id)
    org.is_active = 0 if org.is_active else 1
    db.session.commit()
    return jsonify({"ok": True, "is_active": org.is_active})


@admin_bp.route("/orgs/<int:org_id>", methods=["PATCH"])
@role_required(ROLE_ADMIN)
def update_org(org_id):
    data = request.get_json(silent=True) or {}
    org = Organisation.query.get_or_404(org_id)
    if "nif" in data:
        new_nif = data["nif"].strip()
        if new_nif != org.nif and Organisation.query.filter_by(nif=new_nif).first():
            return jsonify({"error": "NIF ya registrado"}), 409
        org.nif = new_nif
    for field in ("nombre", "pais", "industria", "email_contacto", "web"):
        if field in data:
            val = data[field].strip()
            setattr(org, field, val if val else None)
    if "plan" in data:
        org.plan = data["plan"].strip() or "basic"
    db.session.commit()
    return jsonify({"ok": True})


@admin_bp.route("/orgs/list")
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def list_orgs():
    orgs = Organisation.query.filter_by(is_active=1).order_by(Organisation.nombre).all()
    return jsonify([{"id": o.id, "nombre": o.nombre} for o in orgs])


@admin_bp.route("/reports/<int:report_id>/org", methods=["POST"])
@role_required(ROLE_ADMIN)
def set_report_org(report_id):
    data = request.get_json(silent=True) or {}
    org_id = data.get("org_id")
    report = Report.query.get_or_404(report_id)
    if org_id is None or org_id == "" or org_id == 0:
        report.org_id = None
    else:
        org = Organisation.query.get(int(org_id))
        if not org:
            return jsonify({"error": "Organización no encontrada"}), 404
        report.org_id = org.id
    db.session.commit()
    return jsonify({"ok": True, "org_id": report.org_id})


@admin_bp.route("/reports/<int:report_id>/toggle-visible", methods=["POST"])
@role_required(ROLE_ADMIN)
def toggle_report_visible(report_id):
    report = Report.query.get_or_404(report_id)
    report.is_visible = 0 if report.is_visible else 1
    db.session.commit()
    return jsonify({"ok": True, "is_visible": report.is_visible})


@admin_bp.route("/publish", methods=["POST"])
@role_required(ROLE_ADMIN, ROLE_ANALYST)
def publish_analysis():
    """Publish a PipelineAnalysis or ManualAnalysis as a Report visible to a client org."""
    try:
        import weasyprint  # noqa: F401
    except ImportError:
        return jsonify({"error": "WeasyPrint no instalado"}), 500

    from app.routes.pipeline import build_report_pdf_bytes
    from app.utils import to_local

    data          = request.get_json(silent=True) or {}
    analysis_type = data.get("type")          # "pipeline" or "manual"
    analysis_id   = data.get("analysis_id")
    org_id        = data.get("org_id")
    titulo        = (data.get("titulo") or "").strip()

    # Analysts can only publish to their own organisation
    if session.get("user_role") == ROLE_ANALYST:
        org_id = session.get("org_id")
        if not org_id:
            return jsonify({"error": "No tienes una organización asignada. Contacta con el administrador."}), 403

    if not analysis_type or not analysis_id or not org_id:
        return jsonify({"error": "type, analysis_id y org_id son requeridos"}), 400

    org = Organisation.query.get(int(org_id))
    if not org:
        return jsonify({"error": "Organización no encontrada"}), 404

    if analysis_type == "pipeline":
        a = db.session.get(PipelineAnalysis, int(analysis_id))
        if not a:
            return jsonify({"error": "Análisis no encontrado"}), 404
        seeds    = a.seeds or []
        assets   = a.assets or []
        findings = a.findings or []
        score    = a.score or 0
        date_str = to_local(a.created_at).strftime("%d/%m/%Y %H:%M")
        if not titulo:
            titulo = f"Análisis OSINT — {', '.join(seeds[:2])}"
    elif analysis_type == "manual":
        a = db.session.get(ManualAnalysis, int(analysis_id))
        if not a:
            return jsonify({"error": "Análisis no encontrado"}), 404
        seeds    = a.targets or []
        assets   = list({f.get("asset", "") for f in (a.findings or []) if f.get("asset")})
        findings = a.findings or []
        score    = a.score or 0
        date_str = to_local(a.created_at).strftime("%d/%m/%Y %H:%M")
        if not titulo:
            titulo = f"Análisis Manual — {', '.join(seeds[:2])}"
    else:
        return jsonify({"error": "type debe ser 'pipeline' o 'manual'"}), 400

    pdf_bytes = build_report_pdf_bytes(
        seeds         = seeds,
        assets        = assets,
        findings      = findings,
        score         = score,
        date_str      = date_str,
        analysis_type = analysis_type,
    )

    reports_dir = os.path.join(current_app.instance_path, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    report = Report(
        org_id     = int(org_id),
        analyst_id = session.get("user_id"),
        titulo     = titulo,
        resultados = {"type": analysis_type, "analysis_id": int(analysis_id)},
        is_visible = 1,
    )
    db.session.add(report)
    db.session.flush()  # get report.id before saving file

    pdf_path = os.path.join(reports_dir, f"report_{report.id}.pdf")
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)
    report.output_path = pdf_path
    db.session.commit()

    return jsonify({"ok": True, "report_id": report.id})
