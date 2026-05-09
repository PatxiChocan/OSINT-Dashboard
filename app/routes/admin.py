from flask import Blueprint, render_template, request, jsonify, session
from app.routes.auth import role_required
from app.models import ROLE_ADMIN, ROLE_ANALYST, ROLE_CLIENT, User, Organisation
from app.extensions import db

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@role_required(ROLE_ADMIN)
def index():
    users = User.query.order_by(User.created_at.desc()).all()
    orgs  = Organisation.query.order_by(Organisation.nombre).all()
    return render_template("admin.html", users=users, orgs=orgs,
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
