from flask import Blueprint, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
from datetime import datetime, timezone
from app.extensions import db, oauth
from app.models import User, ROLE_ADMIN, ROLE_ANALYST, ROLE_CLIENT
import base64
import json

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

KEYCLOAK_ROLE_MAP = {
    "admin":   ROLE_ADMIN,
    "analyst": ROLE_ANALYST,
    "client":  ROLE_CLIENT,
}

def _role_from_token(access_token: str) -> str:
    """Extrae el rol de mayor privilegio del access token JWT de Keycloak."""
    try:
        payload = access_token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        claims = json.loads(base64.b64decode(payload))
        kc_roles = claims.get("realm_access", {}).get("roles", [])
        for kc_role, app_role in KEYCLOAK_ROLE_MAP.items():
            if kc_role in kc_roles:
                return app_role
    except Exception:
        pass
    return ROLE_CLIENT


@auth_bp.route("/login")
def login():
    redirect_uri = url_for("auth.callback", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)


@auth_bp.route("/callback")
def callback():
    token = oauth.keycloak.authorize_access_token()
    userinfo = token.get("userinfo") or oauth.keycloak.userinfo()

    keycloak_id = userinfo["sub"]
    email       = userinfo.get("email", "")
    nombre      = userinfo.get("given_name", userinfo.get("preferred_username", ""))
    apellido    = userinfo.get("family_name", "")
    role        = _role_from_token(token.get("access_token", ""))

    user = User.query.filter_by(keycloak_id=keycloak_id).first()

    if not user:
        user = User(
            keycloak_id = keycloak_id,
            email       = email,
            nombre      = nombre or "Sin nombre",
            apellido    = apellido or "",
            role        = role,
        )
        db.session.add(user)
    else:
        user.role = role

    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    session["user_id"]     = user.id
    session["user_role"]   = user.role
    session["user_name"]   = user.nombre_completo
    session["org_id"]      = user.org_id

    return redirect("/")


@auth_bp.route("/logout")
def logout():
    session.clear()
    end_session = oauth.keycloak.server_metadata.get(
        "end_session_endpoint",
        "http://localhost:8080/realms/aletheia/protocol/openid-connect/logout"
    )
    keycloak_logout = (
        f"{end_session}"
        f"?post_logout_redirect_uri={url_for('main.index', _external=True)}"
        f"&client_id=aletheia-app"
    )
    return redirect(keycloak_logout)


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("auth.login"))
            if session.get("user_role") not in roles:
                return jsonify({"error": "Acceso denegado"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
