from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_orig_request = requests.Session.request
def _patched_request(self, method, url, **kwargs):
    kwargs.setdefault('verify', False)
    return _orig_request(self, method, url, **kwargs)
requests.Session.request = _patched_request

KEYCLOAK_URL      = "http://localhost:8080"
KEYCLOAK_REALM    = "aletheia"
KEYCLOAK_CLIENT   = "aletheia-app"
KEYCLOAK_SECRET   = "2Xvg8UMSzxZGI3Hs9GZP2niOEjKZvvj6"
KEYCLOAK_REDIRECT = "https://localhost/auth/callback"

def create_app():
    app = Flask(__name__)

    # ── Configuración ──────────────────────────────────────────────────────────
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL",
        "postgresql://aletheia:aletheia@localhost:5432/aletheia_db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"]   = False  # nginx termina SSL; gunicorn ve HTTP
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_PERMANENT"]       = False

    # ── Extensiones ────────────────────────────────────────────────────────────
    from .extensions import db, migrate, oauth
    db.init_app(app)
    migrate.init_app(app, db)
    oauth.init_app(app)

    # ── Keycloak OIDC ──────────────────────────────────────────────────────────
    oauth.register(
        name="keycloak",
        client_id=KEYCLOAK_CLIENT,
        client_secret=KEYCLOAK_SECRET,
        server_metadata_url=(
            f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/"
            ".well-known/openid-configuration"
        ),
        client_kwargs={"scope": "openid email profile"},
    )

    # ── Timezone filter ───────────────────────────────────────────────────────
    from .utils import to_local

    @app.template_filter("localtime")
    def localtime_filter(dt, fmt="%d/%m/%Y %H:%M"):
        local = to_local(dt)
        return local.strftime(fmt) if local else "—"

    # ── Context processor ─────────────────────────────────────────────────────
    from flask import session as _session

    @app.context_processor
    def inject_user():
        return {
            "current_role":   _session.get("user_role", ""),
            "current_name":   _session.get("user_name", ""),
            "current_org_id": _session.get("org_id"),
        }

    # ── Blueprints ─────────────────────────────────────────────────────────────
    from .routes.auth import auth_bp
    from .routes.admin import admin_bp
    from .routes.main import main
    from .routes.runner import runner
    from .routes.news import news_bp
    from .routes.threat import threat_bp
    from .routes.overview import overview_bp
    from .routes.sources import sources_bp
    from .routes.exposure import exposure_bp
    from .routes.breaches import breaches_bp
    from .routes.intelx import intelx_bp
    from .routes.harvest_breaches import harvest_bp
    from .routes.shodan_full import shodan_full_bp
    from .routes.virustotal import vt_bp
    from .routes.stix_validate import stix_validate_bp
    from .routes.misp import misp_bp
    from .routes.urlscan import urlscan_bp
    from .routes.nmap_discover import nmap_discover_bp
    from .routes.pipeline import pipeline_bp
    from .routes.reports import reports_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(main)
    app.register_blueprint(runner)
    app.register_blueprint(news_bp)
    app.register_blueprint(threat_bp)
    app.register_blueprint(overview_bp)
    app.register_blueprint(sources_bp)
    app.register_blueprint(exposure_bp)
    app.register_blueprint(breaches_bp)
    app.register_blueprint(intelx_bp)
    app.register_blueprint(harvest_bp)
    app.register_blueprint(shodan_full_bp)
    app.register_blueprint(vt_bp)
    app.register_blueprint(stix_validate_bp)
    app.register_blueprint(misp_bp)
    app.register_blueprint(urlscan_bp)
    app.register_blueprint(nmap_discover_bp)
    app.register_blueprint(pipeline_bp)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    return app
