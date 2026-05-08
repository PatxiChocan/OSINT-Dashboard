from flask import Flask
import os
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_orig_request = requests.Session.request
def _patched_request(self, method, url, **kwargs):
    kwargs.setdefault('verify', False)
    return _orig_request(self, method, url, **kwargs)
requests.Session.request = _patched_request

def create_app():
    app = Flask(__name__)

    # ── Configuración ──────────────────────────────────────────────────────────
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL",
        "postgresql://aletheia:aletheia@localhost:5432/aletheia_db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ── Extensiones ────────────────────────────────────────────────────────────
    from .extensions import db, login_manager, bcrypt, migrate
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

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

    return app