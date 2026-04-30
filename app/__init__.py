from flask import Flask

def create_app():
    app = Flask(__name__)

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

    return app