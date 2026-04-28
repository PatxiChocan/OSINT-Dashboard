from flask import Flask

def create_app():
    app = Flask(__name__)

    from .routes.main import main
    from .routes.runner import runner
    from .routes.news import news_bp
    from .routes.threat import threat_bp
    from .routes.overview import overview_bp
    from .routes.sources import sources_bp

    app.register_blueprint(main)
    app.register_blueprint(runner)
    app.register_blueprint(news_bp)
    app.register_blueprint(threat_bp)
    app.register_blueprint(overview_bp)
    app.register_blueprint(sources_bp)

    return app