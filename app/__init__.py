from flask import Flask

def create_app():
    app = Flask(__name__)

    from .routes.main import main
    from .routes.runner import runner
    from .routes.news import news_bp

    app.register_blueprint(main)
    app.register_blueprint(runner)
    app.register_blueprint(news_bp)

    return app