from flask import Flask
from .config import Config


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Register blueprints
    from .game import game_bp
    app.register_blueprint(game_bp, url_prefix="/game")

    @app.route("/")
    def index():
        # Redirect straight into the game dashboard
        from flask import redirect, url_for
        return redirect(url_for("game.dashboard"))

    return app
