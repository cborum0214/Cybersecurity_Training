from flask import Blueprint

game_bp = Blueprint(
    "game",
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

from . import routes  # noqa: E402,F401
