import os

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_redis import FlaskRedis
from flask_sqlalchemy import SQLAlchemy

cors = CORS()
db = SQLAlchemy()
bcrypt = Bcrypt()
redis_client = FlaskRedis()


def create_app():
    app = Flask(__name__)

    app_settings = os.environ.get("APP_SETTINGS", "project.config.DevelopmentConfig")
    app.config.from_object(app_settings)

    cors.init_app(app)
    db.init_app(app)
    bcrypt.init_app(app)
    redis_client.init_app(app)

    from project.apis import api

    api.init_app(app)

    @app.shell_context_processor
    def ctx():
        return {"app": app}

    return app
