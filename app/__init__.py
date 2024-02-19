#!/usr/bin/env python3

from flask import Flask
from .main import main as main_blueprint
from .auth import auth as auth_blueprint
from config import Config

from .utils.extensions import limiter  # Import the limiter

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    # Initialize Flask-Limiter with the app
    limiter.init_app(app)
    app.register_blueprint(main_blueprint)
    # app.register_blueprint(auth_blueprint, url_prefix='/auth') ####### Consider for future
    app.register_blueprint(auth_blueprint)
    return app