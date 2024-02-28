#!/usr/bin/env python3

from flask import Flask, g
from .main import main as main_blueprint
from .auth import auth as auth_blueprint
from config import Config
import secrets

from .utils.extensions import limiter  # Import the limiter

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    def generate_nonce():
        return secrets.token_urlsafe(16)

    @app.before_request
    def set_csp_nonce():
        nonce = generate_nonce()
        g.nonce = nonce  # Store the nonce in g for access in templates
       # Define the CSP policy with the nonce
        csp_policy = (
            "default-src 'self';"
            f"script-src 'self' https://code.jquery.com https://cdn.datatables.net 'nonce-{nonce}';"
            #"script-src 'self' 'unsafe-inline' 'nonce-{nonce}';"
            "style-src 'self' 'unsafe-inline' https://cdn.datatables.net;"
            "object-src 'none';"
            "connect-src 'self';"
        )
        
        g.csp_policy = csp_policy.strip()  # Use strip() to remove leading/trailing whitespace

    @app.after_request
    def apply_csp(response):
        response.headers['Content-Security-Policy'] = g.csp_policy
        return response

    # Initialize Flask-Limiter with the app
    limiter.init_app(app)
    app.register_blueprint(main_blueprint)
    # app.register_blueprint(auth_blueprint, url_prefix='/auth') ####### Consider for future
    app.register_blueprint(auth_blueprint)
    return app
