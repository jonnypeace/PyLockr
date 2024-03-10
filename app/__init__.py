#!/usr/bin/env python3

from flask import Flask, g,request
from .main import main as main_blueprint
from .auth import auth as auth_blueprint
from config import Config
import secrets,json
from .utils.pylockr_logging import PyLockrLogs
from .utils.db_utils import Session, set_up_bk_up_dir
from .utils.extensions import limiter

logger = PyLockrLogs(name='CreateApp')

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        Session.remove()

    def generate_nonce():
        return secrets.token_urlsafe(16)

    @app.before_request
    def set_csp_nonce():
        nonce = generate_nonce()
        g.nonce = nonce  # Store the nonce in g for access in templates

        report_to = {
            "group": "default",
            "max_age": 10886400,
            "endpoints": [{"url": "/csp-report-endpoint"}],
            "include_subdomains": True
        }

        report_to_json = json.dumps(report_to)

        csp_policy = (
            "default-src 'self';"
            f"script-src 'self' https://code.jquery.com https://cdn.datatables.net 'nonce-{nonce}';"
            "style-src 'self' https://cdn.datatables.net;"
            "object-src 'none';"
            "img-src 'self';"
            "report-uri /csp-report-endpoint;"
         #   f'report-to "{report_to_json}"'
            "connect-src 'self';"
        )
        
        g.csp_policy = csp_policy.strip()  # Use strip() to remove leading/trailing whitespace

    @app.after_request
    def apply_security_headers(response):
        # CSP header
        response.headers['Content-Security-Policy'] = g.csp_policy
        # Clickjacking Protection
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Or 'DENY' if you prefer
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @app.route('/csp-report-endpoint', methods=['POST'])
    def csp_report():
        report = request.get_json()
        if report is None:
            logger.error("CSP Report is empty or not JSON.")
            return '', 204
        else:
            logger.warning(f"CSP Violation: {report}")
            return '', 204

    # Initialize Flask-Limiter with the app
    limiter.init_app(app)
    app.register_blueprint(main_blueprint)
    # app.register_blueprint(auth_blueprint, url_prefix='/auth') ####### Consider for future
    app.register_blueprint(auth_blueprint)
    set_up_bk_up_dir() # Sets up backup directory
    return app
