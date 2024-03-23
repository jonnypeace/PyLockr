#!/usr/bin/env python3

from flask import Flask, g,request,session,abort,send_from_directory
from .main import main as main_blueprint
from .auth import auth as auth_blueprint
from config import Config
import secrets,json,os
from .utils.pylockr_logging import PyLockrLogs
from .utils.db_utils import Session
from .utils.extensions import limiter
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

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

        trusted_domain = os.environ.get('TRUSTED_DOMAIN', 'laptop.home')
        csp_policy = (
            "default-src 'self';"
            f"script-src 'self' https://code.jquery.com https://cdn.datatables.net 'nonce-{nonce}';"
            "style-src 'self' https://cdn.datatables.net;"
            "object-src 'none';"
            "img-src 'self' data:;"
            "report-to default;"
            #"report-uri /csp-report-endpoint;"
            "connect-src 'self';"
            f"form-action 'self' https://{trusted_domain};"
            f"frame-ancestors 'self' https://{trusted_domain};"
            "base-uri 'none';"
        )
        
        g.csp_policy = csp_policy.strip()  # Use strip() to remove leading/trailing whitespace

    @app.after_request
    def apply_security_headers(response):
        response.headers['Report-To'] = json.dumps({
            "group": "default",
            "max_age": 10886400,
            "endpoints": [{"url": "/csp-report-endpoint"}],
            "include_subdomains": True
        })

       # CSP header
        response.headers['Content-Security-Policy'] = g.csp_policy
        # Clickjacking Protection
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Or 'DENY' if you prefer
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
        # Add COOP, COEP, and CORP headers
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'

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

    @app.context_processor
    def inject_csrf_token():
        # Generate a new CSRF token if one doesn't exist in the session
        # if session.get('csrf_token', None) is None:
        session['csrf_token'] = secrets.token_hex(16)
        return dict(csrf_token=session['csrf_token'])

    @app.before_request
    def check_csrf_token():
        # Only perform CSRF check for POST requests
        if request.method == "POST" and not request.endpoint in ['auth.logout', 'main.decrypt_password']:
            submitted_token = request.form.get('csrf_token')
            # Verify CSRF token
            if not submitted_token or submitted_token != session.get('csrf_token'):
                abort(403)  # CSRF token is invalid

    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(os.path.join(app.root_path, 'static'),
                                'favicon.ico', mimetype='image/vnd.microsoft.icon')


    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    
    # Initialize Flask-Limiter with the app
    limiter.init_app(app)
    app.register_blueprint(main_blueprint)
    # app.register_blueprint(auth_blueprint, url_prefix='/auth') ####### Consider for future
    app.register_blueprint(auth_blueprint)
    # set_up_bk_up_dir() # Sets up backup directory
    return app
