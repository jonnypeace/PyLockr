#!/usr/bin/env python3

from . import auth
from flask import render_template, request, redirect, url_for, session, flash, current_app, make_response, g, jsonify
import re,secrets, os
from app.utils.db_utils import authenticate_user, add_user, update_user_password, decrypt_data, update_initial_setup, retrieve_edek
from app.utils.pylockr_logging import *
from flask.views import MethodView
from html_sanitizer import Sanitizer
from app.utils.extensions import limiter
from flask_limiter.util import get_remote_address
import pyotp, qrcode, io, base64
from itsdangerous import URLSafeTimedSerializer, BadSignature

logger = PyLockrLogs(name='Auth')

sanitizer = Sanitizer()  # Used for name and username

class CookieIntegrityError(Exception):
    """Exception raised when the integrity of a cookie is compromised."""
    def __init__(self, message="Cookie integrity check failed"):
        self.message = message
        super().__init__(self.message)

def is_password_complex(password):
    """Check if the password meets complexity requirements."""
    min_length = current_app.config['MIN_PASSWORD_LENGTH']
    if len(password) < min_length:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*()-_+<>?]", password):
        return False
    return True

def set_remember_me_cookie(remember_me, response):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    token = s.dumps({'remember_me': remember_me})
    https_safe = current_app.config['SESSION_COOKIE_SECURE']
    response.set_cookie('remember_me', token, max_age=30*24*3600, httponly=True, secure=https_safe, samesite='Strict')
    return response

def check_remember_me_cookie():
    remember_me_cookie = request.cookies.get('remember_me', None)
    if remember_me_cookie:
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(remember_me_cookie)
            cookie_status = data.get('remember_me', None)
            if cookie_status is None:
                raise CookieIntegrityError("Invalid 'remember_me' value in cookie.")
            return cookie_status
        except BadSignature:
            logger.error(f'Cookie has a bad signature, and potentially been tampered with')
            return False
    return False

class Logout(MethodView):
    def post(self):
        '''
        Logs out and clears the session and redirects to homepage.
        '''
        session.clear()
        flash('You have been logged out.', 'alert alert-ok')
        return redirect(url_for('main.home'))
auth.add_url_rule('/logout', view_func=Logout.as_view('logout'))


class Authenticate(MethodView):
    def post(self):
        data = request.get_json()
        username = sanitizer.sanitize(data['username'])
        hashed_password = data['password']
        # Verification logic here...
        user = authenticate_user(username, hashed_password)
        session['temp_user_id'] = user.id # Needed for 2FA and storing dek in redis
        if user:
            # Assuming get_user_edek_iv is a function that retrieves the EDEK and IV for the user
            user = retrieve_edek(username=username)
            return jsonify({'encryptedDEK': user.edek, 'iv': user.iv}), 200
        else:
            return jsonify({'message': 'Authentication failed'}), 403

auth.add_url_rule('/authenticate', view_func=Authenticate.as_view('authenticate'))


class Login(MethodView):
    decorators = [limiter.limit("7 per minute")]
    def get(self):
        # Render the template as usual
        return render_template('login.html', nonce=g.nonce)

    def post(self):
        '''
        Logs into website and starts a session.
        Rate limited, 5 per minute.
        '''
        
        username = sanitizer.sanitize(request.form['username'])
        hashed_password = request.form['password']
        
        logger.info(hashed_password)
        
        requested_ip = get_remote_address()
        user = authenticate_user(username, hashed_password)

        if user:
            session['temp_user_id'] = user.id # Needed for 2FA
            session['username'] = user.username
            session['2fa_otp'] = user.otp_2fa_enc
            session['initial_setup'] = user.initial_setup
            try:
                session['remember_me'] = check_remember_me_cookie()
            except CookieIntegrityError as CIE:
                logger.error(f'Cookie Does not contain remember_me field.\n{CIE}')
            if session['remember_me']:
                # Proceed without 2FA
                session['user_id'] = session.pop('temp_user_id')
                flash('Login successful.', 'alert alert-ok')
                logger.info(f'Successful login attempt {requested_ip=}')
                return redirect(url_for('main.dashboard'))
            else:
                # Prompt for 2FA
                flash('Login successful, please check 2FA', 'alert alert-ok')
                return redirect(url_for('auth.login2fa'))
        else:
            flash('Invalid username or password.', 'alert alert-error')
            logger.error(f'Failed login attempt {requested_ip=} {username=}')
            return redirect(url_for('auth.login'))

auth.add_url_rule('/login', view_func=Login.as_view('login'))

class ChangeUserPass(MethodView):
    '''
    Changes user password for loging into website, and checks for upper/lowercase special character and number, and password length.
    Default minimum password length is 12.
    '''
    def get(self):
        # Render the template as usual
        return render_template('change_user_password.html', min_password_length=current_app.config['MIN_PASSWORD_LENGTH'])

    def post(self):
        
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']
        requested_ip = get_remote_address()
        username = session.get('username')

        # Password complexity check
        if not is_password_complex(new_password):
            flash(f'Password must be at least {current_app.config["MIN_PASSWORD_LENGTH"]} characters long and include an uppercase letter, a lowercase letter, a number, and a special character.', 'alert alert-error')
            return redirect(url_for('auth.change_user_password'))

        # New passwords match check
        if new_password != confirm_new_password:
            logger.warning(f'Passwords Did Not Match during password change: IP {requested_ip}')
            flash('New passwords do not match.', 'alert alert-error')
            return redirect(url_for('auth.change_user_password'))

        # Attempt to update the user's password
        try:
            if update_user_password(username, current_password, new_password):
                flash('Password successfully updated.', 'alert alert-ok')
                return redirect(url_for('main.dashboard'))
        except Exception as e:
            flash('Current password is incorrect or update failed.', 'alert alert-error')
            logger.error(f'Username/Password update failed.\n{e}')
            return redirect(url_for('auth.change_user_password'))


auth.add_url_rule('/change_user_password', view_func=ChangeUserPass.as_view('change_user_password'))

class SignUP(MethodView):
    def get(self):
        return render_template('signup.html', min_password_length=current_app.config['MIN_PASSWORD_LENGTH'], nonce=g.nonce)
    
    def post(self):
        
        username = sanitizer.sanitize(request.form['username'])
        hashed_password = request.form['hashed_password']
        encrypted_dek_b64 = request.form['encryptedDEK']
        iv_b64 = request.form['iv']

        # Decode the Base64 encoded eDEK and IV
        # encrypted_dek = base64.b64decode(encrypted_dek_b64)
        # iv = base64.b64decode(iv_b64)

        # Store the encrypted DEK and IV securely in the user's account record
        # Assume a function `create_user_account` that handles this.
        if add_user(username, hashed_password, encrypted_dek_b64, iv_b64):
            flash('User successfully registered.', 'alert alert-ok')
            return redirect(url_for('main.home'))
        else:
            logger.error(f'Signup unsuccessful, username possibly in use')
            flash('Username already exists. Please choose a different one.', 'alert alert-error')
            return redirect(url_for('auth.signup'))
        
auth.add_url_rule('/signup', view_func=SignUP.as_view('signup'))

class Login2FA(MethodView):
    decorators = [limiter.limit("7 per minute")]
    def get(self):
        if session['initial_setup']:
            url = pyotp.totp.TOTP(decrypt_data(session['2fa_otp'])).provisioning_uri(session['username'], issuer_name="PyLockr")
            otp_img = qrcode.make(url)
            # Save the QR code to a bytes buffer
            buf = io.BytesIO()
            otp_img.save(buf, format='PNG')
            buf.seek(0)
            otp_img_data = base64.b64encode(buf.getvalue()).decode()
            update_initial_setup(session['username'])
            session['initial_setup'] = False
            return render_template('login2fa.html', otp_key=decrypt_data(session['2fa_otp']), otp_img=otp_img_data, otp_url=url)
        else:
            return render_template('login2fa.html', otp_img='')

    def post(self):
        otp = request.form.get('otp')
        if pyotp.TOTP(decrypt_data(session['2fa_otp'])).verify(otp):
            remember_me = 'remember_me' in request.form
            response = redirect(url_for('main.dashboard'))
            response = set_remember_me_cookie(remember_me, response)
            session['user_id'] = session.pop('temp_user_id', None)
            if session['user_id'] is not None:
                flash('Authentication Successful', 'alert alert-ok')
                return response
            else:
                flash('Authentication Failed due to user_id not being set', 'alert alert-error')
                return redirect(url_for('auth.login2fa'))
        else:
            flash('Authentication: Please Try QR Code Again', 'alert alert-error')
            return redirect(url_for('auth.login2fa'))
            
auth.add_url_rule('/login2fa', view_func=Login2FA.as_view('login2fa'))
