#!/usr/bin/env python3

from . import auth
from flask import render_template, request, redirect, url_for, session, flash, current_app, make_response, g, jsonify
import re,secrets, os
from app.utils.db_utils import (authenticate_user, add_user, update_user_password,
                                decrypt_data, update_initial_setup, retrieve_edek,
                                validate_hashed_password, RedisComms)
from app.utils.key_exchange import shared_secret_exchange, derive_aes_key_from_shared_secret, return_new_key_exchanged_edek
from app.utils.pylockr_logging import *
from flask.views import MethodView
from html_sanitizer import Sanitizer
from app.utils.extensions import limiter
from flask_limiter.util import get_remote_address
import pyotp, qrcode, io, base64
from itsdangerous import URLSafeTimedSerializer, BadSignature
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

logger = PyLockrLogs(name='Auth')

sanitizer = Sanitizer()  # Used for name and username

# redis_client: RedisComms = RedisComms()

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

def set_remember_me_cookie(remember_me, response, user_id):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    token = s.dumps({'remember_me': remember_me})
    https_safe = current_app.config['SESSION_COOKIE_SECURE']
    response.set_cookie(user_id, token, max_age=30*24*3600, httponly=True, secure=https_safe, samesite='Strict')
    return response

def check_remember_me_cookie(user_id):
    remember_me_cookie = request.cookies.get(user_id, None)
    if remember_me_cookie:
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(remember_me_cookie)
            if 'remember_me' not in data:
                raise CookieIntegrityError("Invalid 'pylockr_remember_me' cookie data.")
            cookie_status = data['remember_me']
            return cookie_status
        except BadSignature:
            logger.error(f'Cookie has a bad signature, and potentially been tampered with')
            return False
    return False

class BaseAuthView(MethodView):
    '''
    if user_id is not in session, redirect to home/login page
    '''
    decorators = [limiter.limit("7 per minute")]
    
    def __init__(self):
        self.redis_client = RedisComms()  # Initialize your Redis communication class
    
    def dispatch_request(self, *args, **kwargs):
        user_id = session.get('user_id') or session.get('temp_user_id')

        if user_id is None:
            return redirect(url_for('main.home'))
        
        # If user_id is in session, extend DEK TTL in Redis
        self.extend_dek_ttl(user_id)
        return super(BaseAuthView, self).dispatch_request(*args, **kwargs)

    def extend_dek_ttl(self, user_id):
        '''
        Extend the TTL for the user's DEK in Redis.
        '''
        # This assumes your RedisComms class has a method to extend DEK TTL
        # Modify this method based on your RedisComms implementation
        try:
            self.redis_client.extend_dek_ttl(user_id)
        except Exception as e:
            logger.error(f"Error extending DEK TTL for user {user_id}: {e}")
            # Handle the error as appropriate for your application


class Logout(MethodView):
    def post(self):
        '''
        Logs out and clears the session and redirects to homepage.
        '''
        session.clear()
        flash('You have been logged out.', 'alert alert-ok')
        return redirect(url_for('main.home'))
auth.add_url_rule('/logout', view_func=Logout.as_view('logout'))


class GetEdekIV(BaseAuthView):
    '''
    Pull in client public key, iv and salt, generate a server key pair, and encrypt the dek stored in redis to send back.
    '''
    def post(self):
        try:
            # Attempt to retrieve the user's eDEK and IV using the provided username
            user_id = session.get('user_id') or session.get('temp_user_id')
            data = request.get_json()
            edek_b64, server_public_key_b64 = return_new_key_exchanged_edek(user_id,
                                                                            data['salt'],
                                                                            data['publicKey'],
                                                                            data['iv'])
            logger.info(f'{edek_b64=}, {server_public_key_b64}')
            return jsonify({'edek': edek_b64, 'serverPubKeyB64': server_public_key_b64}), 200
        except Exception as e:
            logger.error(e)
            return jsonify({'error': 'Key Error'}), 404

# Register the route for handling the AJAX request
auth.add_url_rule('/get_user_edek_iv', view_func=GetEdekIV.as_view('get_user_edek_iv'))


class SendDek(BaseAuthView):
    '''
    Sends dek from client to redis server
    '''
    def post(self):
        super().__init__()
        user_id = session.get('temp_user_id')
        data = request.get_json()
        if user_id:
            self.redis_client.send_dek(user_id, data['dek'])
            return jsonify({"message": "Session data stored."}), 200
        return jsonify({"message": "No user session."}), 400
auth.add_url_rule('/send_dek', view_func=SendDek.as_view('send_dek'))


class Authenticate(MethodView):
    decorators = [limiter.limit("7 per minute")]
    def post(self):
        data = request.get_json()
        username = sanitizer.sanitize(data['username'])
        hashed_password = data['password']
        # Verification logic here...
        user = authenticate_user(username, hashed_password)
        if user:
            session['temp_user_id'] = user.id # Needed for 2FA and storing dek in redis
            # Assuming get_user_edek_iv is a function that retrieves the EDEK and IV for the user
            user = retrieve_edek(username=username)
            return jsonify({'encryptedDEK': user.edek, 'iv': user.iv}), 200
        else:
            return jsonify({'message': 'Authentication failed'}), 403

auth.add_url_rule('/authenticate', view_func=Authenticate.as_view('authenticate'))


class KeyExchange(BaseAuthView):
    def post(self):
        data = request.get_json()
        super().__init__()
        try:
            shared_secret, server_public_key_b64 = shared_secret_exchange(data['publicKey'])
            user_id = session.get('user_id') or session.get('temp_user_id')

            # This sends to redis, storing after encrypting with the fernet key
            self.redis_client.send_secret(user_id, shared_secret)
            self.redis_client.send_salt(user_id, data['salt'])
            # Return the server's public key to the client
            return jsonify({'serverPublicKey': server_public_key_b64})
        
        except Exception as e:
            logger.error(f'Error during Key Communication\n{e}')
            return jsonify({'error': 'Key Comms Error'}), 500
    
auth.add_url_rule('/keyexchange', view_func=KeyExchange.as_view('keyexchange'))

    
class SharedSecretDecrypt(BaseAuthView):
    def post(self):
        super().__init__()
        try:
            user_id = session.get('user_id') or session.get('temp_user_id')
            shared_secret = self.redis_client.get_secret(user_id)
            salt = self.redis_client.get_salt(user_id)
            kek = derive_aes_key_from_shared_secret(shared_secret, salt)

            data = request.get_json()
            iv = base64.b64decode(data['ivB64'])

            encrypted_edek = base64.b64decode(data['edekBase64'])
            # Create an AESGCM instance with the KEK
            aesgcm = AESGCM(kek)
            # Decrypt the EDEK
            dek = aesgcm.decrypt(iv, encrypted_edek, None)
            # This sends to redis, storing after encrypting with the fernet key
            self.redis_client.send_dek(user_id, dek)
            # Clean up the Redis by removing the shared secret and salt
            self.redis_client.delete_secret(user_id)
            self.redis_client.delete_salt(user_id)

            return jsonify({'success': 'key exchange successful'}), 200

        except InvalidTag as e:
            logger.error(f'Most likely you have incorrectly formatted cryptography, or incorrect credentials. Check formatting\n{e}')
            return jsonify({'error': 'Incorrect Format'}), 500

auth.add_url_rule('/secretprocessing', view_func=SharedSecretDecrypt.as_view('secretprocessing'))


class Login(MethodView):
    decorators = [limiter.limit("7 per minute")]
    def get(self):
        # Render the template as usual
        return render_template('login.html', nonce=g.nonce)

    def post(self):
        '''
        Logs into website and starts a session.
        Rate limited, 7 per minute.
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
                session['remember_me'] = check_remember_me_cookie(user.id)
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

class ChangeUserPass(BaseAuthView):
    '''
    Changes user password for loging into website, and checks for upper/lowercase special character and number, and password length.
    Default minimum password length is 12.
    '''
    def get(self):
        # Render the template as usual
        return render_template('change_user_password.html', min_password_length=current_app.config['MIN_PASSWORD_LENGTH'])

    def post(self):
        
        current_password = request.form['current_password'] # needs to be hashed
        new_password = request.form['new_password'] # needs to be hashed
        confirm_new_password = request.form['confirm_new_password'] # needs to be hashed
        dek = request.form['dek']
        edek = request.form['encryptedDEK']
        iv = request.form['iv']

        requested_ip = get_remote_address()
        username = session.get('username')

        # Password complexity check
        if not validate_hashed_password(new_password):
            flash(f'Passwords have failed security checks', 'alert alert-error')
            return redirect(url_for('auth.change_user_password'))

        # New passwords match check
        if new_password != confirm_new_password:
            logger.warning(f'Passwords Did Not Match during password change: IP: {requested_ip} Username: {username}')
            flash('New passwords do not match.', 'alert alert-error')
            return redirect(url_for('auth.change_user_password'))

        # Attempt to update the user's password
        try:
            if update_user_password(username, current_password, new_password, edek, iv):
                self.redis_client.send_dek(session['user_id'], dek)
                flash('Password successfully updated.', 'alert alert-ok')
                return redirect(url_for('main.dashboard'))
        except Exception as e:
            flash('Current password is incorrect or update failed.', 'alert alert-error')
            logger.error(f'Username/Password update failed.\n{e}')
            return redirect(url_for('auth.change_user_password'))


auth.add_url_rule('/change_user_password', view_func=ChangeUserPass.as_view('change_user_password'))

class SignUP(MethodView):
    decorators = [limiter.limit("7 per minute")]
    def get(self):
        return render_template('signup.html', min_password_length=current_app.config['MIN_PASSWORD_LENGTH'], nonce=g.nonce)
    
    def post(self):
        
        username = sanitizer.sanitize(request.form['username'])
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        encrypted_dek_b64 = request.form['encryptedDEK']
        iv_b64 = request.form['iv']
        requested_ip = get_remote_address()

        # Password complexity check
        if not validate_hashed_password(password):
            flash(f'Passwords have failed security checks', 'alert alert-error')
            return redirect(url_for('auth.signup'))

        # New passwords match check
        if password != confirm_password:
            logger.warning(f'Passwords Did Not Match during signup: IP: {requested_ip} Username: {username}')
            flash('Passwords do not match.', 'alert alert-error')
            return redirect(url_for('auth.signup'))

        # Store the encrypted DEK and IV securely in the user's account record
        # Assume a function `create_user_account` that handles this.
        if add_user(username, password, encrypted_dek_b64, iv_b64):
            flash('User successfully registered.', 'alert alert-ok')
            return redirect(url_for('main.home'))
        else:
            logger.error(f'Signup unsuccessful, username possibly in use')
            flash('Username already exists. Please choose a different one.', 'alert alert-error')
            return redirect(url_for('auth.signup'))
        
auth.add_url_rule('/signup', view_func=SignUP.as_view('signup'))

class Login2FA(BaseAuthView):
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
            response = set_remember_me_cookie(remember_me, response, session['temp_user_id'])
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
