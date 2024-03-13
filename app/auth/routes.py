#!/usr/bin/env python3

from . import auth
from flask import render_template, request, redirect, url_for, session, flash, current_app
import re,secrets
from app.utils.db_utils import authenticate_user, add_user, update_user_password, decrypt_data, encrypt_data
from app.utils.pylockr_logging import *
from flask.views import MethodView
from html_sanitizer import Sanitizer
from app.utils.extensions import limiter
from flask_limiter.util import get_remote_address

logger = PyLockrLogs(name='Auth')

sanitizer = Sanitizer()  # Used for name and username

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

class Logout(MethodView):
    def post(self):
        '''
        Logs out and clears the session and redirects to homepage.
        '''
        session.clear()
        flash('You have been logged out.', 'alert alert-ok')
        return redirect(url_for('main.home'))
auth.add_url_rule('/logout', view_func=Logout.as_view('logout'))

class Login(MethodView):
    decorators = [limiter.limit("5 per minute")]
    def get(self):
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        # Render the template as usual
        return render_template('login.html', csrf_token=csrf_token)

    def post(self):
        '''
        Logs into website and starts a session.
        Rate limited, 5 per minute.
        '''
        submitted_token = request.form.get('csrf_token')
        
        if not submitted_token or submitted_token != session.get('csrf_token'):
            flash('CSRF token is invalid.', 'alert alert-error')
            return redirect(url_for('login'))
        
        username = sanitizer.sanitize(request.form['username'])
        password = request.form['password']
        
        requested_ip = get_remote_address()
        user = authenticate_user(username, password)
        if user:
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful.', 'alert alert-ok')
            logger.info(f'Successful login attempt from IP: {requested_ip}')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid username or password.', 'alert alert-error')
            logger.warning(f'Failed login attempt from IP: {requested_ip}')
            return redirect(url_for('auth.login_form'))

auth.add_url_rule('/login', view_func=Login.as_view('login'))

class ChangeUserPass(MethodView):
    '''
    Changes user password for loging into website, and checks for upper/lowercase special character and number, and password length.
    Default minimum password length is 12.
    '''
    def get(self):
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        # Render the template as usual
        return render_template('change_user_password.html', min_password_length=current_app.config['MIN_PASSWORD_LENGTH'], csrf_token=csrf_token)

    def post(self):
        submitted_token = request.form.get('csrf_token')
        
        if not submitted_token or submitted_token != session.get('csrf_token'):
            flash('CSRF token is invalid.', 'alert alert-error')
            return redirect(url_for('change_user_password'))
        
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
        if update_user_password(username, current_password, new_password):
            flash('Password successfully updated.', 'alert alert-ok')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Current password is incorrect or update failed.', 'alert alert-error')
            return redirect(url_for('auth.change_user_password'))


auth.add_url_rule('/change_user_password', view_func=ChangeUserPass.as_view('change_user_password'))

class SignUP(MethodView):
    def get(self):
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        return render_template('signup.html', min_password_length=current_app.config['MIN_PASSWORD_LENGTH'], csrf_token=csrf_token)
    
    def post(self):
        submitted_token = request.form.get('csrf_token')
        
        if not submitted_token or submitted_token != session.get('csrf_token'):
            flash('CSRF token is invalid.', 'alert alert-error')
            return redirect(url_for('signup'))
        
        username = sanitizer.sanitize(request.form['username'])
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            logger.warning(f'Signup Failed, passwords do not match: Username {username}')
            flash('Passwords do not match. Please try again.', 'alert alert-error')
            return redirect(url_for('auth.signup'))
        
        # Password complexity check
        if not is_password_complex(password):
            flash(f'Password must be at least {current_app.config["MIN_PASSWORD_LENGTH"]} characters long and include an uppercase letter, a lowercase letter, a number, and a special character.', 'alert alert-error')
            return redirect(url_for('auth.signup'))
        
        if add_user(username, password):
            flash('User successfully registered.', 'alert alert-ok')
            return redirect(url_for('main.home')) 
        else:
            logger.error(f'Username already be in use')
            flash('Username already exists. Please choose a different one.', 'alert alert-error')
            return redirect(url_for('auth.signup'))
        
auth.add_url_rule('/signup', view_func=SignUP.as_view('signup'))
