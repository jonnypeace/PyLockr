#!/usr/bin/env python3

from . import auth
from flask import render_template, request, redirect, url_for, session, flash, current_app
from werkzeug.security import generate_password_hash, check_password_hash
import re
from app.utils.security import *
from app.utils.db_utils import *
from flask.views import MethodView

class Logout(MethodView):
    def post(self):
        '''
        Logs out and clears the session and redirects to homepage.
        '''
        session.clear()
        return redirect(url_for('main.home'))
auth.add_url_rule('/logout', view_func=Logout.as_view('logout'))

class Login(MethodView):
    def post(self):
        '''
        Logs into website and starts a session.
        '''
        username = request.form['username']
        password = request.form['password']
        
        # Retrieve the secure passphrase
        secure_key = get_secure_key()
        
        # Connect to the encrypted database (SQLCipher) using the secure key
        with get_db_connection(secure_key) as conn:
            c = conn.cursor()
        
            # Fetch the user by username
            c.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = c.fetchone()

        if user and check_password_hash(user[2], password):
            # User authenticated successfully
            session['user_id'] = user[0] 
            session['username'] = user[1]  # Log the user in by setting the session
            return redirect(url_for('main.dashboard'))  # Redirect to the dashboard page after successful login
        else:
            return 'Login failed. Check your login details.'
auth.add_url_rule('/login', view_func=Login.as_view('login'))

class ChangeUserPass(MethodView):
    '''
    Changes user password for loging into website, and checks for upper/lowercase special character and number, and password length.
    Default minimum password length is 12.
    '''
    def get(self):
        return render_template('change_user_password.html')
    def post(self):
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        uppercase_characters = len(re.findall(r"[A-Z]", new_password))
        lowercase_characters = len(re.findall(r"[a-z]", new_password))
        numerical_characters = len(re.findall(r"[0-9]", new_password))
        special_characters = len(re.findall(r"[!@#$%^&*()-_+<>?]", new_password))
        
        if len(new_password) < current_app.config['MIN_PASSWORD_LENGTH'] or not all([uppercase_characters,lowercase_characters,numerical_characters,special_characters]):
            flash(f'Password must be at least {current_app.config["MIN_PASSWORD_LENGTH"]} characters long and include an uppercase letter, a lowercase letter, a number, and a special character.', 'error')
            return redirect(url_for('auth.change_user_password'))

        # Retrieve the secure passphrase
        secure_key = get_secure_key()
        username = session['username']
        # Connect to the encrypted database (SQLCipher) using the secure key
        with get_db_connection(secure_key) as conn:
            c = conn.cursor()
            # Insert new user into the users table
            c.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            if user and check_password_hash(user[2], current_password):
                # Check if new password and confirmation match
                if new_password == confirm_new_password:
                    # Update password
                    new_password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
                    c.execute('UPDATE users SET password_hash = ? WHERE username = ?', (new_password_hash, username))
                    conn.commit()
                    flash('Password successfully updated.', 'success')
                else:
                    flash('New password and confirmation do not match.', 'error')
            else:
                flash('Current password is incorrect.', 'error')
        return redirect(url_for('main.dashboard'))
auth.add_url_rule('/change_user_password', view_func=ChangeUserPass.as_view('change_user_password'))

class SignUP(MethodView):
    def get(self):
        return render_template('signup.html')  # Render the sign-up page if method is GET
    def post(self):
        username = request.form['username']
        password = request.form['password']

        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('auth.signup'))

        uppercase_characters = len(re.findall(r"[A-Z]", password))
        lowercase_characters = len(re.findall(r"[a-z]", password))
        numerical_characters = len(re.findall(r"[0-9]", password))
        special_characters = len(re.findall(r"[!@#$%^&*()-_+<>?]", password))
        
        if len(password) < current_app.config['MIN_PASSWORD_LENGTH'] or not all([uppercase_characters,lowercase_characters,numerical_characters,special_characters]):
            flash(f'Password must be at least {current_app.config["MIN_PASSWORD_LENGTH"]} characters long and include an uppercase letter, a lowercase letter, a number, and a special character.', 'error')
            return redirect(url_for('auth.signup'))
        
        # Hash the password for secure storage
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Retrieve the secure passphrase
        secure_key = get_secure_key()
        
        # Connect to the encrypted database (SQLCipher) using the secure key
        with get_db_connection(secure_key) as conn:
            c = conn.cursor()
            # Insert new user into the users table
            c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed_password))
            conn.commit()

        return redirect(url_for('main.home'))  # Redirect to the login page after successful registration
auth.add_url_rule('/signup', view_func=SignUP.as_view('signup'))