#!/usr/bin/env python3

from . import auth
from flask import render_template, request, redirect, url_for, session, flash, current_app
from werkzeug.security import generate_password_hash, check_password_hash
import re
from app.utils.security import *
from app.utils.db_utils import *

@auth.route('/logout', methods=['POST'])
def logout():
    # Clear the session
    session.clear()
    # Redirect to the login page
    return redirect(url_for('main.home'))

@auth.route('/login', methods=['POST'])
def login():

    global username
    username = request.form['username']
    password = request.form['password']
    
    # Retrieve the secure passphrase
    secure_key = get_secure_key()
    
    # Connect to the encrypted database (SQLCipher) using the secure key
    conn = get_db_connection(secure_key)
    c = conn.cursor()
    
    # Fetch the user by username
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        # User authenticated successfully
        session['user_id'] = user[0] 
        session['username'] = user[1]  # Log the user in by setting the session
        return redirect(url_for('main.dashboard'))  # Redirect to the dashboard page after successful login
    else:
        return 'Login failed. Check your login details.'
    
@auth.route('/change_user_password', methods=['GET', 'POST'])
def change_user_password():

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        uppercase_characters = len(re.findall(r"[A-Z]", new_password))
        lowercase_characters = len(re.findall(r"[a-z]", new_password))
        numerical_characters = len(re.findall(r"[0-9]", new_password))
        special_characters = len(re.findall(r"[!@#$%^&*()-_+<>?]", new_password))
        
        if len(new_password) < current_app.config['MIN_PASSWORD_LENGTH'] or not all([uppercase_characters,lowercase_characters,numerical_characters,special_characters]):
            flash('Password must be at least 12 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.', 'error')
            return redirect(url_for('auth.change_user_password'))

        # Retrieve the secure passphrase
        secure_key = get_secure_key()
        username = session['username']
        
        # Connect to the encrypted database (SQLCipher) using the secure key
        conn = get_db_connection(secure_key)
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
        
        conn.close()
        return redirect(url_for('main.dashboard'))

    return render_template('change_user_password.html')

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
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
            flash('Password must be at least 12 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.', 'error')
            return redirect(url_for('auth.signup'))
        
        # Hash the password for secure storage
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Retrieve the secure passphrase
        secure_key = get_secure_key()
        
        # Connect to the encrypted database (SQLCipher) using the secure key
        conn = get_db_connection(secure_key)
        c = conn.cursor()

        # Insert new user into the users table
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed_password))

        conn.commit()
        conn.close()

        return redirect(url_for('main.home'))  # Redirect to the login page after successful registration

    return render_template('signup.html')  # Render the sign-up page if method is GET