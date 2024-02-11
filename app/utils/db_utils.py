#!/usr/bin/env python3

from pysqlcipher3 import dbapi2 as sqlite
import os
from flask import current_app
from app.utils.security import *
from app.utils.db_utils import *
from html_sanitizer import Sanitizer

def get_db_connection(passphrase):
    '''
    get_db_connection
    -----------------

    passphrase: str
        for the database
    
    Returns:
        Connection to database
    '''
    conn = sqlite.connect(str(current_app.config['DB_PATH']))
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA key = '{passphrase}'")
    return conn

def setup_db():
    '''
    Sets up database table for user authentication. Passwords here are hashed.

    Sets up database table for password manager. All password entries here are encrypted.

    Sets up database table for backup times, a prompt for the user to download and keep a copy if it's been a while.
    '''
    conn = sqlite.connect(str(current_app.config['DB_PATH']))
    cursor = conn.cursor()

    passphrase = os.environ.get('SQLCIPHER_KEY')
    if not passphrase:
        raise ValueError("SQLCIPHER_KEY is not set in the environment variables.")
    
    cursor.execute(f"PRAGMA key = '{passphrase}'")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users
        ([id] INTEGER PRIMARY KEY, [username] TEXT, [password_hash] TEXT)
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords
        ([id] INTEGER PRIMARY KEY, [user_id] INTEGER, [name] TEXT, [username] TEXT, [encrypted_password] TEXT, [notes] TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id))
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS backup_history (
            id INTEGER PRIMARY KEY,
            backup_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        ''')

    conn.commit()
    conn.close()

# def import_csv(filepath: str):
#     import csv
#     from pathlib import Path

#     sanitizer = Sanitizer()

#     # Retrieve the secure passphrase
#     secure_key = get_secure_key()
    
#     # Connect to the encrypted database (SQLCipher) using the secure key
#     conn = get_db_connection(secure_key)
#     c = conn.cursor()

#     if Path(filepath).exists():
#         with open(filepath, mode='r') as file:
#             csv_reader = csv.reader(file)
#             for row in csv_reader:
#                 name, username = row[3], row[8]
#                 encrypted_pass = encrypt_data(sanitizer.sanitize(row[9]))
#                 encrypted_notes = encrypt_data(sanitizer.sanitize(row[4]))
#                 # Insert new password into the passwords table
#                 c.execute('INSERT INTO passwords (user_id, name, username, encrypted_password, notes) VALUES (?, ?, ?, ?, ?)', 
#                         (session['user_id'], name, username, encrypted_pass, encrypted_notes))

#         conn.commit()
#         conn.close()