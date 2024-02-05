#!/usr/bin/env python3

from pysqlcipher3 import dbapi2 as sqlite
import os
from flask import current_app

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
    print(passphrase)
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
