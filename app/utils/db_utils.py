#!/usr/bin/env python3

from pysqlcipher3 import dbapi2 as sqlite
import os

def get_db_connection(passphrase):
    conn = sqlite.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA key = '{passphrase}'")
    return conn

# Assuming your database file is named 'users.db' and is in the root of your project directory
db_path = os.path.join(os.getcwd(), 'database/users.db')

def setup_db():
    conn = sqlite.connect(str(db_path))
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
