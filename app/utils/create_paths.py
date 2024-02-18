#!/usr/bin/env python3

from pathlib import Path
import os
from pysqlcipher3 import dbapi2 as sqlite

class Config:
    DB_PATH = os.path.join(os.environ.get('DB_PATH', '/usr/src/app/database'), 'users.db')
    BACKUP_DIR = os.path.join(os.environ.get('BACKUP_DIR', '/usr/src/app/backup'))

def setup_db(db_path):
    '''
    Sets up database table for user authentication. Passwords here are hashed.

    Sets up database table for password manager. All password entries here are encrypted.

    Sets up database table for backup times, a prompt for the user to download and keep a copy if it's been a while.
    '''
    conn = sqlite.connect(str(db_path))
    cursor = conn.cursor()

    passphrase = os.environ.get('SQLCIPHER_KEY')
    if not passphrase:
        raise ValueError("SQLCIPHER_KEY is not set in the environment variables.")
    
    cursor.execute(f"PRAGMA key = '{passphrase}'")

    # for authenticating users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users
        ([id] INTEGER PRIMARY KEY AUTOINCREMENT, [username] TEXT UNIQUE NOT NULL, [password_hash] TEXT NOT NULL)
    ''')

    # for password manager
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords
        ([id] INTEGER PRIMARY KEY AUTOINCREMENT, [user_id] INTEGER NOT NULL, [name] TEXT, [username] TEXT, [encrypted_password] TEXT, [category] TEXT, [notes] TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id))
    ''')

    # for tracking last time backups were made
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS backup_history (
            id INTEGER PRIMARY KEY,
            backup_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        ''')

    conn.commit()
    conn.close()

def set_up():

    db_path = Path(Config.DB_PATH).parent
    db_path.mkdir(parents=True, exist_ok=True)
    backup_path = Path(Config.BACKUP_DIR)
    backup_path.mkdir(parents=True, exist_ok=True)
    db_path = Path(Config.DB_PATH)
    print(f"Checking for DB at: {db_path.absolute()}")
    if not db_path.exists():
        print("DB not found, setting up the database...")
        setup_db(db_path=db_path) 
    else:
        print("DB found. Not initializing.")

set_up()