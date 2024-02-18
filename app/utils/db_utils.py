#!/usr/bin/env python3

from pysqlcipher3 import dbapi2 as sqlite
import os
from flask import current_app
from app.utils.security import *
from app.utils.db_utils import *
from html_sanitizer import Sanitizer
import secrets, string, logging
from contextlib import contextmanager
import glob

@contextmanager
def get_db_connection(passphrase):
    '''
    get_db_connection
    -----------------

    passphrase: str
        for the database, and taken from environment variable
    
    Creates and manages a database connection encrypted with SQLCipher,
    using the provided passphrase.

    :param passphrase: The passphrase used for the SQLCipher encryption.
    :return: Yields a connection to the encrypted SQLite database.
    '''

    conn = None
    try:
        conn = sqlite.connect(str(current_app.config['DB_PATH']))
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA key = '{passphrase}'")
        yield conn
    except sqlite.DatabaseError as e:
        logging.error(f"Database error: {e}")
        # Handle database-specific errors, e.g., incorrect passphrase, corrupted database
        raise
    except Exception as e:
        logging.error(f"Unexpected error when working with the database: {e}")
        # Handle any other unexpected errors
        raise
    finally:
        if conn:
            conn.close()

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

def db_server_backup():
    import subprocess
    import os
    from datetime import datetime

    # Define variables
    database_path = os.environ.get('DB_PATH')
    backup_dir = os.path.join(os.getcwd(), os.environ.get('BACKUP_DIR', 'backup'), 'db_bk_up')
    encryption_key = os.environ.get('SQLCIPHER_KEY')

    # Ensure the backup directory exists
    os.makedirs(backup_dir, exist_ok=True)

    # Create a unique backup file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_file = f"PyLockr_DB_Backup_{timestamp}.db"
    backup_path = os.path.join(backup_dir, backup_file)

    import tempfile

    # Create a temporary file securely
    with tempfile.NamedTemporaryFile(mode='w+', delete=True) as temp_sql:
        temp_sql.write(f'''
        PRAGMA key = '{encryption_key}';
        ATTACH DATABASE '{backup_path}' AS backupdb KEY '{encryption_key}';
        SELECT sqlcipher_export('backupdb');
        DETACH DATABASE backupdb;
        ''')
        temp_sql.flush()  # Ensure data is written to file

        # Build and execute the SQLCipher command
        sqlcipher_command = f'sqlcipher {database_path} < {temp_sql.name}'

        try:
            # Capture stdout and stderr for inspection
            result = subprocess.run(sqlcipher_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)

            # Check if the command was successful
            if result.returncode != 0:
                # Sanitize and log the error message, omitting sensitive information
                sanitized_error = result.stderr.replace(encryption_key, "[ENCRYPTION KEY]")
                print(f"Backup failed. Error: {sanitized_error}")
            else:
                print(f"Backup completed to {backup_path}")
                rotate_backups(backup_dir)
        except Exception as e:
            # Log a generic message for unexpected errors
            print("An unexpected error occurred during the backup process.")

def rotate_backups(backup_dir, max_backups=42):
    # Get a list of backup files sorted by modification time
    backup_files = sorted(glob.glob(os.path.join(backup_dir, 'PyLockr_DB_Backup_*.db')), key=os.path.getmtime)

    # If we have more backups than max_backups, remove the oldest
    while len(backup_files) > max_backups:
        os.remove(backup_files[0])
        backup_files.pop(0)
