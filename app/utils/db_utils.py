#!/usr/bin/env python3

from pysqlcipher3 import dbapi2 as sqlite
from flask import current_app
from app.utils.pylockr_logging import PyLockrLogs
from app.utils.security import *
from contextlib import contextmanager

logger = PyLockrLogs(name=__name__)

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
        logger.error(f"Database error: {e}")
        # Handle database-specific errors, e.g., incorrect passphrase, corrupted database
        raise
    except Exception as e:
        logger.error(f"Unexpected error when working with the database: {e}")
        # Handle any other unexpected errors
        raise
    finally:
        if conn:
            conn.close()
