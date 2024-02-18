#!/usr/bin/env python3

import os
from datetime import timedelta
from cryptography.fernet import Fernet

class Config:
    MIN_PASSWORD_LENGTH = int(os.environ.get('MIN_PASSWORD_LENGTH', 12))  # Default to 12 if not set
    SECRET_KEY = os.environ.get('APP_SECRET_KEY')
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get('SESSION_TIMEOUT', 30)))
    DB_PATH = os.path.join(os.environ.get('DB_PATH', '/usr/src/app/database'), 'users.db')
    FERNET_KEY = os.environ.get('FERNET_KEY')
    BACKUP_DIR = os.path.join(os.environ.get('BACKUP_DIR', '/usr/src/app/backup'))

    if FERNET_KEY:
        # Theres a bug in python 3.11/python-dotenv/flask loading .env files with base64 encoding.
        # The bug strips the padding from the end of the string.
        # Calculate required padding based on the current length
        padding_needed = 4 - len(FERNET_KEY) % 4
        if padding_needed != 4:  # Only add padding if it's less than 4
            FERNET_KEY += "=" * padding_needed
        CIPHER_SUITE = Fernet(FERNET_KEY)
    else:
        raise ValueError("No FERNET_KEY found in environment variables.")