#!/usr/bin/env python3

import os
from datetime import timedelta
from cryptography.fernet import Fernet

class Config:
    MIN_PASSWORD_LENGTH = int(os.environ.get('MIN_PASSWORD_LENGTH', 12))  # Default to 12 if not set
    SECRET_KEY = os.environ.get('APP_SECRET_KEY')
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get('SESSION_TIMEOUT', 30)))
    DB_PATH = os.environ.get('DB_PATH')
    FERNET_KEY = os.environ.get('FERNET_KEY')

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

    secure_cookies =  os.environ.get('SECURE_COOKIE_HTTPS', True)

    # Convert the string to a boolean
    SESSION_COOKIE_SECURE = secure_cookies.lower() in ['true', '1']
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'  # or 'Lax'

