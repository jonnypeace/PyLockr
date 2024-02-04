#!/usr/bin/env python3

import os
from datetime import timedelta
from cryptography.fernet import Fernet

class Config:
    MIN_PASSWORD_LENGTH = int(os.environ.get('MIN_PASSWORD_LENGTH', 12))  # Default to 12 if not set
    SECRET_KEY = os.environ.get('APP_SECRET_KEY')
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get('SESSION_TIMEOUT', 30)))
    DB_PATH = os.path.join(os.getcwd(), 'database/users.db')
    KEY = os.environ.get('FERNET_KEY')
    # CIPHER_SUITE = Fernet(os.environ.get('FERNET_KEY'))

    # DB_PATH = os.environ.get('DATABASE_URL', 'sqlite:///database/users.db')
    FERNET_KEY = os.environ.get('FERNET_KEY')
    
    if FERNET_KEY:
        CIPHER_SUITE = Fernet(FERNET_KEY)
    else:
        raise ValueError("No FERNET_KEY found in environment variables.")