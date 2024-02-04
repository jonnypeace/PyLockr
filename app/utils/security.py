#!/usr/bin/env python3

from flask import current_app
import os

def get_secure_key():
    key = os.environ.get('SQLCIPHER_KEY')
    if not key:
        raise ValueError("SQLCIPHER_KEY is not set in the environment variables.")
    return key

def encrypt_password(password):
    return current_app.config['CIPHER_SUITE'].encrypt(password.encode())

def encrypt_data(data):
    return current_app.config['CIPHER_SUITE'].encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    return current_app.config['CIPHER_SUITE'].decrypt(encrypted_data.encode()).decode()