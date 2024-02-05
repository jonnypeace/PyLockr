#!/usr/bin/env python3

from flask import current_app
import os

def get_secure_key():
    '''
    Grabs the key for encryption from environment variable

    Returns:
        key
    '''
    key = os.environ.get('SQLCIPHER_KEY')
    if not key:
        raise ValueError("SQLCIPHER_KEY is not set in the environment variables.")
    return key

def encrypt_data(data):
    '''
    Encrypts notes and passwords for password manager
    '''
    return current_app.config['CIPHER_SUITE'].encrypt(data.encode())

def decrypt_data(encrypted_data):
    '''
    Decrypts passwords and notes for password manager
    '''
    return current_app.config['CIPHER_SUITE'].decrypt(encrypted_data).decode()
