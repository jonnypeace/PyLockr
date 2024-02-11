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
    Encrypts notes and passwords for the password manager.

    This function applies an additional layer of encryption using Fernet
    on top of the SQLCipher database encryption. The encrypted data is stored
    in the SQLCipher-encrypted database, effectively double-encrypting it.
    '''
    return current_app.config['CIPHER_SUITE'].encrypt(data.encode())

def decrypt_data(encrypted_data):
    '''
    Decrypts passwords and notes for the password manager.

    This function decrypts data that was previously encrypted with Fernet,
    which is stored in a SQLCipher-encrypted database. This means the data
    is decrypted by Fernet first, then automatically decrypted by SQLCipher
    as it's read from the database, reversing the double encryption process.
    '''
    return current_app.config['CIPHER_SUITE'].decrypt(encrypted_data).decode()
