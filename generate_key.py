#!/usr/bin/env python3

from cryptography.fernet import Fernet
import secrets
import base64

def generate_keys():
    # Generate a new Fernet key
    key = Fernet.generate_key()
    # Decode the key to convert from bytes to string
    fer_decoded_key = key.decode()
    # Generate a 32-byte (256-bit) random key
    random_key = secrets.token_bytes(32)
    # Optionally, encode the key in a readable format such as hex or base64
    encoded_key = base64.b64encode(random_key).decode('utf-8')
    print(f'''
          If adding to your .bashrc file:
          export SQLCIPHER_KEY='{encoded_key}'
          export FERNET_KEY='{fer_decoded_key}'
          
          or .env file:
          SQLCIPHER_KEY='{encoded_key}'
          FERNET_KEY='{fer_decoded_key}'
            ''')

if __name__ == "__main__":
    generate_keys()