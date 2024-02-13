#!/usr/bin/env python3

from cryptography.fernet import Fernet
import secrets, string

def generate_password(length: int = 12, special_chars: str ='#-!£$%^&_:'):
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits + special_chars
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

def generate_secret_key(length=24):
    return secrets.token_hex(length)

def generate_keys():
    # Example usage:
    flask_secret_key = generate_secret_key()
    # Generate a new Fernet key
    key = Fernet.generate_key()
    # Decode the key to convert from bytes to string
    fernet_decoded_key = key.decode()
    sqlcipher_key = generate_password(32)
    print(f'''
          If adding to your .bashrc file:
          export SECRET_KEY='{flask_secret_key}'
          export SQLCIPHER_KEY='{sqlcipher_key}'
          export FERNET_KEY='{fernet_decoded_key}'
          
          or .env file (better if using a docker build):
          SECRET_KEY='{flask_secret_key}
          SQLCIPHER_KEY='{sqlcipher_key}'
          FERNET_KEY='{fernet_decoded_key}'
          
          Please Backup These keys, especially the SQLCIPHER_KEY which encrypts the database,
          and the FERNET_KEY which applies another layer and encrypts passwords and notes.
            ''')

if __name__ == "__main__":
    generate_keys()