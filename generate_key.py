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
    fernet_key = Fernet.generate_key()
    # Decode the key to convert from bytes to string
    fernet_decoded_key = fernet_key.decode()

    print(f'''
        Some randomly generated keys you can use for your
        .env file:

        APP_SECRET_KEY='{generate_secret_key(32)}'
        FERNET_KEY='{fernet_decoded_key}'
        REDIS_PASSWORD='{generate_password(32)}'
        MYSQL_ROOT='{generate_password(32)}'
        MYSQL_PASSWORD='{generate_password(32)}'
        GPG_PASSPHRASE='{generate_password(32)}'

        Please Backup These keys, they are especially important for your password encryption,
        and the FERNET_KEY which applies another layer and encrypts passwords and notes.
    ''')

if __name__ == "__main__":
    generate_keys()
