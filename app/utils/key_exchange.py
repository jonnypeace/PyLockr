import base64, binascii
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from app.utils.db_utils import RedisComms

def shared_secret_exchange(client_public_key_b64):
    # Load the client's public key from the request
    client_public_key_bytes = base64.b64decode(client_public_key_b64)
    client_public_key = load_der_public_key(client_public_key_bytes, backend=default_backend())

    # Generate the server's private and public key for ECDH
    server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_public_key = server_private_key.public_key()

    # Serialize the server's public key to send it back to the client
    server_public_key_der = server_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    server_public_key_b64 = base64.b64encode(server_public_key_der).decode('utf-8')

    # Derive the shared secret using the client's public key and server's private key 
    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
    return shared_secret, server_public_key_b64

# aes-key is the kek
def derive_aes_key_from_shared_secret(shared_secret, salt):
    # Derive a 256-bit AES key from the shared secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        info=b"ECDH AES-GCM",
        backend=default_backend()
    )
    aes_key = hkdf.derive(shared_secret)
    return aes_key

def return_new_key_exchanged_edek(user_id,salt,public_key, iv):
    '''
    returns edek in base64, and server public key

    user_id:
        user id
    salt:
        Received from client
    public_key:
        Received from client
    iv:
        Received from client
    '''
    redis_client = RedisComms()
    dek = redis_client.get_dek(user_id)
    salt = base64.b64decode(salt)
    shared_secret, server_public_key_b64 = shared_secret_exchange(public_key)
    kek = derive_aes_key_from_shared_secret(shared_secret, salt)
    iv = base64.b64decode(iv)
    # Create an AESGCM instance with the KEK
    aesgcm = AESGCM(kek)
    # Encrypt the DEK
    edek = aesgcm.encrypt(iv, dek, None)
    edek_b64 = base64.b64encode(edek).decode()
    return edek_b64, server_public_key_b64

class ValidB64Error(Exception):
    """Exception raised when the integrity of received base64 string is compromised."""
    def __init__(self, message="Base64 check failed"):
        self.message = message
        super().__init__(self.message)


def is_valid_base64(*args):
    """Validate multiple Base64 encoded strings.

    Args:
        *args: Variable length argument list of strings to be validated as Base64.

    Returns:
        bool: True if all strings are valid Base64.

    Raises:
        ValidB64Error: If any string is not valid Base64.
    """
    try:
        for s in args:
            # Attempt to decode the string from Base64
            base64.b64decode(s, validate=True)
        return True
    except (ValueError, TypeError, binascii.Error) as e:
        # Raising an exception with more context about the failure
        raise ValidB64Error(f"Base64 check failed: {e}")