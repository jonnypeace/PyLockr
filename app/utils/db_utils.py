#!/usr/bin/env python3

from app.utils.pylockr_logging import PyLockrLogs
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, TIMESTAMP, inspect, Boolean, LargeBinary, BLOB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql import func
from pathlib import Path
import os, uuid, logging, pyotp, base64, redis, re
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import IntegrityError
from flask import current_app
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.exc import SQLAlchemyError

logger = PyLockrLogs(name='DB_UTILS')

logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING) # Set up for logging warning+ messages

Base = declarative_base()

# Initialize engine and session
DB_PATH = os.environ.get('DB_PATH')

if DB_PATH is None:
    raise ValueError('DB_PATH environment variable not set in .env')

engine = create_engine(DB_PATH, echo=False) # use echo=True for debugging
Session = scoped_session(sessionmaker(bind=engine, autoflush=False))

def init_db():
    inspector = inspect(engine)
    Base.metadata.create_all(engine,checkfirst=True)

class User(Base):
    __tablename__ = 'users'
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    username = Column(String(128), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    otp_2fa_enc = Column(BLOB, nullable=False)
    initial_setup = Column(Boolean, nullable=False, default=True)
    edek = Column(String(128), nullable=False)
    iv = Column(String(64), nullable=False)
    salt = Column(String(64), nullable=False)
    temporary_dek = Column(LargeBinary, nullable=True)
    change_user_pass = Column(Boolean, default=False)
    passwords = relationship("Password", back_populates="user")
    backup_history = relationship("BackupHistory", back_populates="user")

class Password(Base):
    __tablename__ = 'passwords'
    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    # id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(64), ForeignKey('users.id'), nullable=False)
    Name = Column(String(128)) # b64 direct from js. decodes into crypto
    ivName = Column(String(64)) # b64 direct from js. decodes into bytes
    Username = Column(String(128)) # b64 direct from js. decodes into crypto
    ivUsername = Column(String(64)) # b64 direct from js. decodes into bytes
    Password = Column(String(128)) # b64 direct from js. decodes into crypto
    ivPassword = Column(String(64)) # b64 direct from js. decodes into bytes
    Category = Column(String(128)) # b64 direct from js. decodes into crypto
    ivCategory = Column(String(64)) # b64 direct from js. decodes into bytes
    Notes = Column(String(1024)) # b64 direct from js. decodes into crypto
    ivNotes = Column(String(64)) # b64 direct from js. decodes into bytes
    user = relationship("User", back_populates="passwords")

class BackupHistory(Base):
    __tablename__ = 'backup_history'
    id = Column(Integer, primary_key=True)
    backup_date = Column(TIMESTAMP, default=func.current_timestamp())
    user_id = Column(String(128), ForeignKey('users.id'), nullable=False)
    user = relationship("User", back_populates="backup_history")  # This establishes a relationship with the User model


def update_initial_setup(username)-> bool:
    with Session() as session:
        user = session.query(User).filter_by(username=username).first()
        if user:
            user.initial_setup = False
            session.commit()
            logger.info(f'{username} Completed initial setup')
            return True
        else:
            return False


def add_user(username, password, edek, iv, salt):
    '''Add a new user with a hashed password to the database.'''
    #user_id = str(uuid.uuid4())
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    encrypted_otp = encrypt_data(pyotp.random_base32())
    #id=user_id,
    new_user = User(username=username,
                    password_hash=hashed_password,
                    otp_2fa_enc=encrypted_otp,
                    initial_setup=True,
                    edek=edek,
                    iv=iv,
                    salt=salt)
    
    session = Session()
    try:
        session.add(new_user)
        session.commit()
        return True
    except IntegrityError:
        session.rollback()
        logger.error(f'Failed to add user {username}, possibly due to a duplicate username.')
        return False
    finally:
        session.close()  # Use remove() instead of close() when using scoped_session
        
def retrieve_edek(username):
    '''Check if a user exists and return User details'''
    session = Session()
    user = session.query(User).filter_by(username=username).first()
    if user:
        session.close()
        return user
    session.close()
    return None
    

def authenticate_user(username, hashed_password):
    '''Check if a user exists and the password is correct.'''
    session = Session()
    user = session.query(User).filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, hashed_password):
    # if user and user.password_hash == hashed_password:
        logger.info('passwords match')
    # if user and user.password_hash == hashed_password:
        session.close()
        return user
    session.close()
    return False

def update_user_password(username, current_password, new_password, edek, iv, salt, temporary_dek):
    '''Update the specified user's password.'''
    session = Session()
    try:
        # Fetch the user by username
        user = session.query(User).filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, current_password):
            # Update password hash
            new_password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
            user.password_hash = new_password_hash
            user.edek = edek
            user.iv = iv
            user.salt = salt
            user.change_user_pass = True
            user.temporary_dek = temporary_dek
            session.commit()
            logger.info(f'User successfully changed password for username: {username}')
            return True
        elif user:
            logger.warning(f'Attempt to change password failed due to incorrect current password: {username}')
            return False  # Indicates incorrect current password
        else:
            logger.warning(f'Attempt to change password for non-existent user: {username}')
            return False  # Indicates user does not exist
    except IntegrityError as e:
        session.rollback()
        logger.error(f'Error updating password for {username}')
        return False
    finally:
        session.close()
        
def encrypt_data(data, encoder=True):
    '''
    Encrypts notes and passwords for the password manager.

    This function applies an additional layer of encryption using Fernet
    on top of the SQLCipher database encryption. The encrypted data is stored
    in the SQLCipher-encrypted database, effectively double-encrypting it.
    '''
    if encoder:
        data = data.encode()
    return current_app.config['CIPHER_SUITE'].encrypt(data)

def decrypt_data(encrypted_data, decoder=True):
    '''
    Decrypts passwords and notes for the password manager.

    This function decrypts data that was previously encrypted with Fernet,
    which is stored in a SQLCipher-encrypted database. This means the data
    is decrypted by Fernet first, then automatically decrypted by SQLCipher
    as it's read from the database, reversing the double encryption process.
    '''
    data = current_app.config['CIPHER_SUITE'].decrypt(encrypted_data)
    if decoder:
        data = data.decode()
    return data

##### Handling Dek Encryption and Decryption #####


def encrypt_data_dek(data, dek):
    # Decode the DEK from Base64
    aesgcm = AESGCM(dek)
    # For AESGCM, an IV should be 12 bytes long and unique for each encryption
    iv = os.urandom(12)
    # Encrypt the data. AESGCM requires bytes, so ensure `data` is bytes
    encrypted_data = aesgcm.encrypt(iv, data.encode(), None)
    # Return the IV and encrypted data, both encoded in Base64 for storage or transmission
    return base64.b64encode(iv), base64.b64encode(encrypted_data)

def decrypt_data_dek(encrypted_data_b64, iv_b64, dek):
    try:
        # Decode the IV, encrypted data, and DEK from Base64
        iv = base64.b64decode(iv_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)
        # dek = base64.b64decode(dek_b64)
        aesgcm = AESGCM(dek)
        # Decrypt the data
        data = aesgcm.decrypt(iv, encrypted_data, None)
        # Return the decrypted data as a string
        return data.decode()
    except Exception as e:
        logger.error(f'Error handling data decryption using dek')
        return False



def validate_hashed_password(hashed_password):
    """Validate the hashed password received from the client.
    
    Args:
        hashed_password (str): The hashed password to validate.
    
    Returns:
        bool: True if the hashed password is valid, False otherwise.
    """
    # Define the regex pattern for a valid SHA-256 hash
    pattern = re.compile('^[a-f0-9]{64}$')
    
    # Check if the hashed password matches the pattern
    if pattern.match(hashed_password):
        return True
    else:
        return False

def ensure_old_dek_remains(temporary_dek, user_id):
    with Session() as db_session:
        try:
            user = db_session.query(User).filter_by(id=user_id).first()
            user.change_user_pass = True
            user.temporary_dek = temporary_dek
            db_session.commit()
        except SQLAlchemyError as e:
            logger.error('Unable to store old dek in database')
        
    
def encrypt_with_new_dek(old_dek, new_dek, user_id):
    with Session() as db_session:
        try:
            data = db_session.query(Password).filter_by(user_id=user_id).all()

            for row in data:
                row.Name = decrypt_data_dek(row.Name, row.ivName, old_dek)
                row.Username = decrypt_data_dek(row.Username, row.ivUsername, old_dek)
                row.Password = decrypt_data_dek(row.Password, row.ivPassword, old_dek)
                row.Category = decrypt_data_dek(row.Category, row.ivCategory, old_dek)
                row.Notes = decrypt_data_dek(row.Notes, row.ivNotes, old_dek)

                row.ivName, row.Name = encrypt_data_dek(row.Name, new_dek)
                row.ivUsername, row.Username = encrypt_data_dek(row.Username, new_dek)
                row.ivPassword, row.Password = encrypt_data_dek(row.Password, new_dek)
                row.ivCategory, row.Category = encrypt_data_dek(row.Category, new_dek)
                row.ivNotes, row.Notes = encrypt_data_dek(row.Notes, new_dek)
            
            user = db_session.query(User).filter_by(id=user_id).first()
            user.change_user_pass = False
            user.temporary_dek = b''
            db_session.commit()
            return True
        except SQLAlchemyError as e:
            logger.error(f'Database Error\n{e}')
        except Exception as e:
            logger.error(f'Unknown Error Occured\n{e}')
    
    return False


class RedisComms:
    '''
    RedisComms
    ----------
    Get and Send to Redis using TLS communication.
    '''
    def __init__(self):
        # Path to your certificate files
        ca_cert = os.environ.get('SSL_CA')
        client_cert = os.environ.get('SSL_CERT')
        client_key = os.environ.get('SSL_KEY')
        password = os.environ.get('REDIS_PASSWORD')

        try:
            # Create a Redis connection with TLS
            self.redis_client = redis.Redis(
                host='redis-dek',
                port=6379,
                password=password,
                ssl=True,
                ssl_ca_certs=ca_cert,
                ssl_certfile=client_cert,
                ssl_keyfile=client_key,
                decode_responses=True
            )

            # Test the connection
            self.redis_client.ping()
            logger.info("Connected to Redis with TLS successfully.")

        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis")
        
    def get_dek(self, user_id):
        try:
            enc_dek = self.redis_client.get(f"user:{user_id}:dek")
            dek = decrypt_data(enc_dek, decoder=False) # It's ok to be b64 encoded. Password manager will decode
            dek = base64.b64decode(dek)
            if dek:
                return dek
            else:
                logger.warning("DEK not found.")
                return None
        except Exception as e:
            logger.error(f"Error retrieving DEK")
            return None

    def send_dek(self, user_id, dek):
        try:
            b64_dek = base64.b64encode(dek)
            enc_dek = encrypt_data(b64_dek, encoder=False)
            self.redis_client.set(f"user:{user_id}:dek", enc_dek, ex=1800)  # Expires in 30mins
            logger.info("DEK sent successfully.")
        except Exception as e:
            logger.error(f"Error sending DEK {e}")

    def get_secret(self, user_id):
        try:
            enc_shared_secret = self.redis_client.get(f"user:{user_id}:sharedSecret")
            decrypted_Secret = decrypt_data(enc_shared_secret, decoder=False)
            shared_secret = base64.b64decode(decrypted_Secret)
            if shared_secret:
                return shared_secret
            else:
                logger.warning("SharedSecret not found.")
                return None
        except Exception as e:
            logger.error(f"Error retrieving Shared_secret")
            return None

    def send_secret(self, user_id, shared_secret):
        try:
            b64_secret = base64.b64encode(shared_secret)
            enc_secret = encrypt_data(b64_secret, encoder=False)
            self.redis_client.set(f"user:{user_id}:sharedSecret", enc_secret, ex=1800)  # Expires in 30mins
            logger.info("Shared Secret sent successfully.")
        except Exception as e:
            logger.error(f"Error sending Shared Secret")

    def get_salt(self, user_id):
        try:
            enc_salt = self.redis_client.get(f"user:{user_id}:salt")
            salt = base64.b64decode(decrypt_data(enc_salt, decoder=False))
            salt = base64.b64decode(salt.decode())
            if salt:
                return salt
            else:
                logger.warning("salt not found.")
                return None
        except Exception as e:
            logger.error(f"Error retrieving salt")
            return None
        
    def send_salt(self, user_id, salt):
        try:
            
            b64_salt = base64.b64encode(salt.encode())
            enc_salt = encrypt_data(b64_salt, encoder=False)
            self.redis_client.set(f"user:{user_id}:salt", enc_salt, ex=1800)  # Expires in 30mins
            logger.info("Salt sent successfully.")
        except Exception as e:
            logger.error(f"Error sending Salt")

    def delete_secret(self, user_id):
        self.redis_client.delete(f"user:{user_id}:sharedSecret")

    def delete_salt(self, user_id):
        self.redis_client.delete(f"user:{user_id}:salt")

    def delete_dek(self, user_id):
        self.redis_client.delete(f"user:{user_id}:dek")

    def extend_dek_ttl(self, user_id):
        try:
            # Check if the DEK exists before extending the TTL
            if self.redis_client.exists(f"user:{user_id}:dek"):
                self.redis_client.expire(f"user:{user_id}:dek", 1800)  # Reset TTL to 30 mins
                logger.info("DEK TTL extended.")
            else:
                logger.warning("DEK does not exist, no TTL to extend.")
        except Exception as e:
            logger.error(f"Error extending DEK TTL")
