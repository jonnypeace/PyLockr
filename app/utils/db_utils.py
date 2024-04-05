#!/usr/bin/env python3

from app.utils.pylockr_logging import PyLockrLogs
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, TIMESTAMP, inspect, Boolean, LargeBinary, BLOB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql import func
from pathlib import Path
import os, uuid, logging, pyotp, base64
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import IntegrityError
from flask import current_app
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = PyLockrLogs(name='DB_UTILS')

logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING) # Set up for logging warning+ messages

Base = declarative_base()

# Initialize engine and session
DB_PATH = os.environ.get('DB_PATH')

if DB_PATH is None:
    raise ValueError('DB_PATH environment variable not set in .env')

engine = create_engine(DB_PATH, echo=True) # use echo=True for debugging
Session = scoped_session(sessionmaker(bind=engine, autoflush=False))

def init_db():
    inspector = inspect(engine)
    Base.metadata.create_all(engine,checkfirst=True)

class User(Base):
    __tablename__ = 'users'
    # id = Column(String(255), primary_key=True, unique=True, nullable=False)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    username = Column(String(256), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    otp_2fa_enc = Column(BLOB, nullable=False)
    initial_setup = Column(Boolean, nullable=False, default=True)
    edek = Column(String(256), nullable=False)
    iv = Column(String(24), nullable=False)
    passwords = relationship("Password", back_populates="user")
    backup_history = relationship("BackupHistory", back_populates="user")

class Password(Base):
    __tablename__ = 'passwords'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    # id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False)
    name = Column(String(256))
    username = Column(String(256))
    encrypted_password = Column(BLOB)
    iv_password = Column(LargeBinary)
    category = Column(String(256))
    notes = Column(String(4096))
    # iv_notes = Column(LargeBinary)
    user = relationship("User", back_populates="passwords")

class BackupHistory(Base):
    __tablename__ = 'backup_history'
    id = Column(Integer, primary_key=True)
    backup_date = Column(TIMESTAMP, default=func.current_timestamp())
    user_id = Column(String(256), ForeignKey('users.id'), nullable=False)
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


def add_user(username, hashed_password, edek, iv):
    '''Add a new user with a hashed password to the database.'''
    #user_id = str(uuid.uuid4())
    hashed_password = generate_password_hash(hashed_password, method='pbkdf2:sha256')
    encrypted_otp = encrypt_data(pyotp.random_base32())
    #id=user_id,
    new_user = User(username=username,
                    password_hash=hashed_password,
                    otp_2fa_enc=encrypted_otp,
                    initial_setup=True,
                    edek=edek,
                    iv=iv)
    
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

def update_user_password(username, current_password, new_password):
    '''Update the specified user's password.'''
    session = Session()
    try:
        # Fetch the user by username
        user = session.query(User).filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, current_password):
            # Update password hash
            new_password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
            user.password_hash = new_password_hash
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
        logger.error(f'Error updating password for {username}: {e}')
        return False
    finally:
        session.close()
        
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

##### Handling Dek Encryption and Decryption #####


def encrypt_data(data, dek_b64):
    # Decode the DEK from Base64
    dek = base64.b64decode(dek_b64)
    aesgcm = AESGCM(dek)
    # For AESGCM, an IV should be 12 bytes long and unique for each encryption
    iv = AESGCM.generate_iv(12)
    # Encrypt the data. AESGCM requires bytes, so ensure `data` is bytes
    encrypted_data = aesgcm.encrypt(iv, data.encode(), None)
    # Return the IV and encrypted data, both encoded in Base64 for storage or transmission
    return base64.b64encode(iv), base64.b64encode(encrypted_data)

def decrypt_data(encrypted_data_b64, iv_b64, dek_b64):
    # Decode the IV, encrypted data, and DEK from Base64
    iv = base64.b64decode(iv_b64)
    encrypted_data = base64.b64decode(encrypted_data_b64)
    dek = base64.b64decode(dek_b64)
    aesgcm = AESGCM(dek)
    # Decrypt the data
    data = aesgcm.decrypt(iv, encrypted_data, None)
    # Return the decrypted data as a string
    return data.decode()

# Encrypt data
iv_b64, encrypted_data_b64 = encrypt_data("Hello, world!", dek_b64)

# Decrypt data
decrypted_data = decrypt_data(encrypted_data_b64, iv_b64, dek_b64)
print(decrypted_data)  # Output: "Hello, world!"

