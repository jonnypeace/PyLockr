#!/usr/bin/env python3

from app.utils.pylockr_logging import PyLockrLogs
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, TIMESTAMP, inspect, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql import func
from pathlib import Path
import os, uuid, logging, pyotp
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import IntegrityError
from flask import current_app

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
    id = Column(String(255), primary_key=True, unique=True, nullable=False)
    username = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(300), nullable=False)
    otp_2fa_enc = Column(String(255), nullable=False)
    initial_setup = Column(Boolean, nullable=False, default=True)
    passwords = relationship("Password", back_populates="user")
    backup_history = relationship("BackupHistory", back_populates="user")

class Password(Base):
    __tablename__ = 'passwords'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(255), ForeignKey('users.id'), nullable=False)
    name = Column(String(255))
    username = Column(String(255))
    encrypted_password = Column(String(255))
    category = Column(String(255))
    notes = Column(String(4096))
    user = relationship("User", back_populates="passwords")

class BackupHistory(Base):
    __tablename__ = 'backup_history'
    id = Column(Integer, primary_key=True)
    backup_date = Column(TIMESTAMP, default=func.current_timestamp())
    user_id = Column(String(255), ForeignKey('users.id'), nullable=False)
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


def add_user(username, password):
    '''Add a new user with a hashed password to the database.'''
    user_id = str(uuid.uuid4())
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    encrypted_otp = encrypt_data(pyotp.random_base32())
    new_user = User(id=user_id,
                    username=username,
                    password_hash=hashed_password,
                    otp_2fa_enc=encrypted_otp,
                    initial_setup=True)
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

def authenticate_user(username, password):
    '''Check if a user exists and the password is correct.'''
    session = Session()
    user = session.query(User).filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        session.close()
        return user
    session.close()
    return None

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
