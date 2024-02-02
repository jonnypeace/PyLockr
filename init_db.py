from pysqlcipher3 import dbapi2 as sqlite
import os

def setup_db():
    conn = sqlite.connect('users.db')
    cursor = conn.cursor()

    passphrase = os.environ.get('SQLCIPHER_KEY')
    if not passphrase:
        raise ValueError("SQLCIPHER_KEY is not set in the environment variables.")
    
    cursor.execute(f"PRAGMA key = '{passphrase}'")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users
        ([id] INTEGER PRIMARY KEY, [username] TEXT, [password_hash] TEXT)
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords
        ([id] INTEGER PRIMARY KEY, [user_id] INTEGER, [name] TEXT, [username] TEXT, [encrypted_password] TEXT, [notes] TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id))
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS backup_history (
            id INTEGER PRIMARY KEY,
            backup_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        ''')

    conn.commit()
    conn.close()
