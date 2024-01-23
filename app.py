from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
from pysqlcipher3 import dbapi2 as sqlite
import init_db, os
from datetime import timedelta

app = Flask(__name__)

app.secret_key = os.environ.get('APP_SECRET_KEY')
if not app.secret_key:
    raise ValueError('No APP_SECRET_KEY found in environment variables. Please set it in your .bashrc file.')

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) 

from cryptography.fernet import Fernet

key = os.environ.get('FERNET_KEY')
if not key:
    raise ValueError("No FERNET key found in environment variables. Please set it in your .bashrc file.")

cipher_suite = Fernet(key)

@app.route('/logout', methods=['POST'])
def logout():
    # Clear the session
    session.clear()
    # Redirect to the login page
    return redirect(url_for('home'))

@app.route('/decrypt_password/<int:password_id>', methods=['GET'])
def decrypt_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('home'))  # Not logged in, redirect to home
    
    # Retrieve the secure passphrase
    secure_key = get_secure_key()
    
    # Connect to the encrypted database (SQLCipher) using the secure key
    conn = get_db_connection(secure_key)
    c = conn.cursor()
    
    # Fetch the encrypted password for the given password ID
    c.execute('SELECT encrypted_password FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
    encrypted_password = c.fetchone()

    conn.close()

    if encrypted_password:
        # Decrypt the password
        decrypted_password = cipher_suite.decrypt(encrypted_password[0]).decode()
        return decrypted_password  # Send the decrypted password back
    else:
        return 'Password not found or access denied', 403  # Or handle as appropriate
    
@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
def edit_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('home'))  # Not logged in, redirect to home

    secure_key = get_secure_key()
    conn = get_db_connection(secure_key)
    c = conn.cursor()

    if request.method == 'POST':
        # Update the password entry
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        c.execute('UPDATE passwords SET name = ?, username = ?, encrypted_password = ? WHERE id = ? AND user_id = ?', 
                  (name, username, encrypt_password(password), password_id, session['user_id']))
        conn.commit()
        conn.close()
        return redirect(url_for('retrieve_passwords'))

    # For a GET request, retrieve the current password details for the form
    c.execute('SELECT id, name, username FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
    password_data = c.fetchone()
    conn.close()

    if password_data:
        return render_template('edit_password.html', password_data=password_data)
    else:
        return 'Password not found or access denied', 403

@app.route('/delete_multiple_passwords', methods=['POST'])
def delete_multiple_passwords():
    if 'user_id' not in session:
        return redirect(url_for('home'))  # Not logged in, redirect to home

    # Get the list of selected password IDs
    selected_passwords = request.form.getlist('selected_passwords')

    if selected_passwords:
        secure_key = get_secure_key()
        conn = get_db_connection(secure_key)
        c = conn.cursor()

        # Delete each selected password
        for password_id in selected_passwords:
            c.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
        
        conn.commit()
        conn.close()

        flash(f'Deleted {len(selected_passwords)} passwords.', 'success')
    
    return redirect(url_for('retrieve_passwords'))


@app.route('/delete_password/<int:password_id>')
def delete_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('home'))  # Not logged in, redirect to home

    secure_key = get_secure_key()
    conn = get_db_connection(secure_key)
    c = conn.cursor()

    # Delete the password entry
    c.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
    conn.commit()
    conn.close()

    return redirect(url_for('retrieve_passwords'))

@app.route('/retrieve_passwords')
def retrieve_passwords():
    if 'user_id' not in session:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('home'))

    # Retrieve the secure passphrase
    secure_key = get_secure_key()
    
    # Connect to the encrypted database (SQLCipher) using the secure key
    conn = get_db_connection(secure_key)
    c = conn.cursor()
    
    c.execute("SELECT id, name, username, encrypted_password FROM passwords WHERE user_id = ?", 
                  (session['user_id'],))
    # Retrieve all passwords for the logged-in user
    # c.execute('SELECT id, name, username, encrypted_password FROM passwords WHERE user_id = ?', (session['user_id'],))
    passwords = c.fetchall()

    conn.close()

    # Decrypt passwords just-in-time for display
    for i in range(len(passwords)):
        passwords[i] = (
            passwords[i][0],
            passwords[i][1],
            passwords[i][2],
            # passwords[i][3]
            '*******',  # Mask the actual password; it's decrypted when needed
        )

    return render_template('retrieve_passwords.html', passwords=passwords)


def encrypt_password(password):
    return cipher_suite.encrypt(password.encode())


@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if 'username' not in session:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        
        # Retrieve the secure passphrase
        secure_key = get_secure_key()
        
        # Connect to the encrypted database (SQLCipher) using the secure key
        conn = get_db_connection(secure_key)
        c = conn.cursor()
        
        # Insert new password into the passwords table
        c.execute('INSERT INTO passwords (user_id, name, username, encrypted_password) VALUES (?, ?, ?, ?)', 
                (session['user_id'], name, username, encrypt_password(password)))

        conn.commit()
        conn.close()
        flash('Password added successfully!', 'success')

        return redirect(url_for('dashboard'))  # Redirect back to the dashboard
    
    # If it's a GET request, render the add_password.html template
    return render_template('add_password.html')

def get_secure_key():
    key = os.environ.get('SQLCIPHER_KEY')
    if not key:
        raise ValueError("SQLCIPHER_KEY is not set in the environment variables.")
    return key

def get_db_connection(passphrase):
    conn = sqlite.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA key = '{passphrase}'")
    return conn

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Retrieve the secure passphrase
    secure_key = get_secure_key()
    
    # Connect to the encrypted database (SQLCipher) using the secure key
    conn = get_db_connection(secure_key)
    c = conn.cursor()
    
    # Fetch the user by username
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        # User authenticated successfully
        session['user_id'] = user[0] 
        session['username'] = user[1]  # Log the user in by setting the session
        return redirect(url_for('dashboard'))  # Redirect to the dashboard page after successful login
    else:
        return 'Login failed. Check your login details.'


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('home'))  # Redirect to home if not logged in
    return render_template('dashboard.html')  # Render the dashboard page for logged-in users

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password for secure storage
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Retrieve the secure passphrase
        secure_key = get_secure_key()
        
        # Connect to the encrypted database (SQLCipher) using the secure key
        conn = get_db_connection(secure_key)
        c = conn.cursor()

        # Insert new user into the users table
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed_password))

        conn.commit()
        conn.close()

        return redirect(url_for('home'))  # Redirect to the login page after successful registration

    return render_template('signup.html')  # Render the sign-up page if method is GET

@app.route('/')
def home():
    return render_template('login.html')

# hashed_password = generate_password_hash('your_raw_password', method='sha256')
# # Store 'hashed_password' in the database, not the raw password

db_path = Path('./users.db')
print(f"Checking for DB at: {db_path.absolute()}")
if not db_path.exists():
    print("DB not found, setting up the database...")
    init_db.setup_db()
else:
    print("DB found. Not initializing.")

if __name__ == '__main__':
    app.run(debug=True)
