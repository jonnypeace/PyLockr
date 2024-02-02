from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, send_file, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
from pysqlcipher3 import dbapi2 as sqlite
import init_db, os, re
from datetime import timedelta, datetime
from html_sanitizer import Sanitizer # type: ignore

sanitizer = Sanitizer()  # default configuration

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

@app.route('/backup')
def backup():
    # Retrieve the secure passphrase
    secure_key = get_secure_key()
    
    # Connect to the encrypted database (SQLCipher) using the secure key
    conn = get_db_connection(secure_key)
    c = conn.cursor()
    c.execute('INSERT INTO backup_history (backup_date) VALUES (CURRENT_TIMESTAMP)')
    conn.commit()
    conn.close()

    file_path = Path('users.db')  # Ensure this path is correct and accessible
    attachment_filename = f'backup_jonnys_den_{datetime.now().isoformat(sep="_",timespec="minutes")}.db'

    return send_file(file_path, as_attachment=True, download_name=attachment_filename)

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
    
def encrypt_data(data):
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data.encode()).decode()
    
@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
def edit_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('home'))  # Not logged in, redirect to home

    secure_key = get_secure_key()
    conn = get_db_connection(secure_key)
    c = conn.cursor()

    if request.method == 'POST':
        # Update the password entry
        name = sanitizer.sanitize(request.form['name'])
        username = sanitizer.sanitize(request.form['username'])
        password = sanitizer.sanitize(request.form['password'])

        # Encrypt Notes. Can use the password encryption because it does the same thing
        encrypted_notes = encrypt_data(sanitizer.sanitize(request.form['notes']))

        # Define maximum lengths
        max_length_name = 50
        max_length_username = 50
        max_length_notes = 4096

        # Validate lengths
        if len(name) > max_length_name or len(username) > max_length_username or len(request.form['notes']) > max_length_notes:
            # Handle error: return an error message or redirect
            return "Error: Input data too long.", 400

        c.execute('UPDATE passwords SET name = ?, username = ?, encrypted_password = ?, notes = ? WHERE id = ? AND user_id = ?', 
                  (name, username, encrypt_password(password), encrypted_notes, password_id, session['user_id']))
        conn.commit()
        conn.close()
        return redirect(url_for('retrieve_passwords'))

    # For a GET request, retrieve the current password details for the form
    c.execute('SELECT name, username, encrypted_password, notes FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
    # c.execute('SELECT id, name, username FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
    password_data = c.fetchone()
    conn.close()
    # print(password_data)
    if password_data:
        decrypted_password = cipher_suite.decrypt(password_data[2]).decode()
        decrypted_notes = decrypt_data(password_data[3])
        return render_template('edit_password.html', password_data=password_data, name=password_data[0],
                                   username=password_data[1], password=decrypted_password, notes=decrypted_notes)
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
        name = sanitizer.sanitize(request.form['name'])
        username = sanitizer.sanitize(request.form['username'])
        password = sanitizer.sanitize(request.form['password'])
        # Define maximum lengths
        max_length_name = 50
        max_length_username = 50
        max_length_notes = 4096

        # Validate lengths
        if len(name) > max_length_name or len(username) > max_length_username or len(request.form['notes']) > max_length_notes:
            # Handle error: return an error message or redirect
            return "Error: Input data too long.", 400

        encrypted_notes = encrypt_data(sanitizer.sanitize(request.form['notes']))
        # Retrieve the secure passphrase
        secure_key = get_secure_key()
        
        # Connect to the encrypted database (SQLCipher) using the secure key
        conn = get_db_connection(secure_key)
        c = conn.cursor()
        
        # Insert new password into the passwords table
        c.execute('INSERT INTO passwords (user_id, name, username, encrypted_password, notes) VALUES (?, ?, ?, ?, ?)', 
                (session['user_id'], name, username, encrypt_password(password), encrypted_notes))

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
    # Retrieve the secure passphrase
    secure_key = get_secure_key()
    
    # Connect to the encrypted database (SQLCipher) using the secure key
    conn = get_db_connection(secure_key)
    c = conn.cursor()
    c.execute('SELECT MAX(backup_date) FROM backup_history')
    last_backup = c.fetchone()[0]
    conn.close()

    # Check if the last backup was more than a month ago
    reminder_needed = False
    if last_backup:
        last_backup_date = datetime.strptime(last_backup, '%Y-%m-%d %H:%M:%S')
        if datetime.now() - last_backup_date > timedelta(days=30):
            reminder_needed = True

    return render_template('dashboard.html', reminder_needed=reminder_needed, last_backup=last_backup)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('signup'))

        MIN_PASSWORD_LENGTH = 12

        uppercase_characters = len(re.findall(r"[A-Z]", password))
        lowercase_characters = len(re.findall(r"[a-z]", password))
        numerical_characters = len(re.findall(r"[0-9]", password))
        special_characters = len(re.findall(r"[!@#$%^&*()-_+<>?]", password))
        
        if len(password) < MIN_PASSWORD_LENGTH or not all([uppercase_characters,lowercase_characters,numerical_characters,special_characters]):
            flash('Password must be at least 12 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.', 'error')
            return redirect(url_for('signup'))
        
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
    # Render the template as usual
    content = render_template('login.html')

    # Create a response object from the rendered template
    response = make_response(content)

    # Define your CSP policy
    csp_policy = (
        "default-src 'self';"
        "script-src 'self' https://code.jquery.com https://cdn.datatables.net;"
        "object-src 'none';"
        "style-src 'self' 'unsafe-inline';"
    )
    # Add the CSP policy to the response headers
    response.headers['Content-Security-Policy'] = csp_policy

    return response

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
