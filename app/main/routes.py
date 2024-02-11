from . import main
from app.utils.security import *
from app.utils.db_utils import *
from flask import Flask, current_app, render_template, request, redirect, url_for, session, flash, Response, send_file, make_response
from pathlib import Path
from datetime import timedelta, datetime
from html_sanitizer import Sanitizer # type: ignore

sanitizer = Sanitizer()  # default configuration

@main.route('/')
def home():
    '''
    Content security policy settings. Allows use of jquery datatables
    '''
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


@main.route('/dashboard')
def dashboard():
    '''
    Dashboard route. Redirects and logs you out if session times out.

    Queries database to retrieve the last time the database was downloaded/backed up.
    '''
    if 'username' not in session:
        return redirect(url_for('main.home'))  # Redirect to home if not logged in
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


@main.route('/add_password', methods=['GET', 'POST'])
def add_password():
    '''
    Add a new entry into the database.

    Entries are sanaitized, to avoid sql injection
    '''
    if 'username' not in session:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('main.home'))

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
                (session['user_id'], name, username, encrypt_data(password), encrypted_notes))

        conn.commit()
        conn.close()
        flash('Password added successfully!', 'success')

        return redirect(url_for('main.dashboard'))  # Redirect back to the dashboard
    
    # If it's a GET request, render the add_password.html template
    return render_template('add_password.html')

@main.route('/retrieve_passwords')
def retrieve_passwords():
    '''
    Retrieve passwords route is basically the password manager table which uses jquery datatables to sort entries.

    Datatables only see's masked out passwords.
    '''
    if 'user_id' not in session:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('main.home'))

    # Retrieve the secure passphrase
    secure_key = get_secure_key()
    
    # Connect to the encrypted database (SQLCipher) using the secure key
    conn = get_db_connection(secure_key)
    c = conn.cursor()
    
    # Retrieve all passwords for the logged-in user
    c.execute('SELECT id, name, username, encrypted_password FROM passwords WHERE user_id = ?', (session['user_id'],))
    passwords = c.fetchall()

    conn.close()

    # Decrypt passwords just-in-time for display
    for i in range(len(passwords)):
        passwords[i] = (
            passwords[i][0],
            passwords[i][1],
            passwords[i][2],
            '*******',  # Mask the actual password; it's decrypted when needed
        )

    return render_template('retrieve_passwords.html', passwords=passwords)

@main.route('/delete_password/<int:password_id>')
def delete_password(password_id):
    '''
    Delete individual passwords
    '''
    if 'user_id' not in session:
        return redirect(url_for('main.home'))  # Not logged in, redirect to home

    secure_key = get_secure_key()
    conn = get_db_connection(secure_key)
    c = conn.cursor()

    # Delete the password entry
    c.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
    conn.commit()
    conn.close()

    return redirect(url_for('main.retrieve_passwords'))

@main.route('/delete_multiple_passwords', methods=['POST'])
def delete_multiple_passwords():
    '''
    Multi Select password entries for deletion
    '''
    if 'user_id' not in session:
        return redirect(url_for('main.home'))  # Not logged in, redirect to home

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
    
    return redirect(url_for('main.retrieve_passwords'))

@main.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
def edit_password(password_id):
    '''
    Edit password. This doesn't use jquery, and will show passwords if unmasked, or you can generate new passwords.
    '''
    if 'user_id' not in session:
        return redirect(url_for('main.home'))  # Not logged in, redirect to home

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
                  (name, username, encrypt_data(password), encrypted_notes, password_id, session['user_id']))
        conn.commit()
        conn.close()
        return redirect(url_for('main.retrieve_passwords'))

    # For a GET request, retrieve the current password details for the form
    c.execute('SELECT name, username, encrypted_password, notes FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
    password_data = c.fetchone()
    conn.close()

    # Decrypt password and render password entry info
    if password_data:
        decrypted_password = current_app.config['CIPHER_SUITE'].decrypt(password_data[2]).decode()
        decrypted_notes = decrypt_data(password_data[3])
        return render_template('edit_password.html', password_data=password_data, name=password_data[0],
                                   username=password_data[1], password=decrypted_password, notes=decrypted_notes)
    else:
        return 'Password not found or access denied', 403
    
@main.route('/decrypt_password/<int:password_id>', methods=['GET'])
def decrypt_password(password_id):
    '''
    Decrypt the passwords from database
    '''
    if 'user_id' not in session:
        return redirect(url_for('main.home'))  # Not logged in, redirect to home
    
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
        decrypted_password = decrypt_data(encrypted_password[0])
        return decrypted_password  # Send the decrypted password back
    else:
        return 'Password not found or access denied', 403  # Or handle as appropriate
    
@main.route('/backup')
def backup():
    '''
    Downloads a copy of the database locally, using data and time for name
    '''
    # Retrieve the secure passphrase
    secure_key = get_secure_key()
    
    # Connect to the encrypted database (SQLCipher) using the secure key
    conn = get_db_connection(secure_key)
    c = conn.cursor()
    c.execute('INSERT INTO backup_history (backup_date) VALUES (CURRENT_TIMESTAMP)')
    conn.commit()
    conn.close()

    file_path = Path(current_app.config['DB_PATH'])  # Ensure this path is correct and accessible
    attachment_filename = f'backup_password_db_{datetime.now().isoformat(sep="_",timespec="minutes")}.db'

    return send_file(file_path, as_attachment=True, download_name=attachment_filename)
