from . import main
from app.utils.security import *
from app.utils.db_utils import *
from flask import Flask, current_app, render_template, request, redirect, url_for, session, flash, Response, send_file, make_response
from pathlib import Path
from datetime import timedelta, datetime
from html_sanitizer import Sanitizer
from flask.views import MethodView


sanitizer = Sanitizer()  # default configuration

class BaseAuthenticatedView(MethodView):
    '''
    if user_id is not in session, redirect to home/login page
    '''
    def dispatch_request(self, *args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('main.home'))
        return super(BaseAuthenticatedView, self).dispatch_request(*args, **kwargs)

class Home(MethodView):
    def get(self):
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

main.add_url_rule('/', view_func=Home.as_view('home'))

class Dashboard(BaseAuthenticatedView):
    def get(self):
        '''
        Dashboard route. Redirects and logs you out if session times out.

        Queries database to retrieve the last time the database was downloaded/backed up.
        '''
        # Retrieve the secure passphrase
        secure_key = get_secure_key()
        
        # Connect to the encrypted database (SQLCipher) using the secure key
        with get_db_connection(secure_key) as conn:
            c = conn.cursor()
            c.execute('SELECT MAX(backup_date) FROM backup_history')
            last_backup = c.fetchone()[0]

        # Check if the last backup was more than a month ago
        reminder_needed = False
        if last_backup:
            last_backup_date = datetime.strptime(last_backup, '%Y-%m-%d %H:%M:%S')
            if datetime.now() - last_backup_date > timedelta(days=30):
                reminder_needed = True

        return render_template('dashboard.html', reminder_needed=reminder_needed, last_backup=last_backup)

main.add_url_rule('/dashboard', view_func=Dashboard.as_view('dashboard'))

class AddPassword(BaseAuthenticatedView):
    '''
    Add a new entry into the database.

    Username and Name Entries are sanaitized, to avoid sql injection
    '''
    def get(self):
        # If it's a GET request, render the add_password.html template
        return render_template('add_password.html')
    def post(self):
        name = sanitizer.sanitize(request.form['name'])
        username = sanitizer.sanitize(request.form['username'])
        encrypted_password = encrypt_data(request.form['password'])
        encrypted_notes = encrypt_data(request.form['notes'])

        # Define maximum lengths
        max_length_name = 50
        max_length_username = 50
        max_length_notes = 4096

        # Validate lengths
        if len(name) > max_length_name or len(username) > max_length_username or len(request.form['notes']) > max_length_notes:
            # Handle error: return an error message or redirect
            return "Error: Input data too long.", 400

        # Retrieve the secure passphrase
        secure_key = get_secure_key()
    
        # Connect to the encrypted database (SQLCipher) using the secure key
        with get_db_connection(secure_key) as conn:
            c = conn.cursor()
        
            # Insert new password into the passwords table
            c.execute('INSERT INTO passwords (user_id, name, username, encrypted_password, notes) VALUES (?, ?, ?, ?, ?)', 
                    (session['user_id'], name, username,encrypted_password, encrypted_notes))

            conn.commit()
        flash('Password added successfully!', 'success')

        return redirect(url_for('main.dashboard'))  # Redirect back to the dashboard

main.add_url_rule('/add_password', view_func=AddPassword.as_view('add_password'))

class RetrievePasswords(BaseAuthenticatedView):
    def get(self):
        '''
        Retrieve passwords route is basically the password manager table which uses jquery datatables to sort entries.

        Datatables only see's masked out passwords.
        '''
        # Retrieve the secure passphrase
        secure_key = get_secure_key()
        
        # Connect to the encrypted database (SQLCipher) using the secure key
        with get_db_connection(secure_key) as conn:
            c = conn.cursor()
        
            # Retrieve all data from vault for the logged-in user
            c.execute('SELECT id, name, username, encrypted_password FROM passwords WHERE user_id = ?', (session['user_id'],))
            vault_data = c.fetchall()

        # Decrypted vault_data for display
        for i in range(len(vault_data)):
            vault_data[i] = (
                vault_data[i][0],
                vault_data[i][1],
                vault_data[i][2],
                '*******',  # Mask the actual password; it's decrypted when needed
            )

        return render_template('retrieve_passwords.html', passwords=vault_data)
    
main.add_url_rule('/retrieve_passwords', view_func=RetrievePasswords.as_view('retrieve_passwords'))

class DeletePassword(BaseAuthenticatedView):
    def get(self, password_id):
        '''
        Delete individual passwords
        '''
        secure_key = get_secure_key()
        # Connect to the encrypted database (SQLCipher) using the secure key
        with get_db_connection(secure_key) as conn:
            c = conn.cursor()
            # Delete the password entry
            c.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
            conn.commit()

        return redirect(url_for('main.retrieve_passwords'))
    
main.add_url_rule('/delete_password/<int:password_id>', view_func=DeletePassword.as_view('delete_password'))

class DeleteMultiplePasswords(BaseAuthenticatedView):
    def post(self):
        '''
        Multi Select password entries for deletion
        '''

        # Get the list of selected password IDs
        selected_passwords = request.form.getlist('selected_passwords')

        if selected_passwords:
            secure_key = get_secure_key()
            # Connect to the encrypted database (SQLCipher) using the secure key
            with get_db_connection(secure_key) as conn:
                c = conn.cursor()

                # Delete each selected password
                for password_id in selected_passwords:
                    c.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
                
                conn.commit()

            flash(f'Deleted {len(selected_passwords)} passwords.', 'success')
        
        return redirect(url_for('main.retrieve_passwords'))
main.add_url_rule('/delete_multiple_passwords', view_func=DeleteMultiplePasswords.as_view('delete_multiple_passwords'))

class EditPassword(BaseAuthenticatedView):
    def get(self, password_id):

        secure_key = get_secure_key()
        with get_db_connection(secure_key) as conn:
            c = conn.cursor()
            c.execute('SELECT name, username, encrypted_password, notes FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
            password_data = c.fetchone()

        if password_data:
            decrypted_password = current_app.config['CIPHER_SUITE'].decrypt(password_data[2]).decode()
            decrypted_notes = decrypt_data(password_data[3])
            return render_template('edit_password.html', password_data=password_data, name=password_data[0],
                                        username=password_data[1], password=decrypted_password, notes=decrypted_notes)
        else:
            return 'Password not found or access denied', 403

    def post(self, password_id):

        secure_key = get_secure_key()
        with get_db_connection(secure_key) as conn:
            c = conn.cursor()
            name = sanitizer.sanitize(request.form['name'])
            username = sanitizer.sanitize(request.form['username'])
            encrypted_password = encrypt_data(request.form['password'])
            encrypted_notes = encrypt_data(request.form['notes'])

            # Define maximum lengths
            max_length_name = 50
            max_length_username = 50
            max_length_notes = 4096

            if len(name) > max_length_name or len(username) > max_length_username or len(request.form['notes']) > max_length_notes:
                return "Error: Input data too long.", 400

            c.execute('UPDATE passwords SET name = ?, username = ?, encrypted_password = ?, notes = ? WHERE id = ? AND user_id = ?', 
                      (name, username, encrypted_password, encrypted_notes, password_id, session['user_id']))
            conn.commit()
        
        return redirect(url_for('main.retrieve_passwords'))

# Register the view
main.add_url_rule('/edit_password/<int:password_id>', view_func=EditPassword.as_view('edit_password'))

class DecryptPassword(BaseAuthenticatedView):
    def get(self, password_id):
        '''
        Decrypt the passwords from database
        '''
        
        # Retrieve the secure passphrase
        secure_key = get_secure_key()
        # Connect to the encrypted database (SQLCipher) using the secure key
        with get_db_connection(secure_key) as conn:
            c = conn.cursor()
        
            # Fetch the encrypted password for the given password ID
            c.execute('SELECT encrypted_password FROM passwords WHERE id = ? AND user_id = ?', (password_id, session['user_id']))
            encrypted_password = c.fetchone()

        if encrypted_password:
            # Decrypt the password
            decrypted_password = decrypt_data(encrypted_password[0])
            return decrypted_password  # Send the decrypted password back
        else:
            return 'Password not found or access denied', 403  # Or handle as appropriate
    
main.add_url_rule('/decrypt_password/<int:password_id>', view_func=DecryptPassword.as_view('decrypt_password'))
    
@main.route('/backup')
def backup():
    '''
    Downloads a copy of the database locally, using data and time for name
    '''
    # Retrieve the secure passphrase
    secure_key = get_secure_key()
    # Connect to the encrypted database (SQLCipher) using the secure key
    with get_db_connection(secure_key) as conn:
        c = conn.cursor()
        c.execute('INSERT INTO backup_history (backup_date) VALUES (CURRENT_TIMESTAMP)')
        conn.commit()

    file_path = Path(current_app.config['DB_PATH'])  # Ensure this path is correct and accessible
    attachment_filename = f'backup_password_db_{datetime.now().isoformat(sep="_",timespec="minutes")}.db'

    return send_file(file_path, as_attachment=True, download_name=attachment_filename)
