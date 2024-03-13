from . import main
from app.utils.db_utils import *
from app.utils.pylockr_logging import *
from flask import current_app, render_template, request, redirect, url_for, session, flash, send_file, make_response, g, after_this_request, abort, jsonify
from datetime import timedelta, datetime
from html_sanitizer import Sanitizer
from flask.views import MethodView
import re, os, csv, py7zr, time, io, csv, secrets
from flask_limiter.util import get_remote_address
from threading import Thread
from sqlalchemy.exc import SQLAlchemyError


sanitizer = Sanitizer()  # Used for name and username
logger = PyLockrLogs(name='PyLockr_Main')

class BaseAuthenticatedView(MethodView):
    '''
    if user_id is not in session, redirect to home/login page
    '''
    def dispatch_request(self, *args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('main.home'))
        return super(BaseAuthenticatedView, self).dispatch_request(*args, **kwargs)

class UploadCSV(BaseAuthenticatedView):
    """
    Class to handle CSV file uploads and update the database.
    Supports CSV files from Chrome, Brave, and Vaultwarden initially.
    """

    def get(self):
        flash('Please select a file to upload', 'alert alert-error')
        return redirect(url_for('main.dashboard'))

    def post(self):
        submitted_token = request.form.get('csrf_token')
        
        if not submitted_token or submitted_token != session.get('csrf_token'):
            flash('CSRF token is invalid.', 'alert alert-error')
            return redirect(url_for('dashboard'))
        
        file = request.files.get('csvFile')
        if not file or file.filename == '':
            flash('No file selected', 'alert alert-error')
            return redirect(request.url)
        
        if not self.is_valid_file(file.filename):
            flash('Invalid file type, please upload a CSV file.', 'alert alert-error')
            return redirect(request.url)
        
        try:
            self.process_file(file)
            flash('CSV File successfully uploaded', 'alert alert-ok')
        except Exception as e:
            flash(f'Error processing the file: {e}', 'alert alert-error')

        return redirect(url_for('main.dashboard'))

    @staticmethod
    def is_valid_file(filename):
        return filename.endswith('.csv')

    def process_file(self, file):
        #file_stream = io.StringIO(file.read().decode('utf-8'))
        file_stream = io.StringIO(file.read().decode('utf-8'), newline=None)
        csv_reader = csv.reader(file_stream)
        db_session = Session()
        row_index_dict = {}
        try:
            headers = next(csv_reader)
            row_index_dict = self.check_indexes(headers)
            for row in csv_reader:
                self.insert_password_row(db_session, row, row_index_dict)
            db_session.commit()
        except csv.Error as e:
            db_session.rollback()
            raise e
        finally:
            db_session.close()

    @staticmethod
    def check_indexes(row: list):
        row_dict = {'name': -1, 'username': -1, 'password': -1, 'category': -1, 'notes': -1}
        # Define patterns for matching headers here as before
        # the name regex =
        #   Does not match user before name, but account name is allowed, or name or url are allowed.
        patterns = {
            'name': re.compile(r'((?<!user\s)((account\s+)?\bname\b)|\burl\b)', re.IGNORECASE),
            'username': re.compile(r'user\s*name', re.IGNORECASE),
            'password': re.compile(r'password', re.IGNORECASE),
            'category': re.compile(r'\bfolder\b|\bcategory\b', re.IGNORECASE),
            'notes': re.compile(r'notes', re.IGNORECASE),
        }
        for num, item in enumerate(row):
            for key, pattern in patterns.items():
                if re.search(pattern, item):
                    row_dict[key] = num
                    break
        return row_dict

    def insert_password_row(self, db_session, row, row_index_dict):
        password_entry = Password(
            user_id=session['user_id'],
            name=sanitizer.sanitize(row[row_index_dict['name']]) if row_index_dict['name'] != -1 else '',
            username=sanitizer.sanitize(row[row_index_dict['username']]) if row_index_dict['username'] != -1 else '',
            encrypted_password=encrypt_data(row[row_index_dict['password']]) if row_index_dict['password'] != -1 else encrypt_data(''),
            category=sanitizer.sanitize(row[row_index_dict.get('category')]) if row_index_dict.get('category') != -1 else '',
            notes=encrypt_data(row[row_index_dict['notes']]) if row_index_dict['notes'] != -1 else encrypt_data('')
        )
        db_session.add(password_entry)

main.add_url_rule('/upload_csv', view_func=UploadCSV.as_view('upload_csv'))

class Home(MethodView):
    def get(self):
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        # Render the template as usual
        content = render_template('login.html', csrf_token=csrf_token)
        # Create a response object from the rendered template
        response = make_response(content)
        return response

main.add_url_rule('/', view_func=Home.as_view('home'))

class Dashboard(BaseAuthenticatedView):
    def get(self):
        '''
        Dashboard route. Redirects and logs you out if session times out.
        Queries database to retrieve the last time the database was downloaded/backed up.
        '''
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        # Query the database to retrieve the last backup date
        try:
            last_backup = Session.query(func.max(BackupHistory.backup_date)).scalar()
        finally:
            Session.close()
        # Check if the last backup was more than a month ago
        reminder_needed = False
        if last_backup:
            # Assuming last_backup is already a datetime object; adjust as needed
            # last_backup_date = datetime.strptime(last_backup, '%Y-%m-%d %H:%M:%S')
            if datetime.now() - last_backup > timedelta(days=30):
                reminder_needed = True

        return render_template('dashboard.html', reminder_needed=reminder_needed, last_backup=last_backup, csrf_token=csrf_token)

main.add_url_rule('/dashboard', view_func=Dashboard.as_view('dashboard'))

class AddPassword(BaseAuthenticatedView):
    '''
    Add a new entry into the database.

    Username and Name Entries are sanaitized, to avoid sql injection
    '''
    def get(self):
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        return render_template('add_password.html', nonce=g.nonce, csrf_token=csrf_token)
    def post(self):
        
        submitted_token = request.form.get('csrf_token')
        
        if not submitted_token or submitted_token != session.get('csrf_token'):
            flash('CSRF token is invalid.', 'alert alert-error')
            return redirect(url_for('add_password'))
        
        name = sanitizer.sanitize(request.form['name'])
        username = sanitizer.sanitize(request.form['username'])
        encrypted_password = encrypt_data(request.form['password'])
        category = sanitizer.sanitize(request.form['category'])
        encrypted_notes = encrypt_data(request.form['notes'])

        # Define maximum lengths
        max_length_name = 50
        max_length_username = 50
        max_length_category = 50
        max_length_notes = 4096

        # Validate lengths
        if len(name) > max_length_name or len(username) > max_length_username or len(request.form['notes']) > max_length_notes or len(category) > max_length_category:
            # Handle error: return an error message or redirect
            flash('Error: Input data too long', 'alert alert-error')
            return redirect(url_for('main.add_password'))

        # Add new password entry
        new_password_entry = Password(
            user_id=session['user_id'],  # Ensure this is set correctly in your session
            name=name,
            username=username,
            encrypted_password=encrypted_password,
            category=category,
            notes=encrypted_notes
        )
        
        db_session = Session()
        try:
            db_session.add(new_password_entry)
            db_session.commit()
            flash('Password added successfully!', 'alert alert-ok')
        except Exception as e:
            db_session.rollback()
            flash('Failed to add password.', 'alert alert-error')
            print(f"Error adding password: {e}")  # Log or handle the error as needed
        finally:
            db_session.close()

        return redirect(url_for('main.dashboard'))  # Adjust the redirect as needed

main.add_url_rule('/add_password', view_func=AddPassword.as_view('add_password'))

class RetrievePasswords(BaseAuthenticatedView):
    def get(self):
        '''
        Retrieve passwords route for the password manager table, which uses jQuery DataTables to sort entries.
        Passwords are masked in the DataTables view.
        '''
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token

        db_session = Session()
        # Retrieve all entries for the logged-in user, excluding the actual password for security
        try:
            password_entries = db_session.query(Password.id, Password.name, Password.username, Password.category).filter_by(user_id=session['user_id']).all()
        finally:
            db_session.close()
        # Prepare data for display, mask the password
        vault_data = [
            (entry.id, entry.name, entry.username, entry.category)  # Mask the password
            for entry in password_entries
        ]

        return render_template('retrieve_passwords.html', passwords=vault_data, nonce=g.nonce, csrf_token=csrf_token)
    
main.add_url_rule('/retrieve_passwords', view_func=RetrievePasswords.as_view('retrieve_passwords'))


class DeletePassword(BaseAuthenticatedView):
    def post(self, password_id):
        '''
        Delete individual passwords.
        '''
        submitted_token = request.form.get('csrf_token')
        
        if not submitted_token or submitted_token != session.get('csrf_token'):
            flash('CSRF token is invalid.', 'alert alert-error')
            return redirect(url_for('retrieve_passwords'))
        db_session = Session()
        try:
            # Fetch the password entry to be deleted
            password_entry = db_session.query(Password).filter_by(id=password_id, user_id=session['user_id']).first()
            if password_entry:
                db_session.delete(password_entry)
                db_session.commit()
                flash('Password entry deleted successfully.', 'alert alert-ok')
            else:
                flash('Password entry not found or not authorized to delete.', 'alert alert-error')
        except Exception as e:
            db_session.rollback()
            flash('Failed to delete password entry.', 'alert alert-error')
            logger.error(f"Error deleting password: {e}")
        finally:
            db_session.close()

        current_ip = get_remote_address()
        logger.info(f'User successfully deleted password from IP: {current_ip}')

        return redirect(url_for('main.retrieve_passwords'))

main.add_url_rule('/delete_password/<int:password_id>', view_func=DeletePassword.as_view('delete_password'))

class DeleteMultiplePasswords(BaseAuthenticatedView):
    def post(self):
        '''
        Multi Select password entries for deletion
        '''
        submitted_token = request.form.get('csrf_token')
        
        if not submitted_token or submitted_token != session.get('csrf_token'):
            flash('CSRF token is invalid.', 'alert alert-error')
            return redirect(url_for('retrieve_passwords'))
        
        db_session = Session()
        # Get the list of selected password IDs
        selected_passwords = request.form.getlist('selected_passwords')

        try:
            # Use filter() to handle deletion in a single query for efficiency
            # Convert selected_passwords to a list of integers if they're not already
            selected_password_ids = [int(pid) for pid in selected_passwords]
            # Delete all selected password entries belonging to the user in one go
            db_session.query(Password).filter(Password.id.in_(selected_password_ids), Password.user_id == session['user_id']).delete(synchronize_session=False)
            db_session.commit()
        except SQLAlchemyError as e:  # Catch more specific database errors
            db_session.rollback()
            flash('Failed to delete selected password entries.', 'alert alert-error')
            logger.error(f"Error deleting selected passwords: {e}")
        finally:
            db_session.close()

        current_ip = get_remote_address()
        logger.info(f'user successfully deleted {len(selected_passwords)} passwords: IP {current_ip}')
        flash(f'Deleted {len(selected_passwords)} passwords.', 'alert alert-ok')

        return redirect(url_for('main.retrieve_passwords'))

main.add_url_rule('/delete_multiple_passwords', view_func=DeleteMultiplePasswords.as_view('delete_multiple_passwords'))


class EditPassword(BaseAuthenticatedView):
    def get(self, password_id):
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token

        # Fetch the password entry to be edited
        password_entry = Session.query(Password).filter_by(id=password_id, user_id=session['user_id']).first()
        
        if password_entry:
            decrypted_password = decrypt_data(password_entry.encrypted_password)
            decrypted_notes = decrypt_data(password_entry.notes)
            return render_template('edit_password.html', name=password_entry.name, username=password_entry.username, password=decrypted_password,
                                   notes=decrypted_notes, category=password_entry.category, nonce=g.nonce, csrf_token=csrf_token) # password_data=password_entry, don't think i need this.
        else:
            flash('Password not found or access denied', 'alert alert-error')
            return redirect(url_for('main.retrieve_passwords'))

    def post(self, password_id):
        submitted_token = request.form.get('csrf_token')
        
        if not submitted_token or submitted_token != session.get('csrf_token'):
            flash('CSRF token is invalid.', 'alert alert-error')
            return redirect(url_for('edit_password'))
        
        name = sanitizer.sanitize(request.form['name'])
        username = sanitizer.sanitize(request.form['username'])
        encrypted_password = encrypt_data(request.form['password'])
        category = sanitizer.sanitize(request.form['category'])
        encrypted_notes = encrypt_data(request.form['notes'])

        # Define maximum lengths
        max_length_name = 50
        max_length_username = 50
        max_length_category = 50
        max_length_notes = 4096

        if len(name) > max_length_name or len(username) > max_length_username or len(request.form['notes']) > max_length_notes or len(category) > max_length_category:
            flash("Error: Input data too long.", "alert alert-error")
            return redirect(url_for('main.edit_password', password_id=password_id))

        try:
            password_entry = Session.query(Password).filter_by(id=password_id, user_id=session['user_id']).first()
            if password_entry:
                password_entry.name = name
                password_entry.username = username
                password_entry.encrypted_password = encrypted_password
                password_entry.category = category
                password_entry.notes = encrypted_notes
                Session.commit()
                flash('Password entry updated successfully.', 'alert alert-ok')
            else:
                flash('Password entry not found.', 'alert alert-error')
        except IntegrityError as e:
            Session.rollback()
            flash('Failed to update password entry.', 'alert alert-error')
            current_app.logger.error(f"Error updating password: {e}")
        finally:
            Session.remove()
        
        return redirect(url_for('main.retrieve_passwords'))

# Register the view
main.add_url_rule('/edit_password/<int:password_id>', view_func=EditPassword.as_view('edit_password'))

class DecryptPassword(BaseAuthenticatedView):
    def post(self, password_id):
        '''
        Decrypt the passwords from database, this is used for copy to clipboard button
        '''
        submitted_token = request.headers.get('csrf_token')
        if not submitted_token or submitted_token != session.get('csrf_token'):
            flash('CSRF token is invalid.', 'alert alert-error')
            return jsonify({'error': 'CSRF token is invalid.'}), 403
        
        try:
            password_entry = Session.query(Password).filter_by(id=password_id, user_id=session['user_id']).first()
        finally:
            Session.close()
        if password_entry and password_entry.encrypted_password:
            # Decrypt the password
            decrypted_password = decrypt_data(password_entry.encrypted_password)
            return jsonify({'password': decrypted_password}) # Send the decrypted password back
        else:
            current_ip = get_remote_address()
            logger.error(f'Issue encountered with user trying to use copy to clipboard: IP {current_ip}')
            abort(403)  # Use Flask's abort for HTTP error codes
    
main.add_url_rule('/decrypt_password/<int:password_id>', view_func=DecryptPassword.as_view('decrypt_password'))

class Backup(BaseAuthenticatedView):
    '''
    Downloads a copy of the database locally, using data and time for name
    '''
    methods = ['GET', 'POST']
    def get(self):
        # Generate a CSRF token
        csrf_token = secrets.token_hex(16)
        session['csrf_token'] = csrf_token
        return render_template('backup.html', nonce=g.nonce, csrf_token=csrf_token)
    
    def post(self):    
        submitted_token = request.form.get('csrf_token')
        
        if not submitted_token or submitted_token != session.get('csrf_token'):
            flash('CSRF token is invalid.', 'alert alert-error')
            return redirect(url_for('dashboard'))
        
        password = request.form.get('backupPassword')
        if not password:
            flash('Password is required for backup.', 'alert alert-error')
            return redirect(url_for('backup'))

        user_id = session['user_id']  # Ensure flask_session is imported correctly
        try:
            password_entries = Session.query(Password).filter_by(user_id=user_id).all()
            # Insert a record into backup_history
            # Prepare decrypted data for CSV
            decrypted_data = [[entry.name, entry.username, decrypt_data(entry.encrypted_password), entry.category, decrypt_data(entry.notes)] for entry in password_entries]
            new_backup_history = BackupHistory()
            Session.add(new_backup_history)
            Session.commit()
        finally:
            Session.close()


        # Save the decrypted data to a CSV file
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
        file_path = f'/tmp/passwords.csv'
        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['name', 'username', 'password', 'category', 'notes'])
            writer.writerows(decrypted_data)

        archive_path =f'/tmp/PyLockr_bk_{timestamp}.7z'

        # Create the 7z archive and add the CSV file
        with py7zr.SevenZipFile(archive_path, mode='w', password=password) as archive:
            archive.write(file_path, os.path.basename(file_path))

        self.secure_delete(file_path)

        @after_this_request
        def cleanup(response):
            def delayed_cleanup():
                time.sleep(30)  # Wait for 60 seconds before deleting
                self.secure_delete(archive_path)
                logger.info("Backup file removed successfully.")
            Thread(target=delayed_cleanup).start()

            return response

        current_ip = get_remote_address()
        logger.info(f'Successful backup download initiated for IP {current_ip}')
        return send_file(archive_path, as_attachment=True, download_name=os.path.basename(archive_path))  

    @staticmethod
    def secure_delete(file_path, passes=3):
        """Securely delete a file using a specified number of overwrite passes."""
        if os.path.exists(file_path):
            with open(file_path, "ba+") as file:
                length = file.tell()
            for _ in range(passes):
                with open(file_path, "br+") as file:
                    file.write(os.urandom(length))
            os.remove(file_path)

main.add_url_rule('/backup', view_func=Backup.as_view('backup'))
