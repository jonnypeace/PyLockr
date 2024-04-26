from . import main
from app.utils.db_utils import *
from app.utils.pylockr_logging import *
from flask import current_app, render_template, request, redirect, url_for, session, flash, send_file, make_response, g, after_this_request, abort, jsonify
from datetime import timedelta, datetime
from html_sanitizer import Sanitizer
from flask.views import MethodView
import re, os, csv, py7zr, time, io, csv, secrets, base64, redis, binascii
from flask_limiter.util import get_remote_address
from threading import Thread
from sqlalchemy.exc import SQLAlchemyError
from app.utils.extensions import limiter
from app.utils.key_exchange import shared_secret_exchange, derive_aes_key_from_shared_secret, return_new_key_exchanged_edek

sanitizer = Sanitizer()  # Used for name and username
logger = PyLockrLogs(name='PyLockr_Main')

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

class BaseAuthenticatedView(MethodView):
    '''
    if user_id is not in session, redirect to home/login page
    '''
    redis_client = RedisComms()  # Initialize your Redis communication class
    decorators = [limiter.limit("7 per minute")]
    
    def dispatch_request(self, *args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('main.home'))
        
        # If user_id is in session, extend DEK TTL in Redis
        self.extend_dek_ttl(session['user_id'])
        return super(BaseAuthenticatedView, self).dispatch_request(*args, **kwargs)

    def extend_dek_ttl(self, user_id):
        '''
        Extend the TTL for the user's DEK in Redis.
        '''
        # This assumes your RedisComms class has a method to extend DEK TTL
        # Modify this method based on your RedisComms implementation
        try:
            self.redis_client.extend_dek_ttl(user_id)
        except Exception as e:
            print(f"Error extending DEK TTL for user {user_id}: {e}")
            # Handle the error as appropriate for your application

class UploadCSV(BaseAuthenticatedView):
    """
    Class to handle CSV file uploads and update the database.
    Supports CSV files from Chrome, Brave, and Vaultwarden initially.
    """

    def get(self):
        flash('Please select a file to upload', 'alert alert-error')
        return redirect(url_for('main.dashboard'))

    def post(self):

        file = request.files.get('csvFile')
        if not file or file.filename == '':
            flash('No file selected', 'alert alert-error')
            return redirect(url_for('main.dashboard'))
        
        if not self.is_valid_file(file.filename):
            flash('Invalid file type, please upload a CSV file.', 'alert alert-error')
            return redirect(url_for('main.dashboard'))
        
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
            dek_b64 = self.redis_client.get_dek(session['user_id'])
            for row in csv_reader:
                self.insert_password_row(db_session, row, row_index_dict, dek_b64)
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

    def insert_password_row(self, db_session, row, row_index_dict, dek_b64):
        iv_b64, enc_pass_b64 = encrypt_data_dek(row[row_index_dict['password']], dek_b64)
        alt_iv_b64, alt_enc_pass_b64 = encrypt_data_dek('', dek_b64) # for cols that don't exist
        password_entry = Password(
            user_id=session['user_id'],
            name=sanitizer.sanitize(row[row_index_dict['name']]) if row_index_dict['name'] != -1 else '',
            username=sanitizer.sanitize(row[row_index_dict['username']]) if row_index_dict['username'] != -1 else '',
            encrypted_password=enc_pass_b64 if row_index_dict['password'] != -1 else alt_enc_pass_b64,
            iv_password=iv_b64 if row_index_dict['password'] != -1 else alt_iv_b64,
            category=sanitizer.sanitize(row[row_index_dict.get('category')]) if row_index_dict.get('category') != -1 else '',
            notes=encrypt_data(row[row_index_dict['notes']]) if row_index_dict['notes'] != -1 else encrypt_data('')
        )
        db_session.add(password_entry)

main.add_url_rule('/upload_csv', view_func=UploadCSV.as_view('upload_csv'))

class Home(MethodView):
    def get(self):
        content = render_template('login.html')
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
        # Query the database to retrieve the last backup date
        try:
            last_backup_query = Session.query(func.max(BackupHistory.backup_date)).filter(BackupHistory.user_id == session['user_id'])
            last_backup = last_backup_query.scalar()
        finally:
            Session.close()
        # Check if the last backup was more than a month ago
        reminder_needed = False
        if last_backup:
            # Assuming last_backup is already a datetime object; adjust as needed
            # last_backup_date = datetime.strptime(last_backup, '%Y-%m-%d %H:%M:%S')
            if datetime.now() - last_backup > timedelta(days=30):
                reminder_needed = True

        return render_template('dashboard.html', reminder_needed=reminder_needed, last_backup=last_backup)

main.add_url_rule('/dashboard', view_func=Dashboard.as_view('dashboard'))


class AddPassword(BaseAuthenticatedView):
    '''
    Add a new entry into the database.

    Username and Name Entries are sanaitized, to avoid sql injection
    '''
    def get(self):
        return render_template('add_password.html', nonce=g.nonce)
    def post(self):
        
        name = sanitizer.sanitize(request.form['name'])
        username = sanitizer.sanitize(request.form['username'])
        # encrypted_password = encrypt_data(request.form['password'])
        category = sanitizer.sanitize(request.form['category'])
        encrypted_notes = encrypt_data(request.form['notes'])
        # password = request.form['password']

        # dek_b64 = self.redis_client.get_dek(session['user_id'])
        # iv_b64, dek_password_b64 = encrypt_data_dek(password, dek_b64)

        iv_b64 = request.form['ivPass']
        # iv_b64_decode = base64.b64decode(iv_b64) # This is needed for decoding, but redundant for client side encryption.
        password_b64 = request.form['password']
        # logger.info(f'{iv_b64=} and {password_b64=}')

        try:
            is_valid_base64(iv_b64, password_b64)
        except ValidB64Error as e:
            logger.warning(f'{session["user_id"]}: Failed B64 Validation:\n{e}')
            flash('Error: B64 Validation Error', 'alert alert-error')
            return redirect(url_for('main.add_password'))
            
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
            encrypted_password=password_b64,
            iv_password=iv_b64,
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
            logger.error(f"Error adding password: {e}")  # Log or handle the error as needed
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

        return render_template('retrieve_passwords.html', passwords=vault_data, nonce=g.nonce)
    
main.add_url_rule('/retrieve_passwords', view_func=RetrievePasswords.as_view('retrieve_passwords'))


class DeletePassword(BaseAuthenticatedView):
    def post(self, password_id):
        '''
        Delete individual passwords.
        '''
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

main.add_url_rule('/delete_password/<string:password_id>', view_func=DeletePassword.as_view('delete_password'))

class DeleteMultiplePasswords(BaseAuthenticatedView):
    def post(self):
        '''
        Multi Select password entries for deletion
        '''
        
        db_session = Session()
        # Get the list of selected password IDs
        selected_passwords = request.form.getlist('selected_passwords')

        try:
            # Delete all selected password entries belonging to the user in one go
            db_session.query(Password).filter(Password.id.in_(selected_passwords), Password.user_id == session['user_id']).delete(synchronize_session=False)
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
        # Fetch the password entry to be edited
        password_entry = Session.query(Password).filter_by(id=password_id, user_id=session['user_id']).first()
        
        dek_b64 = self.redis_client.get_dek(session['user_id'])
        
        if password_entry:
            decrypted_password = decrypt_data_dek(password_entry.encrypted_password, password_entry.iv_password, dek_b64)
            decrypted_notes = decrypt_data(password_entry.notes)
            logger.info(f'{password_entry.iv_password=}\n{password_entry.encrypted_password}')
            return render_template('edit_password.html', name=password_entry.name, username=password_entry.username, ivPass=password_entry.iv_password,
                                   password=password_entry.encrypted_password,
                                   notes=decrypted_notes, category=password_entry.category, nonce=g.nonce)
        else:
            flash('Password not found or access denied', 'alert alert-error')
            return redirect(url_for('main.retrieve_passwords'))

    def post(self, password_id):
        
        name = sanitizer.sanitize(request.form['name'])
        username = sanitizer.sanitize(request.form['username'])
        # encrypted_password = encrypt_data(request.form['password'])
        category = sanitizer.sanitize(request.form['category'])
        encrypted_notes = encrypt_data(request.form['notes'])

        dek_b64 = self.redis_client.get_dek(session['user_id'])
        iv_b64, dek_password_b64 = encrypt_data_dek(request.form['password'], dek_b64)

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
                password_entry.encrypted_password = request.form['password']
                password_entry.iv_password = request.form['ivPass']
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
main.add_url_rule('/edit_password/<string:password_id>', view_func=EditPassword.as_view('edit_password'))

class DecryptPassword(BaseAuthenticatedView):
    def post(self, password_id):
        '''
        Decrypt the passwords from database, this is used for copy to clipboard button
        '''
        try:
            password_entry = Session.query(Password).filter_by(id=password_id, user_id=session['user_id']).first()
        finally:
            Session.close()
        if password_entry and password_entry.encrypted_password:
            dek_b64 = self.redis_client.get_dek(session['user_id'])
            decrypted_password = decrypt_data_dek(password_entry.encrypted_password, password_entry.iv_password, dek_b64)
            return jsonify({'password': decrypted_password}) # Send the decrypted password back
        else:
            current_ip = get_remote_address()
            logger.error(f'Issue encountered with user trying to use copy to clipboard: IP {current_ip}')
            abort(403)  # Use Flask's abort for HTTP error codes
    
main.add_url_rule('/decrypt_password/<string:password_id>', view_func=DecryptPassword.as_view('decrypt_password'))

class Backup(BaseAuthenticatedView):
    '''
    Downloads a copy of the database locally, using data and time for name
    '''
    methods = ['GET', 'POST']
    def get(self):
        return render_template('backup.html', nonce=g.nonce)
    
    def post(self):    
        
        password = request.form.get('backupPassword')
        if not password:
            flash('Password is required for backup.', 'alert alert-error')
            return redirect(url_for('main.dashboard'))

        user_id = session['user_id']  # Ensure flask_session is imported correctly
        dek = self.redis_client.get_dek(user_id)

        try:
            password_entries = Session.query(Password).filter_by(user_id=user_id).all()
            # Insert a record into backup_history
            # Prepare decrypted data for CSV
            decrypted_data = [[entry.name, entry.username, decrypt_data_dek(entry.encrypted_password, entry.iv_password, dek), entry.category, decrypt_data(entry.notes)] for entry in password_entries]
            new_backup_history = BackupHistory(user_id=user_id)  # Include user_id here
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
                time.sleep(30)  # Wait for 30 seconds before deleting
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
