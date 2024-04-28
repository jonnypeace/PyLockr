from . import main
from app.utils.db_utils import *
from app.utils.pylockr_logging import *
from flask import current_app, render_template, request, redirect, url_for, session, flash, send_file, make_response, g, after_this_request, abort, jsonify
from datetime import timedelta, datetime
from html_sanitizer import Sanitizer
from flask.views import MethodView
import re, os, csv, py7zr, time, io, csv, json, secrets, base64, redis
from flask_limiter.util import get_remote_address
from threading import Thread
from sqlalchemy.exc import SQLAlchemyError
from app.utils.extensions import limiter
from app.utils.key_exchange import ValidB64Error, is_valid_base64
from collections import defaultdict
from typing import Type
from sqlalchemy.ext.declarative import DeclarativeMeta

sanitizer = Sanitizer()  # Used for name and username
logger = PyLockrLogs(name='PyLockr_Main')


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

        enc_file_b64 = request.form.get('encFileB64')
        iv_b64 = request.form.get('ivFileB64')
        dek = self.redis_client.get_dek(session['user_id'])

        if not all([enc_file_b64, iv_b64, dek]) or not is_valid_base64(enc_file_b64, iv_b64):
            logger.error('Invalid or missing encryption parameters')
            flash('Invalid or missing encryption parameters', 'alert alert-error')
            return redirect(url_for('main.dashboard'))
        
        try:
            file = decrypt_data_dek(enc_file_b64, iv_b64, dek)
            if not file:
                flash('Failed to decrypt file', 'alert alert-error')
                return redirect(url_for('main.dashboard'))

            file_stream = io.StringIO(file, newline=None)
            if not self.is_csv(file_stream):
                logger.error('Invalid file format. Please upload a CSV file.')
                flash('Invalid file format. Please upload a CSV file.', 'alert alert-error')
                return redirect(url_for('main.dashboard'))

            self.process_file(file_stream)
            flash('CSV File successfully uploaded', 'alert alert-ok')
        except Exception as e:
            logger.error(f'Error processing the file:\n{e}')
            flash(f'Unknown Error processing the file', 'alert alert-error')
        return redirect(url_for('main.dashboard'))

    def is_csv(self, file_stream):
        try:
            csv.Sniffer().sniff(file_stream.read(1024))  # Check if the file stream is a CSV
            file_stream.seek(0)  # Reset file stream to the beginning
            return True
        except csv.Error:
            return False

    def process_file(self, file_stream):
        csv_reader = csv.reader(file_stream)
        row_index_dict = {}
        with Session() as db_session:
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
        form_keys = set(Password.__table__.columns.keys()) - {'id', 'user_id', 'user', '_sa_instance_state'}
        form_dict = {field: request.form.get(field, '') for field in form_keys}

        try:
            is_valid_base64(*form_dict.values())
        except ValidB64Error as e:
            logger.warning(f'{session["user_id"]}: Failed B64 Validation:\n{e}')
            flash('Error: B64 Validation Error', 'alert alert-error')
            return redirect(url_for('main.add_password'))

        form_dict['user_id'] = session['user_id']
        # Add new password entry
        new_password_entry = Password(**form_dict)

        with Session() as db_session:
            try:
                db_session.add(new_password_entry)
                db_session.commit()
                flash('Password added successfully!', 'alert alert-ok')
            except SQLAlchemyError as e:
                db_session.rollback()
                flash('Failed to add password.', 'alert alert-error')
                logger.error(f"Error adding password: {e}")  # Log or handle the error as needed
                return redirect(url_for('main.add_password'))

        return redirect(url_for('main.dashboard'))  # Adjust the redirect as needed

main.add_url_rule('/add_password', view_func=AddPassword.as_view('add_password'))

def query_to_dict(model: Type[DeclarativeMeta], fields: list, user_id: str)-> defaultdict:
    """
    Query specified fields from a model and return a defaultdict
    where each key corresponds to a field and the value is a list of values for that field.

    :param model: SQLAlchemy model class
    :param fields: List of field names to query
    :return: defaultdict with field names as keys and lists of values as values
    """
    with Session() as db_session:
        try:
            query = db_session.query(*[getattr(model, field) for field in fields]).filter(model.user_id == user_id)
            results = query.all()

            # Initialize a defaultdict with lists as default values
            column_lists = defaultdict(list)
            # Populate the lists
            for entry in results:
                for field in fields:
                    value = getattr(entry, field)
                    column_lists[field].append(value)
        except Exception as e:
            db_session.rollback()
            flash('Failed to retrieve data from PyLockr db', 'alert alert-error')
            logger.error(f"Failed to retrieve data from PyLockr db")

    return column_lists


class RetrievePasswords(BaseAuthenticatedView):
    def get(self):
        '''
        Retrieve passwords route for the password manager table, which uses jQuery DataTables to sort entries.
        Passwords are masked in the DataTables view.
        '''
        fields: list = ['id',
                        'Name',
                        'ivName',
                        'Username',
                        'ivUsername',
                        'Category',
                        'ivCategory']
        vault_data = json.dumps(query_to_dict(Password, fields, session['user_id']))

        return render_template('retrieve_passwords.html', passwords=vault_data, nonce=g.nonce)
    
main.add_url_rule('/retrieve_passwords', view_func=RetrievePasswords.as_view('retrieve_passwords'))


class DeletePassword(BaseAuthenticatedView):
    def post(self, password_id):
        '''
        Delete individual passwords.
        '''
        db_session = Session()
        with Session() as db_session:
            try:
                # Fetch the password entry to be deleted
                password_entry = db_session.query(Password).filter_by(id=password_id, user_id=session['user_id']).first()
                if password_entry:
                    db_session.delete(password_entry)
                    db_session.commit()
                    flash('Password entry deleted successfully.', 'alert alert-ok')
                else:
                    flash('Password entry not found or not authorized to delete.', 'alert alert-error')
            except SQLAlchemyError as e:
                db_session.rollback()
                flash('Failed to delete password entry.', 'alert alert-error')
                logger.error(f"Error deleting password")

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

        with Session() as db_session:
            try:
                # Delete all selected password entries belonging to the user in one go
                db_session.query(Password).filter(Password.id.in_(selected_passwords), Password.user_id == session['user_id']).delete(synchronize_session=False)
                db_session.commit()
            except SQLAlchemyError as e:  # Catch more specific database errors
                db_session.rollback()
                flash('Failed to delete selected password entries.', 'alert alert-error')
                logger.error(f"Error deleting selected passwords: {e}")

        current_ip = get_remote_address()
        logger.info(f'user successfully deleted {len(selected_passwords)} passwords: IP {current_ip}')
        flash(f'Deleted {len(selected_passwords)} passwords.', 'alert alert-ok')

        return redirect(url_for('main.retrieve_passwords'))

main.add_url_rule('/delete_multiple_passwords', view_func=DeleteMultiplePasswords.as_view('delete_multiple_passwords'))


class EditPassword(BaseAuthenticatedView):
    def get(self, password_id):
        # Fetch the password entry to be edited
        data = Session.query(Password).filter_by(id=password_id, user_id=session['user_id']).first()
        form_keys = set(Password.__table__.columns.keys()) - {'user_id', 'user', '_sa_instance_state'}
        # Automatically map all attributes to a dictionary, excluding SQLAlchemy internal items
        vault_data = {key: getattr(data, key) for key in form_keys}
        vault_data = json.dumps(vault_data)
        if vault_data:
            return render_template('edit_password.html', passwords=vault_data, nonce=g.nonce)
        else:
            flash('Password not found or access denied', 'alert alert-error')
            return redirect(url_for('main.retrieve_passwords'))

    def post(self, password_id):
        form_keys = set(Password.__table__.columns.keys()) - {'id', 'user_id', 'user'}
        form_dict = {field: request.form.get(field, '') for field in form_keys}

        try:
            is_valid_base64(*form_dict.values())
        except ValidB64Error as e:
            logger.warning(f'{session["user_id"]}: Failed B64 Validation:\n{e}')
            flash('Error: B64 Validation Error', 'alert alert-error')
            return redirect(url_for('main.edit_password', password_id=password_id))
        
        form_dict['user_id'] = session['user_id']

        # Update password entry
        with Session() as db_session:
            try:
                password_entry = db_session.query(Password).filter_by(id=password_id, user_id=session['user_id']).first()
                if password_entry:
                    for key, value in form_dict.items():
                        setattr(password_entry, key, value)  # Dynamically update attributes
                    db_session.commit()
                    flash('Password entry updated successfully.', 'alert alert-ok')
                else:
                    flash('Password entry not found.', 'alert alert-error')
                    return redirect(url_for('main.edit_password', password_id=password_id))
            except SQLAlchemyError as e:
                db_session.rollback()
                flash('Failed to update password entry.', 'alert alert-error')
                logger.error(f"Error updating password")
                return redirect(url_for('main.edit_password', password_id=password_id))
       
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
        if password_entry:
            return jsonify({'password': password_entry.Password, 'iv': password_entry.ivPassword}) # Send the encrypted password back
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
        
        password_b64 = request.form.get('b64Pass')
        iv_b64 = request.form.get('ivPass')
        print(f'{password_b64=}')
        if not password_b64:
            flash('Password is required for backup.', 'alert alert-error')
            return redirect(url_for('main.dashboard'))

        user_id = session['user_id']  # Ensure flask_session is imported correctly
        dek = self.redis_client.get_dek(user_id)
        password = decrypt_data_dek(password_b64, iv_b64, dek)

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
