#!/usr/bin/env python3

import subprocess, glob, os, time
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

def db_server_backup():

    # Define variables
    database_path = os.path.join(os.getcwd(), os.environ.get('DB_PATH', 'database'), 'users.db')
    backup_dir = os.path.join(os.getcwd(), os.environ.get('BACKUP_DIR', 'backup'))
    encryption_key = os.environ.get('SQLCIPHER_KEY')
    # Ensure the backup directory exists
    os.makedirs(backup_dir, exist_ok=True)

    # Create a unique backup file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_file = f"PyLockr_DB_Backup_{timestamp}.db"
    backup_path = os.path.join(backup_dir, backup_file)

    import tempfile

    # Create a temporary file securely
    with tempfile.NamedTemporaryFile(mode='w+', delete=True) as temp_sql:
        temp_sql.write(f'''
        PRAGMA key = '{encryption_key}';
        ATTACH DATABASE '{backup_path}' AS backupdb KEY '{encryption_key}';
        SELECT sqlcipher_export('backupdb');
        DETACH DATABASE backupdb;
        ''')
        temp_sql.flush()  # Ensure data is written to file

        # Build and execute the SQLCipher command
        sqlcipher_command = f'sqlcipher {database_path} < {temp_sql.name}'

        try:
            # Capture stdout and stderr for inspection
            result = subprocess.run(sqlcipher_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)

            # Check if the command was successful
            if result.returncode != 0:
                # Sanitize and log the error message, omitting sensitive information
                sanitized_error = result.stderr.replace(encryption_key, "[ENCRYPTION KEY]")
                print(f"Backup failed. Error: {sanitized_error}")
            else:
                print(f"Backup completed to {backup_path}")
                rotate_backups(backup_dir)
        except Exception as e:
            # Log a generic message for unexpected errors
            print(f"An unexpected error occurred during the backup process.\n{e}")

def rotate_backups(backup_dir):

    max_backups = int(os.environ.get('MAX_DB_BACKUPS', 42))
    # Get a list of backup files sorted by modification time
    backup_files = sorted(glob.glob(os.path.join(backup_dir, 'PyLockr_DB_Backup_*.db')), key=os.path.getmtime)

    # If we have more backups than max_backups, remove the oldest
    while len(backup_files) > max_backups:
        os.remove(backup_files[0])
        backup_files.pop(0)

def scheduler_run():
    # Initialize APScheduler
    frequency = int(os.environ.get('BACKUP_FREQUENCY', 240))
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=db_server_backup, trigger="interval", minutes=frequency)
    scheduler.start()
    
    try:
        # Use an infinite loop to keep the scheduler running
        while True:
            time.sleep(1000)
    except (KeyboardInterrupt, SystemExit):
        # Gracefully shutdown the scheduler when the script is interrupted
        scheduler.shutdown()

if __name__ == '__main__':
    scheduler_run()