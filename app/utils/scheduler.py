#!/usr/bin/env python3

import subprocess, glob, os, time
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from pylockr_logging import PyLockrLogs

logger = PyLockrLogs(name='SCHEDULER', log_file='scheduler.log')


def db_server_backup():
    # Define variables
    backup_dir = os.path.join(os.getcwd(), os.environ.get('BACKUP_DIR', 'backup'))
    db_user = os.environ.get('MYSQL_USER')
    db_password = os.environ.get('MYSQL_PASSWORD')
    db_name = os.environ.get('MYSQL_DATABASE')
    # Ensure the backup directory exists
    os.makedirs(backup_dir, exist_ok=True)

    # Create a unique backup file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_file = f"PyLockr_DB_Backup_{timestamp}.sql"
    backup_path = os.path.join(backup_dir, backup_file)

    # Build and execute the mysqldump command
    mysqldump_command = ['mysqldump', '-u', db_user, f'--password={db_password}', db_name, '>', backup_path]

    try:
        # Using subprocess to execute mysqldump command
        process = subprocess.Popen(' '.join(mysqldump_command), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Check if the command was successful
        if process.returncode != 0:
            logger.error(f"Backup failed: {stderr.decode('utf-8')}")
        else:
            logger.info(f"Backup completed to {backup_path}")
            rotate_backups(backup_dir)
    except Exception as e:
        logger.error(f"An unexpected error occurred during the backup process: {e}")


def rotate_backups(backup_dir):
    '''
    Rotate backups. Be sure to set your environment variables:

        MAX_DB_BACKUPS: int, default = 42
    '''
    max_backups = int(os.environ.get('MAX_DB_BACKUPS', 42))
    # Get a list of backup files sorted by modification time
    backup_files = sorted(glob.glob(os.path.join(backup_dir, 'PyLockr_DB_Backup_*.db')), key=os.path.getmtime)
    if len(backup_files) > max_backups:
        logger.info('Rotating backup database files commencing, file numbers are greater than MAX_DB_BACKUPS')
    # If we have more backups than max_backups, remove the oldest
    while len(backup_files) > max_backups:
        os.remove(backup_files[0])
        backup_files.pop(0)

def scheduler_run():
    '''
    For the scheduler docker service which cleanly backs up the sqlcipher database
    
    Ensure you have set your backup frequency environment variable

        BACKUP_FREQUENCY: int = default = 240 (mins)
    '''
    # Initialize APScheduler
    frequency = int(os.environ.get('BACKUP_FREQUENCY', 240))
    logger.info(f'Database Backup Frequency set to {frequency} minute(s)')
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