#!/usr/bin/env python3

import subprocess, glob, os, time, signal
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from pylockr_logging import PyLockrLogs

logger = PyLockrLogs(name='SCHEDULER', log_file='scheduler.log')


def db_server_backup():
    # Define variables
    backup_dir = os.path.join(os.getcwd(), os.environ.get('BACKUP_DIR', 'backup'))
    db_user = os.environ.get('MYSQL_USER')
    db_password = os.environ.get('MYSQL_PASSWORD')
    db_name = os.environ.get('MYSQL_DB')
    mysql_host: str = os.environ.get('MYSQL_HOST')
    mysql_port: str = os.environ.get('MYSQL_PORT')

    # SSL Configuration
    ssl_ca: str = os.environ.get('SSL_CA')
    ssl_cert: str = os.environ.get('SSL_CERT')
    ssl_key: str = os.environ.get('SSL_KEY')

    # Ensure the backup directory exists
    os.makedirs(backup_dir, exist_ok=True)

    # Create a unique backup file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_file = f"PyLockr_DB_Backup_{timestamp}.sql"
    backup_path = os.path.join(backup_dir, backup_file)
    gpg_passphrase = os.getenv('GPG_PASSPHRASE')

    # Build the mysqldump command
    mariadb_dump_command = [
        'mariadb-dump',
        f'--user={db_user}',
        f'--password={db_password}',
        f'--host={mysql_host}',
        f'--port={mysql_port}',
        f'--ssl-ca={ssl_ca}',
        f'--ssl-cert={ssl_cert}',
        f'--ssl-key={ssl_key}',
        f'--databases', db_name
    ]

    # Adjust gpg command to use the passphrase from the environment variable
    gpg_encrypt_command = [
        'gpg', '--batch', '--yes', '--passphrase', gpg_passphrase,
        '--symmetric', '--cipher-algo', 'AES256', '-o', f'{backup_path}.gpg'
    ]

    try:
        # Use subprocess.Popen for the mariadb_dump_command
        with subprocess.Popen(mariadb_dump_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as dump_proc:
            stdout, stderr = dump_proc.communicate()  # Capture stdout and stderr
            
            if dump_proc.returncode != 0:
                logger.error(f"MariaDB dump failed: {stderr.decode('utf-8')}")
                raise Exception(f"MariaDB dump failed: {stderr.decode('utf-8')}")
            
            # If mariadb-dump was successful, proceed with encryption using gpg
            with open(f'{backup_path}.gpg', 'wb') as encrypted_file:
                # Note: Changing to subprocess.run for simplicity, but you could use Popen for more control
                gpg_proc = subprocess.run(gpg_encrypt_command, input=stdout, stdout=encrypted_file, stderr=subprocess.PIPE, check=False)
                
                if gpg_proc.returncode != 0:
                    logger.error(f"GPG encryption failed: {gpg_proc.stderr.decode('utf-8')}")
                    raise Exception(f"GPG encryption failed: {gpg_proc.stderr.decode('utf-8')}")

        logger.info(f"Backup and encryption completed successfully to {backup_path}.gpg")
        rotate_backups(backup_dir)

    except Exception as e:
        logger.error(f"An unexpected error occurred during the backup and encryption process: {e}")


def rotate_backups(backup_dir):
    '''
    Rotate backups. Be sure to set your environment variables:

        MAX_DB_BACKUPS: int, default = 42
    '''
    max_backups = int(os.environ.get('MAX_DB_BACKUPS', 42))
    # Get a list of backup files sorted by modification time
    backup_files = sorted(glob.glob(os.path.join(backup_dir, 'PyLockr_DB_Backup_*.sql.gpg')), key=os.path.getmtime)
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
    def signal_handler(signum, frame):
        print('Received shutdown signal, stopping scheduler...')
        scheduler.shutdown(wait=False)
    print('Scheduler stopped gracefully.')
    # Initialize APScheduler
    frequency = int(os.environ.get('BACKUP_FREQUENCY', 240))
    logger.info(f'Database Backup Frequency set to {frequency} minute(s)')
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=db_server_backup, trigger="interval", minutes=frequency)
    scheduler.start()

    # Graceful shutdown for sigterm and sigint to handle database backups
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Keep the scheduler alive with infinite loop
    while True:
        time.sleep(1000)

if __name__ == '__main__':
    scheduler_run()