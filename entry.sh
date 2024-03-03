#!/usr/bin/env bash

# Change ownership of the application directory to appuser
chown -R appuser:appuser /usr/src/app

# Wait for MariaDB to be ready
echo "Waiting for MariaDB to be ready..."
while ! nc -z mariadb 3306; do
    sleep 1
done
echo "MariaDB is ready!"

# Switch to the appuser and run the commands
su -c '
    echo "Starting Gunicorn..."
    exec gunicorn -w 4 -b 0.0.0.0:5000 "wsgi:app"
' appuser
