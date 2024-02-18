#!/usr/bin/env bash

# Change ownership of the application directory to appuser
chown -R appuser:appuser /usr/src/app

# Switch to the appuser and run the commands
su -c '
    echo "Checking for DB and setting up if not found..."
    python3 app/utils/create_paths.py

    echo "Starting Gunicorn..."
    exec gunicorn -w 4 -b 0.0.0.0:5000 "wsgi:app"
' appuser
