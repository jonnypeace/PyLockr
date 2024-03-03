#!/usr/bin/env bash

chown -R appuser:appuser /usr/src/app
# Run the scheduling service
echo "Starting the scheduling service..."
su -c 'exec python3 app/utils/scheduler.py' appuser
