#!/usr/bin/env bash

# Delay execution until the database setup is complete
while [ ! -f /usr/src/app/database/users.db ]; do
  sleep 1
done

# Run the scheduling service
echo "Starting the scheduling service..."
su -c 'exec python3 app/utils/scheduler.py' appuser
