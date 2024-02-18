#!/usr/bin/env python3

from flask import Flask
from .main import main as main_blueprint
from .auth import auth as auth_blueprint
from config import Config
from pathlib import Path
from .utils.db_utils import setup_db, db_server_backup
from apscheduler.schedulers.background import BackgroundScheduler
import os

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.register_blueprint(main_blueprint)
    # app.register_blueprint(auth_blueprint, url_prefix='/auth') ####### Consider for future
    app.register_blueprint(auth_blueprint)

    db_path = Path(app.config['DB_PATH']).parent
    db_path.mkdir(parents=True, exist_ok=True)
    backup_path = Path(app.config['BACKUP_DIR'])
    backup_path.mkdir(parents=True, exist_ok=True)
    db_path = Path(app.config['DB_PATH'])
    print(f"Checking for DB at: {db_path.absolute()}")
    if not db_path.exists():
        print("DB not found, setting up the database...")
        with app.app_context():
            setup_db()  # Now has access to `current_app`
    else:
        print("DB found. Not initializing.")

    # Initialize APScheduler
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        scheduler = BackgroundScheduler()
        scheduler.add_job(func=db_server_backup, trigger="interval", minutes=5)  # Example: daily backup
        scheduler.start()

    # Shutdown your scheduler when the app exits
    @app.teardown_appcontext
    def shutdown_scheduler(response_or_exc):
        scheduler.shutdown()
        return response_or_exc

    return app