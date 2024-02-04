#!/usr/bin/env python3

from flask import Flask
from .main import main as main_blueprint
from .auth import auth as auth_blueprint
from config import Config
from pathlib import Path
from .utils.db_utils import setup_db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.register_blueprint(main_blueprint)
    # app.register_blueprint(auth_blueprint, url_prefix='/auth') ####### Consider for future
    app.register_blueprint(auth_blueprint)

    db_path = Path(app.config['DB_PATH']).parent
    db_path.mkdir(parents=True, exist_ok=True)
    db_path = Path(app.config['DB_PATH'])
    print(f"Checking for DB at: {db_path.absolute()}")
    if not db_path.exists():
        print("DB not found, setting up the database...")
        setup_db()
    else:
        print("DB found. Not initializing.")
    return app