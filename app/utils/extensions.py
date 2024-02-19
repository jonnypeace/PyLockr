# extensions.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

redis_password: str = os.environ.get('REDIS_PASSWORD')

if redis_password:
    # Instantiate Limiter without passing the app
    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri=f"redis://:{redis_password}@redis:6379"
    )
else:
    raise OSError('REDIS_PASSWORD not set in .env file')
