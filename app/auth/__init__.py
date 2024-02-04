#!/usr/bin/env python3

from flask import Blueprint

# Create a Blueprint named 'auth'
auth = Blueprint('auth', __name__)

# Import the routes; this is done at the end to avoid circular dependencies
from . import routes
