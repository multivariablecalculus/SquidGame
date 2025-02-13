# config.py

import os

# Database Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'squid_game.db')}"

DATABASE_URI = "mongodb://localhost:27017/squidgame"

# Security Key (for Flask sessions, if needed)
SECRET_KEY = "hacker_haven"
