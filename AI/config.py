import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'scamshield_super_secret_key_2026_hackathon')
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
    DATABASE_PATH = os.path.join(BASE_DIR, 'database.db')
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

# Ensure folders exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.REPORTS_FOLDER, exist_ok=True)
