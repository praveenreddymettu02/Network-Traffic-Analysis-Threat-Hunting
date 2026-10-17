import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'network_traffic.db')

    # Interface: None means auto-detect at runtime
    CAPTURE_INTERFACE = os.getenv('CAPTURE_INTERFACE', None) or None

    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

    # TShark path: auto-detected if not set
    TSHARK_PATH = os.getenv('TSHARK_PATH', None) or None

    # Database performance
    DB_BATCH_SIZE = int(os.getenv('DB_BATCH_SIZE', '1'))
    DB_BATCH_INTERVAL = float(os.getenv('DB_BATCH_INTERVAL', '2.0'))

    # Retention
    RETENTION_DAYS = int(os.getenv('RETENTION_DAYS', '30'))

    # Capture defaults
    CAPTURE_TIMEOUT = int(os.getenv('CAPTURE_TIMEOUT', '1'))
