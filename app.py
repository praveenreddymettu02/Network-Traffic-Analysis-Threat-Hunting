import os
import sys
from flask import Flask
from flask_cors import CORS
from config import Config
from routes.api import api_bp, start_alert_engine
from routes.views import views_bp
from utils.logger import setup_logger

logger = setup_logger('app')


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    CORS(app)

    app.register_blueprint(api_bp)
    app.register_blueprint(views_bp)

    # Start alert engine
    try:
        start_alert_engine()
        logger.info("Alert engine started successfully")
    except Exception as e:
        logger.error(f"Failed to start alert engine: {e}")

    logger.info("Network Traffic Analysis App started.")
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=False)
