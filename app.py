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

    # Auto-seed realistic demo traffic if database is empty so dashboard is never blank (skipped during testing)
    is_testing = app.config.get('TESTING') or ('unittest' in sys.modules) or bool(os.environ.get('TESTING'))
    if not is_testing:
        try:
            from routes.api import db, alert_engine
            if db.get_packet_count() == 0:
                from utils.demo_generator import generate_demo_traffic
                logger.info("Auto-seeding initial SOC traffic and alerts into database...")
                generate_demo_traffic(db, alert_engine, count=120)
                logger.info("Initial SOC traffic auto-seeded successfully.")
        except Exception as e:
            logger.warning(f"Could not auto-seed initial demo traffic: {e}")

    logger.info("Network Traffic Analysis App started.")
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=False)
