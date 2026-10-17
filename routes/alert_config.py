# routes/alert_config.py

import os

# ============================================
# 🔥 ALERT ENGINE CONFIGURATION
# ============================================

# ============================================
# 🎯 ALERT THRESHOLDS
# ============================================

ALERT_THRESHOLDS = {
    "port_scan": {
        "ports": 20,
        "time_window": 10,
        "severity": "HIGH"
    },
    "dns_flood": {
        "queries": 50,
        "time_window": 5,
        "severity": "HIGH"
    },
    "icmp_flood": {
        "packets": 100,
        "time_window": 5,
        "severity": "MEDIUM"
    },
    "tcp_connections": {
        "connections": 50,
        "time_window": 10,
        "severity": "MEDIUM"
    },
    "beaconing": {
        "requests": 20,
        "time_window": 60,
        "interval_variance": 5,
        "severity": "HIGH"
    },
    "brute_force": {
        "attempts": 10,
        "time_window": 60,
        "severity": "CRITICAL"
    }
}

# ============================================
# 📦 ALERT RETENTION SETTINGS
# ============================================

ALERT_RETENTION_DAYS = 30
MAX_ALERTS_IN_MEMORY = 1000

# ============================================
# 🔔 NOTIFICATION SETTINGS
# ============================================

ENABLE_EMAIL_ALERTS = True
ENABLE_WEBHOOK_ALERTS = False
ENABLE_SLACK_ALERTS = False

# ============================================
# 📧 EMAIL CONFIGURATION
# ============================================

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USE_TLS = True

# Credentials are loaded from environment variables
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

# Email Recipients
ALERT_EMAIL_RECIPIENTS = [
    SMTP_USERNAME
]

# Email Sender
ALERT_EMAIL_SENDER = SMTP_USERNAME

# Email Subject Prefix
ALERT_EMAIL_SUBJECT_PREFIX = "[Network Alert] "

# Minimum severity to send email
EMAIL_MIN_SEVERITY = "MEDIUM"

# ============================================
# 🔗 WEBHOOK CONFIGURATION
# ============================================

WEBHOOK_URL = ""
WEBHOOK_MIN_SEVERITY = "HIGH"

# ============================================
# 💬 SLACK CONFIGURATION
# ============================================

SLACK_WEBHOOK_URL = ""
SLACK_CHANNEL = "#alerts"
SLACK_MIN_SEVERITY = "HIGH"

# ============================================
# 🎚️ ALERT FILTERS
# ============================================

MIN_ALERT_SEVERITY = "LOW"
IGNORED_ALERT_TYPES = []
MAX_ALERTS_PER_HOUR = 10
