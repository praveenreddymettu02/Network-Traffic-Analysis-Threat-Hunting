#!/usr/bin/env python3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime

import os

# CREDENTIALS via environment variables
EMAIL = os.getenv('ALERT_EMAIL', '')
PASSWORD = os.getenv('ALERT_EMAIL_PASSWORD', '')

def send_test():
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL
        msg['To'] = EMAIL
        msg['Subject'] = '✅ Alert Engine - Test Email'
        
        body = f"""
🎉 CONGRATULATIONS! Your email configuration is working!

═══════════════════════════════════════

✅ Test successful!

You will now receive real-time alerts for:
- Port Scans 🔍
- DNS Floods 🌊
- ICMP Floods 📡
- Excessive TCP 🔗
- Beaconing 🎯
- Brute Force 🔓

Test Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Account: {EMAIL}

═══════════════════════════════════════
Network Alert Engine - Ready! 🚀
"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        print("📧 Sending test email...")
        print(f"   From: {EMAIL}")
        print(f"   To: {EMAIL}")
        
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL, PASSWORD)
            server.send_message(msg)
        
        print("\n✅ Test email sent successfully!")
        print(f"📫 Check your inbox: {EMAIL}")
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False

if __name__ == '__main__':
    send_test()