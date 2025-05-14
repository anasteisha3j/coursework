import os
import requests
from dotenv import load_dotenv
from ..models import Log, Device  
from flask_login import current_user
from datetime import datetime

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def generate_report_text(logs):
    if not logs:
        return "Немає подій для звіту."

    lines = [" *Звіт про події* — {0}\n".format(datetime.utcnow().strftime("%Y-%m-%d %H:%M"))]
    
    for log in logs:
        lines.append(f"""
 *Пристрій:* {log.device.name if log.device else 'Невідомо'}
 *Подія:* {log.event_type}
 *Рівень:* {log.severity}
 *Час:* {log.created_at.strftime("%Y-%m-%d %H:%M:%S")}
 *Деталі:* `{str(log.details)[:200]}`
        """)

    return "\n".join(lines)

def send_report(session):
    logs = Log.query.filter_by(organization_id=current_user.organization_id).order_by(Log.created_at.desc()).limit(10).all()
    
    report_text = generate_report_text(logs)

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    data = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': report_text
    }

    response = requests.post(url, json=data)

    if response.status_code != 200:
        raise Exception(f"Telegram error: {response.text}")

    print("Report sent to your Telegram successfully!")
