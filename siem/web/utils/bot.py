
from datetime import datetime


from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from dotenv import load_dotenv
import os
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')


async def send_report_message(message: str):
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    await application.bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message)

import requests

def send_report(file_path):
    bot_token = TELEGRAM_BOT_TOKEN
    chat_id = TELEGRAM_CHAT_ID

    with open(file_path, 'rb') as f:
        url = f'https://api.telegram.org/bot{bot_token}/sendDocument'
        files = {'document': f}
        data = {'chat_id': chat_id}
        response = requests.post(url, data=data, files=files)

    if response.status_code != 200:
        raise Exception(f"Failed to send report: {response.text}")

    
    
    
def generate_report_text(logs):
    if not logs:
        return "Немає подій для звіту."

    lines = ["*Звіт про події* — {0}\n".format(datetime.utcnow().strftime("%Y-%m-%d %H:%M"))]
    for log in logs:
        lines.append(f"""
 *Пристрій:* {log.device.name if log.device else 'Невідомо'}
 *Подія:* {log.event_type}
 *Рівень:* {log.severity}
 *Час:* {log.created_at.strftime("%Y-%m-%d %H:%M:%S")}
 *Деталі:* `{str(log.details)[:200]}`
        """)

    return "\n".join(lines)



