
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

    
    
    

def generate_report_text(logs, start_date=None, end_date=None):
    if not logs:
        return "Не знайдено подій для генерації звіту"
    
    report_lines = []
    
    if start_date and end_date:
        report_lines.append(f"ЗВІТ ПРО ПОДІЇ БЕЗПЕКИ")
        report_lines.append(f"Період: з {start_date} по {end_date}")
        report_lines.append("="*50)
    else:
        report_lines.append("ЗВІТ")
        report_lines.append("="*50)
    
    events_by_type = {}
    for log in logs:
        if log.event_type not in events_by_type:
            events_by_type[log.event_type] = []
        events_by_type[log.event_type].append(log)
    
    for event_type, event_logs in events_by_type.items():
        report_lines.append(f"\nТип події: {event_type.upper()}")
        report_lines.append(f"Кількість: {len(event_logs)}")
        
        report_lines.append("\nОстанні події:")
        for log in event_logs[:5]:
            report_lines.append(f"- [{log.created_at}] : {log.details}")
    
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
    
    for log in logs:
        severity = log.severity.lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    report_lines.append("\nСТАТИСТИКА ЗА РІВНЯМИ:")
    for level, count in severity_counts.items():
        report_lines.append(f"- {level.upper()}: {count}")
    
    return "\n".join(report_lines)

