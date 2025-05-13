import requests
import time
import random

DEVICE_IP = '192.168.1.10'
USERNAME = 'user1'
URL = 'http://127.0.0.1:5000/log_receiver'

events = [
    "opened_file",
    "edited_config",
    "ran_command",
    "uploaded_data",
    "checked_email"
]

for i in range(10):
    event = random.choice(events)
    payload = {
        "device_ip": DEVICE_IP,
        "event_type": event,
        "username": USERNAME,
        "details": f"User {USERNAME} did {event}"
    }
    r = requests.post(URL, json=payload)
    print(f"Event {event} sent: {r.status_code}")
    time.sleep(random.uniform(0.5, 1.5))
