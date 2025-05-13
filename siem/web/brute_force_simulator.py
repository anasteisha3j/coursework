import requests
import time

API_URL = 'http://localhost:5000/simulate_login_failure'

for attempt in range(1, 21):
    payload = {
        'email': 'user1@email.com',
        'ip_address': '192.168.1.10',
        'organization_id': '20c343ac-f3c3-438d-b20c-43c0cdd29cb3'  
    }

    response = requests.post(API_URL, json=payload)
    print(f"Sent attempt {attempt}: {response.status_code}")
    time.sleep(0.5)
