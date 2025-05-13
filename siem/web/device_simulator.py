# device_simulator.py
import requests
import time

BASE_URL = 'http://localhost:5000/send_log'

# Тестовий DDoS
def simulate_ddos():
    for i in range(10):
        data = {
            'device_id': 1,
            'event_type': 'DDoS',
            'severity': 'critical',
            'details': f'DDoS packet #{i}'
        }
        response = requests.post(BASE_URL, json=data)
        print(response.status_code, response.json())
        time.sleep(0.2)

# Тестовий SQL injection
def simulate_sql_injection():
    data = {
        'device_id': 1,
        'event_type': 'SQL Injection',
        'severity': 'high',
        'details': "' OR '1'='1'; DROP TABLE users;"
    }
    response = requests.post(BASE_URL, json=data)
    print(response.status_code, response.json())

# Звичайний лог
def send_normal_log():
    data = {
        'device_id': 1,
        'event_type': 'User Login',
        'severity': 'info',
        'details': 'User logged in successfully.'
    }
    response = requests.post(BASE_URL, json=data)
    print(response.status_code, response.json())

# Обери, що запускати
if __name__ == '__main__':
    send_normal_log()
    simulate_sql_injection()
    simulate_ddos()
