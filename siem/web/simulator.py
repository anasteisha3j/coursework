import random
import time
import uuid
from datetime import datetime
from faker import Faker
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Device, Log, Organization, User

fake = Faker()

class DeviceSimulator:
    def __init__(self):
        self.DATABASE_URI = "postgresql://postgres:postgres@localhost/siem"
        self.engine = create_engine(self.DATABASE_URI)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
        self.DEVICE_COUNT = 10
        self.ATTACK_INTERVAL = 30  # seconds
        self.ATTACK_TYPES = [
            "Brute Force SSH", "SQL Injection", "DDoS",
            "Port Scanning", "Malware Download", "Phishing Attempt"
        ]
        self.ATTACK_TYPES += ["Credential Stuffing", "Phishing Login"]
        
        
        
        
    def simulate_user_attack(self):
        """Simulate attack targeting user credentials"""
        users = self.session.query(User).all()
        if not users:
            print("❗ No users found to simulate user-based attacks.")
            return

        user = random.choice(users)
        attack_type = random.choice(["Credential Stuffing", "Phishing Login"])
        severity = random.choice(["high", "critical"])

        log = Log(
            id=str(uuid.uuid4()),
            device_id=None,  # optional: could link to the device they're using
            organization_id=user.organization_id,
            event_type="User Security Alert",
            severity=severity,
            details={
                "message": f"{attack_type} attempt on user {user.email}",
                "user_email": user.email,
                "attack_type": attack_type,
                "ip_address": fake.ipv4(),
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        self.session.add(log)
        self.session.commit()
        print(f"⚠️  Simulated {attack_type} attack on {user.email}")



    def _get_or_create_org(self):
        """Get or create test organization"""
        org = self.session.query(Organization).first()
        if not org:
            org = Organization(
                id=str(uuid.uuid4()),
                name="Test Org",
                created_at=datetime.utcnow()
            )
            self.session.add(org)
            self.session.commit()
        return org

    def create_test_devices(self):
        """Create test devices in the database"""
        org = self._get_or_create_org()
        
        devices = []
        for _ in range(self.DEVICE_COUNT):
            device = Device(
                id=str(uuid.uuid4()),
                organization_id=org.id,
                name=f"{fake.word().capitalize()}-{fake.random_int(1, 100)}",
                ip_address=fake.ipv4(),
                mac_address=fake.mac_address(),
                type=random.choice(["server", "workstation", "camera", "router", "printer"]),
                is_active=True,
                last_seen=datetime.utcnow()
            )
            devices.append(device)
            self.session.add(device)
        
        self.session.commit()
        return devices

    def normal_activity(self, devices):
        """Simulate normal device activity"""
        if not devices:
            return
            
        for device in devices:
            if device.is_active:
                device.last_seen = datetime.utcnow()
                
                log = Log(
                    id=str(uuid.uuid4()),
                    device_id=device.id,
                    organization_id=device.organization_id,
                    event_type=random.choice(["Authentication", "Network Traffic", "System Event"]),
                    severity="info",
                    details={
                        "message": f"Normal activity on {device.name}",
                        "source_ip": fake.ipv4(),
                        "destination_port": random.randint(1, 65535),
                        "protocol": random.choice(["TCP", "UDP"])
                    }
                )
                self.session.add(log)
        
        self.session.commit()

    def simulate_attack(self, devices):
        """Simulate a security attack"""
        if len(devices) < 2:  # Need at least 2 devices for attack simulation
            print("Not enough devices to simulate attack (need at least 2)")
            return
            
        attacker, target = random.sample(devices, 2)
        
        attack_type = random.choice(self.ATTACK_TYPES)
        severity = random.choice(["high", "critical"])
        
        attack_log = Log(
            id=str(uuid.uuid4()),
            device_id=target.id,
            organization_id=target.organization_id,
            event_type="Security Alert",
            severity=severity,
            details={
                "message": f"{attack_type} attack from {attacker.ip_address} to {target.ip_address}",
                "attack_type": attack_type,
                "source_ip": attacker.ip_address,
                "target_ip": target.ip_address,
                "port": random.randint(1, 65535)
            }
        )
        self.session.add(attack_log)
        
        if random.random() < 0.3:
            target.is_active = False
            compromise_log = Log(
                id=str(uuid.uuid4()),
                device_id=target.id,
                organization_id=target.organization_id,
                event_type="Compromise",
                severity="critical",
                details={
                    "message": f"Device {target.name} compromised",
                    "reason": attack_type
                }
            )
            self.session.add(compromise_log)
        
        self.session.commit()

    def run(self):
        print("🚀 Starting SIEM device simulator...")
        
        # Get existing devices or create new ones
        devices = self.session.query(Device).all()
        if not devices:
            print("No devices found, creating test devices...")
            devices = self.create_test_devices()
        
        print(f"Monitoring {len(devices)} devices...")
        
        try:
            while True:
                self.normal_activity(devices)

                if len(devices) >= 2 and random.random() < 0.6:
                    self.simulate_attack(devices)

                if random.random() < 0.3:  # ~30% chance to run user attack
                    self.simulate_user_attack()

                time.sleep(self.ATTACK_INTERVAL)

        except KeyboardInterrupt:
            print("\n🛑 Stopping simulator...")
        finally:
            self.session.close()

# Export the simulator class
sim = DeviceSimulator