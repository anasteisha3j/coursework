from web import DeviceSimulator
from web import sim


if __name__ == "__main__":
    sim = DeviceSimulator()
    sim.create_test_users(org_name="Test Org")
    sim.create_test_devices(org_name="Test Org")

