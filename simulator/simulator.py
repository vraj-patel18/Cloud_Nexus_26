
import random
import time
from datetime import datetime, timezone


def generate_telemetry(device_id):
    """Generate one sample of virtual IoT device telemetry."""
    return {
        "device_id": device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message_rate": random.randint(5, 30),
        "failed_logins": random.randint(0, 1),
        "payload_size": random.randint(100, 1000),
        "destination_count": random.randint(1, 3),
    }


def main():
    device_ids = ["device_001", "device_002", "device_003"]

    print("TrustLens AI - Virtual IoT Simulator")
    print(f"Simulating {len(device_ids)} devices.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            for device_id in device_ids:
                telemetry = generate_telemetry(device_id)
                print(telemetry)

            print("-" * 50)
            time.sleep(2)

    except KeyboardInterrupt:
        print("\nSimulator stopped.")


if __name__ == "__main__":
    main()
