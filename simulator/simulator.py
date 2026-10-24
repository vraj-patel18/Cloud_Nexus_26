
import random
import time
from datetime import datetime, timezone


def generate_telemetry(device_id, suspicious=False):
    """Generate normal or suspicious simulated IoT telemetry."""

    telemetry = {
        "device_id": device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message_rate": random.randint(5, 30),
        "failed_logins": random.randint(0, 1),
        "payload_size": random.randint(100, 1000),
        "destination_count": random.randint(1, 3),
    }

    if suspicious:
        telemetry["message_rate"] = random.randint(100, 200)
        telemetry["failed_logins"] = random.randint(8, 15)
        telemetry["destination_count"] = random.randint(10, 20)

    return telemetry


def main():
    device_ids = ["device_001", "device_002", "device_003"]
    cycle = 0

    print("TrustLens AI - Virtual IoT Simulator")
    print("Simulating 3 devices.")
    print("Suspicious scenarios are simulated, not real attacks.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            cycle += 1

            for device_id in device_ids:
                suspicious = (
                    device_id == "device_003"
                    and cycle % 3 == 0
                )

                telemetry = generate_telemetry(
                    device_id, suspicious=suspicious
                )

                status = "SUSPICIOUS" if suspicious else "NORMAL"
                print(f"[{status}] {telemetry}")

            print("-" * 60)
            time.sleep(2)

    except KeyboardInterrupt:
        print("\nSimulator stopped.")


if __name__ == "__main__":
    main()
