
import random
import time
import json
import paho.mqtt.client as mqtt

from datetime import datetime, timezone


MQTT_BROKER = "127.0.0.1"
MQTT_PORT = 1883
MQTT_TOPIC = "trustlens/telemetry"


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

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2
    )

    try:
        client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
        client.loop_start()

        print("TrustLens AI - Virtual IoT Simulator")
        print("Simulating 3 devices.")
        print(f"MQTT broker: {MQTT_BROKER}:{MQTT_PORT}")
        print(f"MQTT topic: {MQTT_TOPIC}")
        print("Suspicious scenarios are simulated, not real attacks.")
        print("Press Ctrl+C to stop.\n")

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

                # Display telemetry in the terminal
                print(f"[{status}] {telemetry}")

                # Publish telemetry as JSON over MQTT
                info = client.publish(
                    MQTT_TOPIC,
                    json.dumps(telemetry),
                    qos=1,
                )

                if info.rc != mqtt.MQTT_ERR_SUCCESS:
                    print(f"MQTT publish failed: {info.rc}")

            print("-" * 60)
            time.sleep(2)

    except KeyboardInterrupt:
        print("\nSimulator stopped.")

    except Exception as error:
        print(f"\nSimulator/MQTT error: {error}")

    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
