
# messaging/simulator.py

import json
import random
import time
import uuid
from datetime import datetime, timezone

import paho.mqtt.client as mqtt


BROKER = "127.0.0.1"
PORT = 1883
TOPIC = "trustlens/telemetry"

DEVICE_IDS = [f"device_{i:03d}" for i in range(1, 11)]

PUBLISH_INTERVAL = 2  # Seconds between events


def generate_event(device_id):
    """Generate telemetry for one simulated IoT device."""

    # Most events are normal; some represent suspicious behavior.
    scenario = random.choices(
        ["normal", "message_flood", "login_failures", "unusual_destinations"],
        weights=[75, 10, 8, 7],
        k=1,
    )[0]

    if scenario == "message_flood":
        message_rate = random.randint(100, 180)
        failed_logins = random.randint(0, 2)
        destination_count = random.randint(1, 5)

    elif scenario == "login_failures":
        message_rate = random.randint(5, 40)
        failed_logins = random.randint(5, 10)
        destination_count = random.randint(1, 5)

    elif scenario == "unusual_destinations":
        message_rate = random.randint(5, 40)
        failed_logins = random.randint(0, 2)
        destination_count = random.randint(8, 15)

    else:
        message_rate = random.randint(5, 40)
        failed_logins = random.randint(0, 2)
        destination_count = random.randint(1, 5)

    return {
    "event_id": str(uuid.uuid4()),
    "device_id": device_id,
    "timestamp": time.time(),
    "message_rate": message_rate,
    "failed_logins": failed_logins,
    "destination_count": destination_count,
    "payload_size": random.randint(64, 1500),
    "scenario_label": scenario,
    "source": "simulator",
}


def main():
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"trustlens-simulator-{uuid.uuid4().hex[:8]}",
    )

    client.connect(BROKER, PORT, keepalive=60)
    client.loop_start()

    print(f"Connected to MQTT broker: {BROKER}:{PORT}")
    print(f"Publishing telemetry for {len(DEVICE_IDS)} devices.")
    print("Press Ctrl+C to stop the simulator.")

    device_index = 0

    try:
        while True:
            device_id = DEVICE_IDS[device_index]
            event = generate_event(device_id)

            info = client.publish(
                TOPIC,
                json.dumps(event),
                qos=1,
            )
            info.wait_for_publish()

            print(
                f"{event['device_id']} | "
                f"Scenario: {event['scenario_label']} | "
                f"Rate: {event['message_rate']} | "
                f"Failed logins: {event['failed_logins']} | "
                f"Destinations: {event['destination_count']}"
            )

            # Rotate through all ten devices.
            device_index = (device_index + 1) % len(DEVICE_IDS)
            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print("\nSimulator stopped.")

    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()