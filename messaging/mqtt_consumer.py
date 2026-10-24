
import json
import os

import paho.mqtt.client as mqtt

from detection.risk_engine import analyze_event

BROKER = os.getenv("MQTT_BROKER", "localhost")
PORT = int(os.getenv("MQTT_PORT", "1883"))
TOPIC = os.getenv("MQTT_TOPIC", "trustlens/telemetry")

REQUIRED_FIELDS = {
    "device_id",
    "message_rate",
    "failed_logins",
    "payload_size",
    "destination_count"
}


def on_connect(client, userdata, flags, reason_code, properties):
    print("MQTT connection result:", reason_code)

    if reason_code == 0:
        client.subscribe(TOPIC)
        print("Subscribed to:", TOPIC)


def on_message(client, userdata, message):
    try:
        event = json.loads(message.payload.decode("utf-8"))

        if not isinstance(event, dict):
            print("Skipped message: JSON object expected")
            return

        missing = REQUIRED_FIELDS - event.keys()

        if missing:
            print("Skipped message; missing fields:", sorted(missing))
            return

        # Validate the fields consumed by the detector.
        numeric_fields = [
            "message_rate",
            "failed_logins",
            "payload_size",
            "destination_count"
        ]

        for field in numeric_fields:
            value = event[field]

            if isinstance(value, bool) or not isinstance(value, (int, float)):
                print("Skipped message; invalid numeric field:", field)
                return

            if value < 0:
                print("Skipped message; negative field:", field)
                return

        result = analyze_event(event)

        if result["reasons"]:
            result["timestamp"] = event.get("timestamp")
            print("\nPOTENTIAL SECURITY ALERT")
            print(json.dumps(result, indent=2))
        else:
            print("Normal event:", event["device_id"])

    except (ValueError, TypeError, KeyError) as error:
        print("Invalid telemetry message:", error)


client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id="trustlens-security-engine"
)

client.on_connect = on_connect
client.on_message = on_message

client.connect(BROKER, PORT, 60)
client.loop_forever()