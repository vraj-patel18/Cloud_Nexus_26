
import csv
import json
import os
from pathlib import Path

import paho.mqtt.client as mqtt

from detection.risk_engine import analyze_event
from messaging.alert_storage import save_alert

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TELEMETRY_FILE = PROJECT_ROOT / "data" / "telemetry.csv"

BROKER = os.getenv("MQTT_BROKER", "localhost")
PORT = int(os.getenv("MQTT_PORT", "1883"))
TOPIC = os.getenv("MQTT_TOPIC", "trustlens/telemetry")

TELEMETRY_FIELDS = [
    "device_id",
    "timestamp",
    "message_rate",
    "failed_logins",
    "payload_size",
    "destination_count",
    "scenario_label",
]

REQUIRED_FIELDS = {
    "device_id",
    "message_rate",
    "failed_logins",
    "payload_size",
    "destination_count",
}


def append_telemetry(event):
    TELEMETRY_FILE.parent.mkdir(parents=True, exist_ok=True)

    row = {field: event.get(field, "") for field in TELEMETRY_FIELDS}

    # Preserve the CSV's existing columns and historical rows.
    needs_header = (
        not TELEMETRY_FILE.exists()
        or TELEMETRY_FILE.stat().st_size == 0
    )

    with TELEMETRY_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=TELEMETRY_FIELDS)
        if needs_header:
            writer.writeheader()
        writer.writerow(row)


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

        for field in (
            "message_rate",
            "failed_logins",
            "payload_size",
            "destination_count",
        ):
            value = event[field]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value < 0
            ):
                print("Skipped message; invalid numeric field:", field)
                return

        # Normalize the event to the dashboard's CSV format.
        event.setdefault("timestamp", "")
        event.setdefault("scenario_label", "normal")

        append_telemetry(event)
        result = analyze_event(event)

        if result.get("reasons"):
            result["timestamp"] = event.get("timestamp")
            result.setdefault("device_id", event["device_id"])

            print("\nPOTENTIAL SECURITY ALERT")
            print(json.dumps(result, indent=2))

            save_alert(result)
        else:
            print("Normal event:", event["device_id"])

    except (ValueError, TypeError, KeyError, OSError) as error:
        print("Could not process telemetry message:", error)


client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id="trustlens-security-engine",
)

client.on_connect = on_connect
client.on_message = on_message

client.connect(BROKER, PORT, 60)
client.loop_forever()
