import csv
import json
import os
from pathlib import Path

import paho.mqtt.client as mqtt

from detection.risk_engine import analyze_event


# --------------------------------------------------
# FILE PATHS
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"

TELEMETRY_FILE = DATA_DIR / "telemetry.csv"
LIVE_TELEMETRY_FILE = DATA_DIR / "live_telemetry.csv"
LIVE_ALERTS_FILE = DATA_DIR / "live_alerts.jsonl"


# --------------------------------------------------
# MQTT CONFIGURATION
# --------------------------------------------------

BROKER = os.getenv("MQTT_BROKER", "localhost")
PORT = int(os.getenv("MQTT_PORT", "1883"))
TOPIC = os.getenv("MQTT_TOPIC", "trustlens/telemetry")


# --------------------------------------------------
# TELEMETRY CSV CONFIGURATION
# --------------------------------------------------

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


# --------------------------------------------------
# SAVE LIVE TELEMETRY
# --------------------------------------------------

def append_telemetry(event):
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    row = {
        field: event.get(field, "")
        for field in TELEMETRY_FIELDS
    }

    needs_header = (
        not TELEMETRY_FILE.exists()
        or TELEMETRY_FILE.stat().st_size == 0
    )

    with TELEMETRY_FILE.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=TELEMETRY_FIELDS,
        )

        if needs_header:
            writer.writeheader()

        writer.writerow(row)


# --------------------------------------------------
# SAVE LIVE ALERTS AS JSON LINES
# --------------------------------------------------

def save_live_alert(alert):
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with LIVE_ALERTS_FILE.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(alert, default=str) + "\n"
        )


# --------------------------------------------------
# MQTT CALLBACKS
# --------------------------------------------------

def on_connect(client, userdata, flags, reason_code, properties):
    print("MQTT connection result:", reason_code)

    if reason_code == 0:
        client.subscribe(TOPIC)
        print("Subscribed to:", TOPIC)
    else:
        print("MQTT connection failed:", reason_code)


def on_message(client, userdata, message):
    try:
        event = json.loads(
            message.payload.decode("utf-8")
        )

        if not isinstance(event, dict):
            print("Skipped message: JSON object expected")
            return

        missing = REQUIRED_FIELDS - event.keys()

        if missing:
            print(
                "Skipped message; missing fields:",
                sorted(missing),
            )
            return

        # Validate numeric telemetry fields.
        numeric_fields = [
            "message_rate",
            "failed_logins",
            "payload_size",
            "destination_count",
        ]

        for field in numeric_fields:
            value = event[field]

            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value < 0
            ):
                print(
                    "Skipped message; invalid numeric field:",
                    field,
                )
                return

        if not isinstance(event["device_id"], str) or not event["device_id"].strip():
            print("Skipped message; invalid device_id")
            return

        # Normalize fields used by the dashboard.
        event.setdefault("timestamp", __import__("time").time())
        event.setdefault("scenario_label", "normal")

        # 1. Save telemetry.
        append_telemetry(event)

        # 2. Run detection and risk analysis.
        result = analyze_event(event)

        if not isinstance(result, dict):
            print("Detection returned an unexpected result:", result)
            return

        # Keep the original event attached to the alert so the
        # dashboard can use it for live telemetry charts.
        result["timestamp"] = event.get("timestamp")
        result["device_id"] = event["device_id"]
        result["raw_event"] = event

        # 3. Save only events identified as potential alerts.
        reasons = result.get("reasons", [])

        if reasons:
            print("\nPOTENTIAL SECURITY ALERT")
            print(json.dumps(result, indent=2, default=str))

            save_live_alert(result)
            print("Alert saved to:", LIVE_ALERTS_FILE)

        else:
            print("Normal event:", event["device_id"])

    except (
        json.JSONDecodeError,
        ValueError,
        TypeError,
        KeyError,
        OSError,
    ) as error:
        print("Could not process telemetry message:", error)

    except Exception as error:
        # Keep the MQTT consumer running if an unexpected
        # detection-pipeline error occurs.
        print("Unexpected telemetry processing error:", error)


# --------------------------------------------------
# START MQTT CONSUMER
# --------------------------------------------------

def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="trustlens-security-engine",
    )

    client.on_connect = on_connect
    client.on_message = on_message

    print("Starting TrustLens MQTT consumer...")
    print("Broker:", BROKER, PORT)
    print("Topic:", TOPIC)
    print("Telemetry file:", TELEMETRY_FILE)
    print("Live alerts file:", LIVE_ALERTS_FILE)

    client.connect(BROKER, PORT, 60)
    client.loop_forever()


if __name__ == "__main__":
    main()
