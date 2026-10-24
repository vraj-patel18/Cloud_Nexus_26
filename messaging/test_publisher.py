
import json
import time
import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 1883
TOPIC = "trustlens/telemetry"

client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id="trustlens-test-publisher"
)

client.connect(BROKER, PORT, 60)
client.loop_start()

time.sleep(1)

test_events = [
    {
        "device_id": "device_normal_001",
        "timestamp": int(time.time()),
        "message_rate": 10,
        "failed_logins": 0,
        "payload_size": 200,
        "destination_count": 2
    },
    {
        "device_id": "device_suspicious_001",
        "timestamp": int(time.time()),
        "message_rate": 120,
        "failed_logins": 8,
        "payload_size": 900,
        "destination_count": 12
    }
]

for event in test_events:
    result = client.publish(TOPIC, json.dumps(event), qos=1)
    result.wait_for_publish()
    print("Published:", event["device_id"])

client.loop_stop()
client.disconnect()