
import paho.mqtt.client as mqtt
import json

def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print("Connected to MQTT broker.")
        client.subscribe("trustlens/telemetry", qos=1)
        print("Listening for TrustLens telemetry...\n")
    else:
        print(f"Connection failed: {reason_code}")

def on_message(client, userdata, message):
    try:
        telemetry = json.loads(message.payload.decode("utf-8"))
        print(f"RECEIVED [{message.topic}]: {telemetry}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        print(f"Received non-JSON message: {message.payload!r}")

client = mqtt.Client(
    callback_api_version=mqtt.CallbackAPIVersion.VERSION2
)
client.on_connect = on_connect
client.on_message = on_message

try:
    client.connect("127.0.0.1", 1883, keepalive=60)
    client.loop_forever()
except KeyboardInterrupt:
    print("\nSubscriber stopped.")
finally:
    client.disconnect()
