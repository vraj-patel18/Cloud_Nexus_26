
from pathlib import Path

import joblib
import pandas as pd

MODEL_PATH = Path("detection/isolation_forest.joblib")

bundle = joblib.load(MODEL_PATH)
model = bundle["model"]
FEATURES = bundle["features"]


def detect_with_ml(event):
    values = pd.DataFrame(
        [[event[name] for name in FEATURES]],
        columns=FEATURES
    )

    prediction = int(model.predict(values)[0])
    raw_score = float(model.decision_function(values)[0])

    return {
        "is_anomaly": prediction == -1,
        "anomaly_score": round(raw_score, 4)
    }


if __name__ == "__main__":
    normal_event = {
        "device_id": "device_001",
        "message_rate": 20,
        "failed_logins": 0,
        "payload_size": 512,
        "destination_count": 2
    }

    suspicious_event = {
        "device_id": "device_002",
        "message_rate": 200,
        "failed_logins": 10,
        "payload_size": 512,
        "destination_count": 15
    }

    print("Normal event:")
    print(detect_with_ml(normal_event))

    print("\nSuspicious event:")
    print(detect_with_ml(suspicious_event))