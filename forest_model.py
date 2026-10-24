import pandas as pd
from sklearn.ensemble import IsolationForest

FEATURES = [
    "message_rate",
    "failed_logins",
    "payload_size",
    "destination_count"
]

# Your CSV should contain synthetic training telemetry.
data = pd.read_csv("data/telemetry.csv")
normal_data = data.loc[data["scenario_label"] == "normal"]

model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

model.fit(normal_data[FEATURES])

def detect_anomaly(event):
    values = pd.DataFrame(
        [[event[field] for field in FEATURES]],
        columns=FEATURES
    )

    prediction = model.predict(values)[0]
    score = model.decision_function(values)[0]

    return {
        "is_anomaly": bool(prediction == -1),
        "anomaly_score": float(score)
    }
