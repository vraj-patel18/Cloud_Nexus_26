
from pathlib import Path

import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

FEATURES = [
    "message_rate",
    "failed_logins",
    "payload_size",
    "destination_count"
]

# Load the synthetic IoT dataset
data_path = Path("data/telemetry.csv")
df = pd.read_csv(data_path)

# Train only on normal behaviour
normal_data = df.loc[
    df["scenario_label"] == "normal",
    FEATURES
]

if len(normal_data) < 10:
    raise ValueError("Not enough normal records to train the model.")

# Create and train the anomaly detector
model = IsolationForest(
    n_estimators=150,
    contamination=0.05,
    random_state=42
)

model.fit(normal_data)

# Save the trained model and its feature list
model_path = Path("detection/isolation_forest.joblib")

joblib.dump(
    {
        "model": model,
        "features": FEATURES
    },
    model_path
)

print("Model trained successfully!")
print("Normal training records:", len(normal_data))
print("Model saved to:", model_path.resolve())