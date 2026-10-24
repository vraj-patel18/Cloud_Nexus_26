
from pathlib import Path

import numpy as np
import pandas as pd

rng = np.random.default_rng(42)
rows = []

START_TIME = pd.Timestamp("2026-10-24 09:00:00")


def add_event(
    device_id,
    minute,
    message_rate,
    failed_logins,
    payload_size,
    destination_count,
    scenario
):
    rows.append({
        "device_id": device_id,
        "timestamp": START_TIME + pd.Timedelta(minutes=minute),
        "message_rate": int(message_rate),
        "failed_logins": int(failed_logins),
        "payload_size": int(payload_size),
        "destination_count": int(destination_count),
        "scenario_label": scenario
    })


# 1. Normal IoT activity
for i in range(1200):
    add_event(
        device_id=f"device_{i % 10 + 1:03d}",
        minute=i,
        message_rate=rng.integers(5, 31),
        failed_logins=rng.choice([0, 0, 0, 1]),
        payload_size=rng.integers(100, 1001),
        destination_count=rng.integers(1, 4),
        scenario="normal"
    )


# 2. Simulated message flooding
for i in range(100):
    add_event(
        f"device_{i % 10 + 1:03d}",
        1200 + i,
        rng.integers(100, 301),
        rng.integers(0, 3),
        rng.integers(100, 1001),
        rng.integers(1, 5),
        "message_flood"
    )


# 3. Simulated repeated login failures
for i in range(100):
    add_event(
        f"device_{i % 10 + 1:03d}",
        1300 + i,
        rng.integers(5, 31),
        rng.integers(6, 16),
        rng.integers(100, 1001),
        rng.integers(1, 4),
        "repeated_login_failures"
    )


# 4. Simulated unusual destination behaviour
for i in range(100):
    add_event(
        f"device_{i % 10 + 1:03d}",
        1400 + i,
        rng.integers(5, 31),
        rng.integers(0, 2),
        rng.integers(100, 1001),
        rng.integers(10, 26),
        "unusual_destinations"
    )


# 5. Combined suspicious indicators
for i in range(100):
    add_event(
        f"device_{i % 10 + 1:03d}",
        1500 + i,
        rng.integers(100, 301),
        rng.integers(6, 16),
        rng.integers(100, 1001),
        rng.integers(10, 26),
        "combined_suspicious"
    )


df = pd.DataFrame(rows).sort_values("timestamp")

output_path = Path(__file__).with_name("telemetry.csv")
df.to_csv(output_path, index=False)

print("Dataset generated successfully!")
print("Total records:", len(df))
print("Unique devices:", df["device_id"].nunique())
print("\nScenario counts:")
print(df["scenario_label"].value_counts())
print("\nFirst five records:")
print(df.head().to_string(index=False))
print("\nSaved to:", output_path.resolve())