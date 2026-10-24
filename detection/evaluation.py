
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

FEATURES = [
    "message_rate",
    "failed_logins",
    "payload_size",
    "destination_count"
]

df = pd.read_csv("data/telemetry.csv")

normal = df[df["scenario_label"] == "normal"].sample(
    frac=1, random_state=42
)
suspicious = df[df["scenario_label"] != "normal"]

split = int(len(normal) * 0.7)
train_normal = normal.iloc[:split]
test_normal = normal.iloc[split:]

test = pd.concat(
    [test_normal, suspicious], ignore_index=True
)

X_test = test[FEATURES]
y_true = (test["scenario_label"] != "normal").astype(int)

# Train only on the normal training partition.
model = IsolationForest(
    n_estimators=150,
    contamination=0.05,
    random_state=42
)
model.fit(train_normal[FEATURES])

# Rule-based predictions
rules = (
    (test["message_rate"] > 80)
    | (test["failed_logins"] >= 5)
    | (test["destination_count"] >= 8)
).astype(int)

# ML predictions
ml = (model.predict(X_test) == -1).astype(int)

# Combined predictions: alert if either detector flags an event.
combined = ((rules == 1) | (ml == 1)).astype(int)


def report(name, actual, predicted):
    print(f"\n--- {name} ---")
    print("Precision:", round(
        precision_score(actual, predicted, zero_division=0), 3
    ))
    print("Recall:", round(
        recall_score(actual, predicted, zero_division=0), 3
    ))
    print("F1-score:", round(
        f1_score(actual, predicted, zero_division=0), 3
    ))
    print("Confusion matrix:")
    print(confusion_matrix(actual, predicted))

    normal_mask = (actual == 0)
    fp = ((predicted == 1) & normal_mask).sum()
    n = normal_mask.sum()

    print(
        "False positives per 100 normal events:",
        round(100 * fp / n, 2) if n else 0
    )


report("Rule-based detector", y_true, rules)
report("Isolation Forest", y_true, ml)
report("Combined detector", y_true, combined)