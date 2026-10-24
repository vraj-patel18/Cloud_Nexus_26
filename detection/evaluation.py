
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
    frac=1,
    random_state=42
)

suspicious = df[df["scenario_label"] != "normal"]

# Reserve normal examples for testing
split_index = int(len(normal) * 0.7)

train_normal = normal.iloc[:split_index]
test_normal = normal.iloc[split_index:]

test = pd.concat(
    [test_normal, suspicious],
    ignore_index=True
)

y_true = (
    test["scenario_label"] != "normal"
).astype(int)

# Rule-based predictions
y_rules = (
    (test["message_rate"] > 80)
    | (test["failed_logins"] >= 5)
    | (test["destination_count"] >= 8)
).astype(int)

# Train ML model only on training normal data
model = IsolationForest(
    n_estimators=150,
    contamination=0.05,
    random_state=42
)

model.fit(train_normal[FEATURES])

y_ml = (
    model.predict(test[FEATURES]) == -1
).astype(int)


def report(name, actual, predicted):
    print(f"\n--- {name} ---")

    print(
        "Precision:",
        round(precision_score(actual, predicted), 3)
    )

    print(
        "Recall:",
        round(recall_score(actual, predicted), 3)
    )

    print(
        "F1-score:",
        round(f1_score(actual, predicted), 3)
    )

    print("Confusion matrix:")
    print(confusion_matrix(actual, predicted))

    normal_mask = actual == 0
    false_positives = (
        (predicted == 1) & normal_mask
    ).sum()

    normal_count = normal_mask.sum()

    rate = (
        100 * false_positives / normal_count
        if normal_count else 0
    )

    print(
        "False positives per 100 normal events:",
        round(rate, 2)
    )


report("Rule-based detector", y_true, y_rules)
report("Isolation Forest", y_true, y_ml)