
import json
import pandas as pd

from detection.risk_engine import analyze_event


def main():
    df = pd.read_csv("data/telemetry.csv")
    alerts = []

    for event in df.to_dict(orient="records"):
        result = analyze_event(event)

        if result["reasons"]:
            result["timestamp"] = str(event["timestamp"])
            alerts.append(result)

    output = {
        "total_events": len(df),
        "alerts_generated": len(alerts),
        "alerts": alerts
    }

    with open(
        "data/alerts.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(output, file, indent=2)

    print("Pipeline completed!")
    print("Events processed:", len(df))
    print("Alerts generated:", len(alerts))
    print("Output: data/alerts.json")


if __name__ == "__main__":
    main()