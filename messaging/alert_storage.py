
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALERTS_FILE = PROJECT_ROOT / "data" / "alerts.json"


def save_alert(alert):
    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Preserve existing alerts.
    if ALERTS_FILE.exists():
        try:
            with ALERTS_FILE.open("r", encoding="utf-8") as file:
                alerts = json.load(file)

            if not isinstance(alerts, list):
                alerts = []
        except (json.JSONDecodeError, OSError):
            alerts = []
    else:
        alerts = []

    alerts.append(alert)

    with ALERTS_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=2)

    print(f"Alert saved to: {ALERTS_FILE}")