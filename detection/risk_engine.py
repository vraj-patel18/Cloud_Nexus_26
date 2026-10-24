
from detection.rules import detect_with_rules
from detection.detector import detect_with_ml


def analyze_event(event):
    # Run both detectors
    rule_result = detect_with_rules(event)
    ml_result = detect_with_ml(event)

    reasons = list(rule_result["reasons"])

    if ml_result["is_anomaly"]:
        reasons.append("ML detected unusual behaviour")

    # Calculate an illustrative risk score
    score = 0

    if ml_result["is_anomaly"]:
        score += 25

    if event["message_rate"] > 80:
        score += 25

    if event["failed_logins"] >= 5:
        score += 30

    if event["destination_count"] >= 8:
        score += 20

    score = min(score, 100)

    if score >= 70:
        priority = "HIGH"
    elif score >= 35:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "device_id": event["device_id"],
        "is_anomaly": ml_result["is_anomaly"],
        "rule_triggered": rule_result["is_suspicious"],
        "anomaly_score": ml_result["anomaly_score"],
        "risk_score": score,
        "priority": priority,
        "reasons": reasons,
        "status": (
            "Needs investigation"
            if reasons
            else "No alert"
        )
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

    print("NORMAL EVENT RESULT:")
    print(analyze_event(normal_event))

    print("\nSUSPICIOUS EVENT RESULT:")
    print(analyze_event(suspicious_event))