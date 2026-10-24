
def detect_with_rules(event):
    reasons = []

    # Rule 1: Abnormally high message rate
    if event["message_rate"] > 80:
        reasons.append("Message rate exceeds threshold")

    # Rule 2: Repeated failed logins
    if event["failed_logins"] >= 5:
        reasons.append("Repeated login failures")

    # Rule 3: Unusually many destinations
    if event["destination_count"] >= 8:
        reasons.append("Unusually many destinations")

    return {
        "is_suspicious": len(reasons) > 0,
        "reasons": reasons
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
        "failed_logins": 8,
        "payload_size": 512,
        "destination_count": 12
    }

    print("Normal event:")
    print(detect_with_rules(normal_event))

    print("\nSuspicious event:")
    print(detect_with_rules(suspicious_event))
    