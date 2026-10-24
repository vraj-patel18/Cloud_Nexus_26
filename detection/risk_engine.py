def calculate_risk(
    is_anomaly,
    failed_logins,
    high_message_rate,
    correlated_events
):
    score = 0
    reasons = []

    if is_anomaly:
        score += 25
        reasons.append("Unusual device behaviour")

    if failed_logins >= 5:
        score += 30
        reasons.append("Repeated login failures")

    if high_message_rate:
        score += 25
        reasons.append("Abnormally high message rate")

    if correlated_events >= 2:
        score += 20
        reasons.append("Related events detected")

    score = min(score, 100)

    if score >= 70:
        priority = "HIGH"
    elif score >= 35:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "risk_score": score,
        "priority": priority,
        "reasons": reasons
    }