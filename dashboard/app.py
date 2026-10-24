
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


# Resolve paths relative to the project, not the terminal directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
TELEMETRY_FILE = PROJECT_ROOT / "data" / "telemetry.csv"
ALERTS_FILE = PROJECT_ROOT / "data" / "alerts.json"

st.set_page_config(
    page_title="TrustLens AI | IoT Security",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ TrustLens AI")
st.caption(
    "IoT Threat Detection & Risk Monitoring | "
    "Simulated prototype data"
)

if st.button("🔄 Refresh data"):
    st.rerun()


@st.cache_data
def load_data(telemetry_mtime, alerts_mtime):
    telemetry = pd.read_csv(TELEMETRY_FILE)

    with open(ALERTS_FILE, "r", encoding="utf-8") as file:
        alert_data = json.load(file)

    alerts = pd.DataFrame(alert_data.get("alerts", []))

    if not alerts.empty:
        alerts["priority"] = (
            alerts["priority"].fillna("UNKNOWN").str.upper()
        )
        alerts["risk_score"] = pd.to_numeric(
            alerts["risk_score"], errors="coerce"
        )
        alerts["timestamp"] = pd.to_datetime(
            alerts["timestamp"], errors="coerce"
        )
        alerts["reasons_text"] = alerts["reasons"].apply(
            lambda value: ", ".join(map(str, value))
            if isinstance(value, list)
            else str(value or "")
        )

    if "timestamp" in telemetry.columns:
        telemetry["timestamp"] = pd.to_datetime(
            telemetry["timestamp"], errors="coerce"
        )

    return telemetry, alerts, alert_data


try:
    telemetry, alerts, alert_data = load_data(
        TELEMETRY_FILE.stat().st_mtime,
        ALERTS_FILE.stat().st_mtime,
    )
except FileNotFoundError as error:
    st.error(f"Required data file not found: {error.filename}")
    st.info(
        "Generate telemetry and run the detection pipeline first."
    )
    st.stop()
except (json.JSONDecodeError, pd.errors.ParserError) as error:
    st.error(f"Could not read the project data: {error}")
    st.stop()


if telemetry.empty:
    st.warning("No telemetry events are available.")
    st.stop()

# Main metrics
total_events = int(
    alert_data.get("total_events", len(telemetry))
)
total_alerts = int(
    alert_data.get("alerts_generated", len(alerts))
)
high_alerts = (
    int((alerts["priority"] == "HIGH").sum())
    if not alerts.empty else 0
)
medium_alerts = (
    int((alerts["priority"] == "MEDIUM").sum())
    if not alerts.empty else 0
)
low_alerts = (
    int((alerts["priority"] == "LOW").sum())
    if not alerts.empty else 0
)
unique_devices = telemetry["device_id"].nunique()

st.subheader("Security Overview")

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Events Processed", f"{total_events:,}")
c2.metric("Alerts Generated", f"{total_alerts:,}")
c3.metric("High Priority", high_alerts)
c4.metric("Medium Priority", medium_alerts)
c5.metric("Devices Observed", unique_devices)

st.caption(
    f"Priority breakdown: {high_alerts} high · "
    f"{medium_alerts} medium · {low_alerts} low"
)

if len(telemetry) != total_events:
    st.warning(
        "The event count in alerts.json differs from telemetry.csv. "
        "Run the pipeline again if these files are meant to match."
    )

st.divider()

# Charts
left, right = st.columns(2)

with left:
    st.subheader("Alert Priority Distribution")

    if alerts.empty:
        st.info("No alerts in the current output.")
    else:
        priority_counts = (
            alerts["priority"]
            .value_counts()
            .rename_axis("Priority")
            .reset_index(name="Alerts")
        )
        fig = px.bar(
            priority_counts,
            x="Priority",
            y="Alerts",
            color="Priority",
            title="Generated alerts by priority",
        )
        st.plotly_chart(fig, width="stretch")

with right:
    st.subheader("Telemetry Scenario Labels")

    if "scenario_label" in telemetry.columns:
        scenario_counts = (
            telemetry["scenario_label"]
            .fillna("Unknown")
            .value_counts()
            .rename_axis("Scenario")
            .reset_index(name="Events")
        )
        fig = px.pie(
            scenario_counts,
            names="Scenario",
            values="Events",
            title="Events by simulator label",
        )
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("No scenario_label column found.")

# Telemetry activity
st.subheader("Message Activity Over Time")

if {"timestamp", "message_rate"}.issubset(telemetry.columns):
    activity = telemetry.dropna(
        subset=["timestamp", "message_rate"]
    ).sort_values("timestamp")

    if not activity.empty:
        fig = px.line(
            activity,
            x="timestamp",
            y="message_rate",
            title="Message rate across telemetry events",
            labels={
                "timestamp": "Time",
                "message_rate": "Messages per interval",
            },
        )
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("No valid timestamps available for the activity chart.")

st.divider()

# Alert explorer
st.subheader("🚨 Alert Explorer")

if alerts.empty:
    st.success("No alerts are currently present in alerts.json.")
else:
    priorities = ["ALL"] + [
        priority
        for priority in ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        if priority in alerts["priority"].unique()
    ]

    f1, f2 = st.columns([1, 2])
    with f1:
        selected_priority = st.selectbox(
            "Filter by priority", priorities
        )
    with f2:
        device_search = st.text_input(
            "Search device ID", placeholder="e.g. device_002"
        )

    filtered = alerts.copy()

    if selected_priority != "ALL":
        filtered = filtered[
            filtered["priority"] == selected_priority
        ]

    if device_search.strip():
        filtered = filtered[
            filtered["device_id"].astype(str).str.contains(
                device_search.strip(), case=False, na=False
            )
        ]

    display_columns = [
        column
        for column in [
            "timestamp",
            "device_id",
            "priority",
            "risk_score",
            "is_anomaly",
            "rule_triggered",
            "reasons_text",
            "status",
        ]
        if column in filtered.columns
    ]

    st.caption(f"Showing {len(filtered):,} of {len(alerts):,} alerts")

    st.dataframe(
        filtered[display_columns].sort_values(
            "timestamp", ascending=False, na_position="last"
        ),
        width="stretch",
        hide_index=True,
    )

# Device summary
st.subheader("📡 Device Risk Summary")

device_summary = (
    telemetry.groupby("device_id")
    .agg(
        Events=("device_id", "size"),
        Avg_Message_Rate=("message_rate", "mean"),
        Max_Failed_Logins=("failed_logins", "max"),
        Max_Destinations=("destination_count", "max"),
    )
    .reset_index()
)

if not alerts.empty:
    device_alerts = (
        alerts.groupby("device_id")
        .agg(
            Alert_Count=("device_id", "size"),
            Max_Risk_Score=("risk_score", "max"),
        )
        .reset_index()
    )

    device_summary = device_summary.merge(
        device_alerts, on="device_id", how="left"
    )
else:
    device_summary["Alert_Count"] = 0
    device_summary["Max_Risk_Score"] = pd.NA

device_summary["Alert_Count"] = (
    device_summary["Alert_Count"].fillna(0).astype(int)
)
device_summary["Max_Risk_Score"] = (
    device_summary["Max_Risk_Score"].fillna(0)
)

device_summary = device_summary.sort_values(
    ["Max_Risk_Score", "Alert_Count"],
    ascending=False,
)

st.dataframe(
    device_summary.round(2),
    width="stretch",
    hide_index=True,
)

st.caption(
    "Prototype note: results are based on the current telemetry, "
    "configured rules, and ML detector. They are not a guarantee "
    "of real-world threat detection."
)
