
from pathlib import Path
import json

import pandas as pd
import plotly.express as px
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TELEMETRY_FILE = PROJECT_ROOT / "data" / "telemetry.csv"
ALERTS_FILE = PROJECT_ROOT / "data" / "alerts.json"

st.set_page_config(
    page_title="TrustLens AI",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ TrustLens AI")
st.caption("IoT Threat Detection & Risk Monitoring | Simulated prototype data")


@st.cache_data
def load_data(telemetry_mtime, alerts_mtime):
    telemetry = pd.read_csv(TELEMETRY_FILE)

    with ALERTS_FILE.open("r", encoding="utf-8") as file:
        alert_data = json.load(file)

    # Support both a list of alerts and a dictionary containing alerts.
    if isinstance(alert_data, list):
        alert_records = alert_data
        summary_data = {}
    elif isinstance(alert_data, dict):
        alert_records = alert_data.get("alerts", [])
        summary_data = alert_data
    else:
        alert_records = []
        summary_data = {}

    if not isinstance(alert_records, list):
        alert_records = []

    alerts = pd.DataFrame(alert_records)

    if not alerts.empty:
        if "risk_score" in alerts.columns:
            alerts["risk_score"] = pd.to_numeric(
                alerts["risk_score"], errors="coerce"
            )

        if "timestamp" in alerts.columns:
            alerts["timestamp"] = pd.to_datetime(
                alerts["timestamp"], errors="coerce", utc=True
            )

    if "timestamp" in telemetry.columns:
        telemetry["timestamp"] = pd.to_datetime(
            telemetry["timestamp"], errors="coerce", utc=True
        )

    return telemetry, alerts, summary_data


if st.button("🔄 Refresh data"):
    st.cache_data.clear()
    st.rerun()


try:
    telemetry, alerts, alert_data = load_data(
        TELEMETRY_FILE.stat().st_mtime,
        ALERTS_FILE.stat().st_mtime,
    )
except FileNotFoundError as error:
    st.error(f"Required data file not found: {error.filename}")
    st.info("Generate telemetry and run the detection pipeline first.")
    st.stop()
except (json.JSONDecodeError, pd.errors.ParserError, OSError, ValueError) as error:
    st.error(f"Could not load dashboard data: {error}")
    st.stop()

if telemetry.empty:
    st.warning("No telemetry events are available.")
    st.stop()

# Ensure expected columns exist before building charts and tables.
required_columns = [
    "device_id",
    "message_rate",
    "failed_logins",
    "payload_size",
    "destination_count",
]
missing_columns = [
    column for column in required_columns if column not in telemetry.columns
]
if missing_columns:
    st.error(f"Telemetry CSV is missing columns: {', '.join(missing_columns)}")
    st.stop()

total_events = len(telemetry)
unique_devices = telemetry["device_id"].nunique()
total_alerts = len(alerts)

if not alerts.empty and "priority" in alerts.columns:
    high_alerts = int(
        alerts["priority"].astype(str).str.upper().eq("HIGH").sum()
    )
else:
    high_alerts = 0

if not alerts.empty and "risk_score" in alerts.columns:
    average_risk = alerts["risk_score"].mean()
else:
    average_risk = 0

# Summary metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Telemetry Events", f"{total_events:,}")
col2.metric("Devices Monitored", f"{unique_devices:,}")
col3.metric("Security Alerts", f"{total_alerts:,}")
col4.metric("High-Priority Alerts", f"{high_alerts:,}")

st.divider()

# Telemetry activity
st.subheader("📈 Telemetry Activity")

if {"timestamp", "message_rate"}.issubset(telemetry.columns):
    activity = telemetry.dropna(
        subset=["timestamp", "message_rate"]
    ).sort_values("timestamp")

    if not activity.empty:
        fig = px.line(
            activity,
            x="timestamp",
            y="message_rate",
            color="device_id",
            title="Message rate across telemetry events",
            labels={
                "timestamp": "Time",
                "message_rate": "Messages per interval",
                "device_id": "Device",
            },
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No valid timestamps available for the activity chart.")
else:
    st.info("Timestamp or message-rate data is unavailable.")

# Scenario distribution
if "scenario_label" in telemetry.columns:
    st.subheader("🧪 Telemetry Scenario Distribution")
    scenario_counts = (
        telemetry["scenario_label"]
        .fillna("unknown")
        .astype(str)
        .value_counts()
        .rename_axis("Scenario")
        .reset_index(name="Events")
    )

    fig = px.bar(
        scenario_counts,
        x="Scenario",
        y="Events",
        title="Events by scenario label",
    )
    st.plotly_chart(fig, use_container_width=True)

st.divider()

# Alerts table
st.subheader("🚨 Security Alerts")

if alerts.empty:
    st.info("No security alerts have been saved yet.")
else:
    if "timestamp" in alerts.columns:
        alerts = alerts.sort_values(
            "timestamp", ascending=False, na_position="last"
        )

    display_columns = [
        column
        for column in [
            "timestamp",
            "device_id",
            "priority",
            "risk_score",
            "is_anomaly",
            "rule_triggered",
            "status",
            "reasons",
        ]
        if column in alerts.columns
    ]

    if display_columns:
        st.dataframe(
            alerts[display_columns],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.dataframe(alerts, use_container_width=True, hide_index=True)

# Device summary
st.subheader("💻 Device Summary")

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

if not alerts.empty and "device_id" in alerts.columns:
    alert_summary = (
        alerts.groupby("device_id")
        .agg(Alert_Count=("device_id", "size"))
        .reset_index()
    )
    device_summary = device_summary.merge(
        alert_summary, on="device_id", how="left"
    )
    device_summary["Alert_Count"] = (
        device_summary["Alert_Count"].fillna(0).astype(int)
    )
else:
    device_summary["Alert_Count"] = 0

st.dataframe(
    device_summary,
    use_container_width=True,
    hide_index=True,
)

st.caption(
    "Prototype note: results are based on simulated telemetry and "
    "the alerts saved by the detection pipeline."
)

