from pathlib import Path
import json

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"

TELEMETRY_FILE = DATA_DIR / "telemetry.csv"
ALERTS_FILE = DATA_DIR / "alerts.json"
LIVE_ALERTS_FILE = DATA_DIR / "live_alerts.jsonl"

st.set_page_config(
    page_title="TrustLens AI",
    page_icon="🛡️",
    layout="wide",
)

# Re-run the dashboard every five seconds.
st_autorefresh(
    interval=5000,
    key="trustlens_auto_refresh",
)

st.title("🛡️ TrustLens AI")
st.caption(
    "IoT Threat Detection & Risk Monitoring | "
    "Simulated prototype data"
)


# --------------------------------------------------
# FILE VERSIONS
# --------------------------------------------------

def file_version(path):
    """Detect changes to a data file."""
    try:
        stat = path.stat()
        return stat.st_mtime_ns, stat.st_size
    except FileNotFoundError:
        return 0, 0


# --------------------------------------------------
# TIMESTAMP NORMALIZATION
# --------------------------------------------------

def parse_timestamp(value):
    """Parse Unix timestamps (seconds/milliseconds) or date strings."""
    if pd.isna(value) or value == "":
        return pd.NaT

    try:
        number = float(value)
        # Contemporary Unix timestamps in milliseconds are much larger
        # than timestamps expressed in seconds.
        unit = "ms" if abs(number) >= 100_000_000_000 else "s"
        return pd.to_datetime(number, unit=unit, errors="coerce", utc=True)
    except (TypeError, ValueError):
        return pd.to_datetime(value, errors="coerce", utc=True)


def normalize_timestamps(series):
    return series.map(parse_timestamp)


# --------------------------------------------------
# ALERT LOADING
# --------------------------------------------------

def read_historical_alerts():
    if not ALERTS_FILE.exists() or ALERTS_FILE.stat().st_size == 0:
        return [], {}

    with ALERTS_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, list):
        return data, {}

    if isinstance(data, dict):
        records = data.get("alerts", [])
        return (records if isinstance(records, list) else []), data

    return [], {}


def read_live_alerts():
    """Read JSONL: each non-empty line is a separate alert object."""
    records = []

    if not LIVE_ALERTS_FILE.exists():
        return records

    with LIVE_ALERTS_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    records.append(record)
            except json.JSONDecodeError:
                # A partially written last line should not break the dashboard.
                continue

    return records


# --------------------------------------------------
# DATA LOADING
# --------------------------------------------------

@st.cache_data(show_spinner=False)
def load_data(telemetry_version, alerts_version, live_alerts_version):
    # telemetry.csv is the file written by the MQTT consumer.
    if not TELEMETRY_FILE.exists():
        raise FileNotFoundError(str(TELEMETRY_FILE))

    telemetry = pd.read_csv(TELEMETRY_FILE, low_memory=False)

    historical_records, summary_data = read_historical_alerts()
    live_records = read_live_alerts()

    historical_alerts = pd.DataFrame(historical_records)
    live_alerts = pd.DataFrame(live_records)

    if not historical_alerts.empty:
        historical_alerts["alert_source"] = "Historical"

    if not live_alerts.empty:
        live_alerts["alert_source"] = "Live MQTT"

    alerts = pd.concat(
        [historical_alerts, live_alerts],
        ignore_index=True,
        sort=False,
    )

    # Ensure fields used by the charts are numeric.
    for column in (
        "message_rate",
        "failed_logins",
        "payload_size",
        "destination_count",
    ):
        if column in telemetry.columns:
            telemetry[column] = pd.to_numeric(
                telemetry[column], errors="coerce"
            )

    if "timestamp" in telemetry.columns:
        telemetry["timestamp"] = normalize_timestamps(
            telemetry["timestamp"]
        )

    if not alerts.empty:
        if "risk_score" in alerts.columns:
            alerts["risk_score"] = pd.to_numeric(
                alerts["risk_score"], errors="coerce"
            )
        if "timestamp" in alerts.columns:
            alerts["timestamp"] = normalize_timestamps(
                alerts["timestamp"]
            )

    return telemetry, alerts, summary_data


# --------------------------------------------------
# LOAD FRESH DATA
# --------------------------------------------------

try:
    telemetry, alerts, alert_data = load_data(
        file_version(TELEMETRY_FILE),
        file_version(ALERTS_FILE),
        file_version(LIVE_ALERTS_FILE),
    )
except FileNotFoundError as error:
    st.error(f"Required data file not found: {error.filename}")
    st.info(
        "Start the MQTT consumer and simulator, then confirm "
        "that data/telemetry.csv exists."
    )
    if st.button("🔄 Retry loading data"):
        st.cache_data.clear()
        st.rerun()
    st.stop()
except (
    json.JSONDecodeError,
    pd.errors.ParserError,
    OSError,
    ValueError,
) as error:
    st.error(f"Could not load dashboard data: {error}")
    if st.button("🔄 Retry loading data"):
        st.cache_data.clear()
        st.rerun()
    st.stop()

# Preserve the manual refresh control.
if st.button("🔄 Refresh data"):
    st.cache_data.clear()
    st.rerun()

if telemetry.empty:
    st.warning("No telemetry events are available.")
    st.stop()

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
    st.error(
        "Telemetry CSV is missing columns: "
        + ", ".join(missing_columns)
    )
    st.stop()


# --------------------------------------------------
# SECURITY OVERVIEW
# --------------------------------------------------

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

col1, col2, col3, col4 = st.columns(4)
col1.metric("Telemetry Events", f"{total_events:,}")
col2.metric("Devices Monitored", f"{unique_devices:,}")
col3.metric("Security Alerts", f"{total_alerts:,}")
col4.metric("High-Priority Alerts", f"{high_alerts:,}")

live_alert_count = (
    int(alerts["alert_source"].eq("Live MQTT").sum())
    if not alerts.empty and "alert_source" in alerts.columns
    else 0
)
st.caption(
    f"Live alerts loaded: {live_alert_count} | "
    f"Average alert risk score: {average_risk:.1f}"
    if pd.notna(average_risk)
    else f"Live alerts loaded: {live_alert_count} | "
         "Average alert risk score unavailable"
)

st.divider()


# --------------------------------------------------
# TELEMETRY ACTIVITY GRAPH
# --------------------------------------------------

st.subheader("📈 Telemetry Activity")

if {"timestamp", "message_rate"}.issubset(telemetry.columns):
    activity = (
    telemetry.dropna(subset=["timestamp", "message_rate"])
    .sort_values("timestamp")
    .tail(100)
)

    if not activity.empty:
        fig = px.line(
            activity,
            x="timestamp",
            y="message_rate",
            color="device_id",
            markers=True,
            title="Message rate across telemetry events",
            labels={
                "timestamp": "Time",
                "message_rate": "Messages per interval",
                "device_id": "Device",
            },
        )
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Messages per interval",
            legend_title="Device",
        )
        st.plotly_chart(
            fig,
            use_container_width=True,
            key="telemetry_activity_chart",
        )
    else:
        st.info(
            "No valid timestamps or message-rate values are available "
            "for the activity chart."
        )
else:
    st.info("Timestamp or message-rate data is unavailable.")


# --------------------------------------------------
# SCENARIO DISTRIBUTION GRAPH
# --------------------------------------------------

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
    st.plotly_chart(
        fig,
        use_container_width=True,
        key="scenario_distribution_chart",
    )


# --------------------------------------------------
# ALERT PRIORITY GRAPH
# --------------------------------------------------

st.subheader("🚨 Alert Priority Distribution")

if not alerts.empty and "priority" in alerts.columns:
    priority_counts = (
        alerts["priority"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
        .value_counts()
        .rename_axis("Priority")
        .reset_index(name="Alerts")
    )
    fig = px.bar(
        priority_counts,
        x="Priority",
        y="Alerts",
        title="Security alerts by priority",
    )
    st.plotly_chart(
        fig,
        use_container_width=True,
        key="alert_priority_chart",
    )
else:
    st.info("No alert priority data is available yet.")

st.divider()


# --------------------------------------------------
# SECURITY ALERTS TABLE
# --------------------------------------------------

st.subheader("🚨 Security Alerts")

if alerts.empty:
    st.info("No security alerts have been saved yet.")
else:
    if "timestamp" in alerts.columns:
        alerts = alerts.sort_values(
            "timestamp",
            ascending=False,
            na_position="last",
        )

    display_columns = [
        column
        for column in (
            "timestamp",
            "device_id",
            "priority",
            "risk_score",
            "is_anomaly",
            "rule_triggered",
            "status",
            "reasons",
            "alert_source",
        )
        if column in alerts.columns
    ]

    if display_columns:
        st.dataframe(
            alerts[display_columns],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.dataframe(
            alerts,
            use_container_width=True,
            hide_index=True,
        )


# --------------------------------------------------
# DEVICE SUMMARY
# --------------------------------------------------

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
    alert_rows = alerts.dropna(subset=["device_id"])
    alert_summary = (
        alert_rows.groupby("device_id")
        .agg(Alert_Count=("device_id", "size"))
        .reset_index()
    )
    device_summary = device_summary.merge(
        alert_summary,
        on="device_id",
        how="left",
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
    "Prototype note: results use simulated telemetry and alerts "
    "saved by the detection pipeline. Dashboard refresh interval: 5 seconds."
)

st.write("Total telemetry rows:", len(telemetry))
st.write("Latest telemetry timestamp:", telemetry["timestamp"].max())
st.dataframe(telemetry.tail(5))