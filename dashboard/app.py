
import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(
    page_title="TrustLens AI",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ TrustLens AI")
st.subheader("Context-Aware IoT Threat Detection")
st.caption("Prototype dashboard • Sample data only")

# Illustrative data until the team modules are connected
devices = pd.DataFrame([
    {
        "Device ID": "CAM-001",
        "Device Type": "Smart Camera",
        "Status": "Online",
        "Messages/min": 24,
        "Failed Logins": 0,
        "Risk": "Normal",
    },
    {
        "Device ID": "SNS-002",
        "Device Type": "Room Sensor",
        "Status": "Online",
        "Messages/min": 31,
        "Failed Logins": 1,
        "Risk": "Review",
    },
    {
        "Device ID": "CTL-003",
        "Device Type": "Smart Controller",
        "Status": "Online",
        "Messages/min": 180,
        "Failed Logins": 12,
        "Risk": "High",
    },
    {
        "Device ID": "LGT-004",
        "Device Type": "Smart Light",
        "Status": "Online",
        "Messages/min": 18,
        "Failed Logins": 0,
        "Risk": "Normal",
    },
    {
        "Device ID": "SNS-005",
        "Device Type": "Temperature Sensor",
        "Status": "Offline",
        "Messages/min": 0,
        "Failed Logins": 0,
        "Risk": "Offline",
    },
])

# Summary metrics
total = len(devices)
online = int((devices["Status"] == "Online").sum())
high_risk = int((devices["Risk"] == "High").sum())
needs_review = int((devices["Risk"] == "Review").sum())

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Devices", total)
c2.metric("Online Devices", online)
c3.metric("High-Risk Devices", high_risk)
c4.metric("Needs Review", needs_review)

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Device Message Activity")
    fig = px.bar(
        devices,
        x="Device ID",
        y="Messages/min",
        color="Risk",
        title="Messages per minute",
    )
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Risk Distribution")
    risk_counts = (
        devices["Risk"]
        .value_counts()
        .rename_axis("Risk")
        .reset_index(name="Devices")
    )
    fig = px.pie(
        risk_counts,
        names="Risk",
        values="Devices",
        title="Devices by current risk label",
        hole=0.4,
    )
    st.plotly_chart(fig, use_container_width=True)

st.divider()

st.subheader("IoT Device Monitor")
risk_filter = st.selectbox(
    "Filter by risk",
    ["All", "Normal", "Review", "High", "Offline"],
)

visible = devices.copy()
if risk_filter != "All":
    visible = visible[visible["Risk"] == risk_filter]

st.dataframe(visible, use_container_width=True, hide_index=True)

st.subheader("Security Incident Preview")

st.warning(
    "HIGH RISK — CTL-003 has unusually high message activity "
    "and multiple failed logins in this illustrative dataset."
)
st.info(
    "REVIEW — SNS-002 has a failed login event. "
    "Investigate alongside other telemetry before classifying it as an attack."
)

st.caption(
    "Demo limitation: these are manually defined sample records, "
    "not live IoT telemetry or actual AI predictions. "
    "The team will connect the simulator and detection engine later."
)
