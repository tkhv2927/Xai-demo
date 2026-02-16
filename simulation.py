import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import time

# --- PAGE SETUP ---
st.set_page_config(page_title="XAI-IDS Live Demo", page_icon="🛡️", layout="wide")

# --- HACKER STYLE CSS ---
st.markdown("""
    <style>
    .stApp { background-color: #0E1117; color: #FFFFFF; }
    .stHeader { color: #00FF00; }
    div.stButton > button { background-color: #00FF00; color: black; border-radius: 5px; }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER ---
st.title("🛡️ XAI-IDS: Transparency Engine")
st.markdown("### `System Status: ONLINE` | `Monitoring: UNSW-NB15 Stream`")
st.divider()

# --- SIDEBAR ---
st.sidebar.header("🕹️ Simulation Controls")
scenario = st.sidebar.selectbox("Select Attack Scenario:", 
    ["Normal Traffic (Safe)", "DDoS Attack (Volume)", "SQL Injection (Payload)"])

if st.sidebar.button("🚀 Analyze Packet"):
    
    # --- SIMULATION LOGIC ---
    with st.spinner("Intercepting Packet... Decrypting Headers..."):
        time.sleep(1.5) # Dramatic pause for effect

    # COLUMNS FOR DASHBOARD
    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("1. Detection (The Black Box)")
        
        if scenario == "Normal Traffic (Safe)":
            risk = 0.12
            status = "BENIGN"
            color = "green"
            # SHAP Values (Green = Safe)
            shap_data = {"Packet Size": -0.4, "Source IP": -0.2, "Protocol": -0.1, "Time": 0.1}
            reason = "Traffic patterns match authorized user behavior."
            
        elif scenario == "DDoS Attack (Volume)":
            risk = 0.98
            status = "MALICIOUS"
            color = "red"
            # SHAP Values (Red = Danger)
            shap_data = {"Packet Size": 0.85, "Flow Duration": 0.78, "Protocol (UDP)": 0.45, "TTL": 0.12}
            reason = "High Volume & Packet Size indicates Denial of Service attempt."

        elif scenario == "SQL Injection (Payload)":
            risk = 0.94
            status = "MALICIOUS"
            color = "red"
            # SHAP Values
            shap_data = {"Payload Content": 0.92, "Special Chars": 0.88, "Source IP": 0.20, "Time": 0.05}
            reason = "Malicious syntax detected in payload field."

        # DISPLAY BLACK BOX RESULT
        st.markdown(f"**AI Verdict:** :{color}[{status}]")
        st.progress(risk, text=f"Threat Probability: {int(risk*100)}%")
    
    with col2:
        st.subheader("2. XAI Explanation (Why?)")
        st.info(f"📝 **Analyst Summary:** {reason}")
        
        # PLOTLY CHART (THE COOL PART)
        features = list(shap_data.keys())
        impact = list(shap_data.values())
        colors = ['#FF4B4B' if x > 0 else '#00FF00' for x in impact]
        
        fig = go.Figure(go.Bar(
            x=impact, y=features, orientation='h',
            marker=dict(color=colors)
        ))
        fig.update_layout(
            title="SHAP Feature Contribution (Red = Suspicious, Green = Safe)",
            plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        st.plotly_chart(fig, use_container_width=True)

else:
    st.info("👈 Select a scenario from the sidebar and click 'Analyze Packet' to start.")
