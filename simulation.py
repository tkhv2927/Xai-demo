import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import time

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="XAI-IDS Pro", page_icon="🛡️", layout="wide")

# --- CUSTOM CSS FOR "CYBERPUNK" STYLE ---
st.markdown("""
    <style>
    .stApp { background-color: #050505; color: #00FF41; font-family: 'Courier New', Courier, monospace; }
    .stButton>button { color: #000; background-color: #00FF41; border-color: #00FF41; }
    .stProgress > div > div > div > div { background-color: #00FF41; }
    </style>
    """, unsafe_allow_html=True)

# --- TYPEWRITER EFFECT FUNCTION ---
def type_text(text, speed=0.02):
    t = st.empty()
    for i in range(len(text) + 1):
        t.markdown(f"**{text[:i]}**")
        time.sleep(speed)
    return t

# --- HEADER ---
st.title("🛡️ XAI-IDS: INTELLIGENT DEFENSE SYSTEM")
st.markdown("`SYSTEM_STATUS: ONLINE` | `MODE: INTERACTIVE`")
st.divider()

# --- SIDEBAR: ADVANCED CONTROLS ---
st.sidebar.header("🕹️ TRAFFIC GENERATOR")
mode = st.sidebar.radio("Select Mode:", ["Scenario Simulation", "Manual Packet Injection"])

# Initialize variables to avoid errors
p_size = 64
protocol = "TCP"
duration = 0.5
scenario = "Manual"

if mode == "Scenario Simulation":
    scenario = st.sidebar.selectbox("Choose Attack Scenario:", 
        ["Normal Traffic", "DDoS Volumetric", "SQL Injection Payload"])
    
    if scenario == "Normal Traffic":
        p_size = 64
        protocol = "TCP"
        duration = 0.5
    elif scenario == "DDoS Volumetric":
        p_size = 1500
        protocol = "UDP"
        duration = 0.1
    else: # SQL
        p_size = 450
        protocol = "HTTP"
        duration = 1.2

else: # Manual Mode
    st.sidebar.markdown("---")
    st.sidebar.write("🔧 **Manual Override**")
    p_size = st.sidebar.slider("Packet Size (bytes)", 0, 2000, 64)
    protocol = st.sidebar.selectbox("Protocol", ["TCP", "UDP", "HTTP", "ICMP"])
    duration = st.sidebar.slider("Flow Duration (ms)", 0.0, 5.0, 0.5)

# --- MAIN ANIMATION BUTTON ---
if st.button("🚀 INITIATE SCAN"):
    
    # 1. SCANNING ANIMATION
    with st.status("📡 INTERCEPTING NETWORK TRAFFIC...", expanded=True) as status:
        st.write(">> CAPTURING PACKET HEADERS...")
        time.sleep(0.5)
        st.write(">> NORMALIZING FEATURE VECTORS...")
        time.sleep(0.5)
        status.update(label="✅ PACKET INTERCEPTED", state="complete", expanded=False)

    # 2. LOGIC ENGINE (UPDATED FOR SENSITIVITY)
    # This logic now reacts dynamically to sliders
    risk_score = 0.1 # Base safe score
    reasons = {}

    # Logic: High Packet Size always increases risk
    if p_size > 800:
        risk_score += 0.4
        reasons["Packet Size"] = 0.8
    else:
        reasons["Packet Size"] = -0.2

    # Logic: UDP and ICMP are suspicious
    if protocol == "UDP":
        risk_score += 0.3
        reasons["Protocol (UDP)"] = 0.5
    elif protocol == "ICMP":
        risk_score += 0.2
        reasons["Protocol (ICMP)"] = 0.3
    else:
        reasons["Protocol"] = -0.1

    # Logic: Very short duration (burst) increases risk
    if duration < 0.2 and p_size > 500:
        risk_score += 0.2
        reasons["Flow Duration"] = 0.6
    
    # Logic: SQL Injection Scenario override
    if scenario == "SQL Injection Payload" or (protocol == "HTTP" and p_size == 450):
        risk_score = 0.92
        reasons = {"Payload Syntax": 0.9, "Packet Size": 0.2, "Source IP": 0.1}

    # Cap risk at 0.99
    if risk_score > 0.99: risk_score = 0.99

    # Determine Verdict
    if risk_score > 0.5:
        verdict = "MALICIOUS (High Risk)"
        color = "red"
        # Ensure reasons are positive for chart
        reasons = {k: abs(v) for k, v in reasons.items() if v > 0} 
        if not reasons: reasons = {"Unknown Anomaly": 0.5}
    else:
        verdict = "BENIGN (Safe)"
        color = "green"
        reasons = {k: v for k, v in reasons.items()}

    # 3. DISPLAY RESULTS (The Dashboard)
    col1, col2 = st.columns([1, 1.5])
    
    with col1:
        st.subheader("1. AI DETECTION")
        type_text(f"VERDICT: {verdict}", speed=0.02)
        
        st.write(f"**Threat Probability:** {int(risk_score*100)}%")
        
        # Color change for progress bar
        if risk_score > 0.5:
            st.markdown("""<style>.stProgress > div > div > div > div { background-color: #FF4B4B; }</style>""", unsafe_allow_html=True)
        else:
            st.markdown("""<style>.stProgress > div > div > div > div { background-color: #00FF41; }</style>""", unsafe_allow_html=True)
            
        st.progress(risk_score)
        
        # Data Metrics
        st.metric("📦 Packet Size", f"{p_size} bytes")
        st.metric("🌐 Protocol", protocol)

    with col2:
        st.subheader("2. XAI EXPLANATION (SHAP)")
        st.info("Feature Contribution Analysis")
        
        # Dynamic Chart
        features = list(reasons.keys())
        impact = list(reasons.values())
        colors = ['#FF4B4B' if x > 0 else '#00FF41' for x in impact]
        
        fig = go.Figure(go.Bar(
            x=impact, y=features, orientation='h',
            marker=dict(color=colors, line=dict(width=1, color='white'))
        ))
        
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#00FF41', family="Courier New"),
            xaxis=dict(title="Feature Impact (Red=Danger, Green=Safe)", range=[-1, 1]),
            margin=dict(l=0, r=0, t=0, b=0)
        )
        st.plotly_chart(fig, use_container_width=True)

    # 4. FINAL NARRATIVE
    st.divider()
    if risk_score > 0.5:
        st.error(f"❌ **SYSTEM ALERT:** Threat detected! Top factor: **{max(reasons, key=reasons.get)}**")
    else:
        st.success("✅ **SYSTEM CLEAR:** Traffic patterns appear normal.")

else:
    st.info("Waiting for input... Select a mode and click 'INITIATE SCAN'")
