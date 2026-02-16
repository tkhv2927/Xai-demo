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

if mode == "Scenario Simulation":
    scenario = st.sidebar.selectbox("Choose Attack Scenario:", 
        ["Normal Traffic", "DDoS Volumetric", "SQL Injection Payload"])
    
    # Set default values based on scenario
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
    scenario = "Manual"

# --- MAIN ANIMATION BUTTON ---
if st.button("🚀 INITIATE SCAN"):
    
    # 1. SCANNING ANIMATION
    with st.status("📡 INTERCEPTING NETWORK TRAFFIC...", expanded=True) as status:
        st.write(">> CAPTURING PACKET HEADERS...")
        time.sleep(0.8)
        st.write(">> NORMALIZING FEATURE VECTORS...")
        time.sleep(0.8)
        st.write(">> DEEP LEARNING MODEL INFERENCE...")
        time.sleep(0.8)
        status.update(label="✅ PACKET INTERCEPTED", state="complete", expanded=False)

    # 2. LOGIC ENGINE (Simulated AI)
    # Rules to mimic AI decision making
    risk_score = 0.1 # Default safe
    reasons = {}
    
    if p_size > 1000 and protocol == "UDP":
        risk_score = 0.95
        verdict = "MALICIOUS (DDoS)"
        reasons = {"Packet Size": 0.8, "Protocol (UDP)": 0.6, "Duration": 0.4}
        color = "red"
    elif protocol == "HTTP" and (scenario == "SQL Injection Payload" or p_size == 450):
        risk_score = 0.88
        verdict = "MALICIOUS (SQL Injection)"
        reasons = {"Payload Syntax": 0.9, "Packet Size": 0.2, "Source IP": 0.1}
        color = "red"
    else:
        verdict = "BENIGN (Safe)"
        reasons = {"Packet Size": -0.2, "Protocol": -0.1, "Source IP": -0.1}
        color = "green"

    # 3. DISPLAY RESULTS (The Dashboard)
    col1, col2 = st.columns([1, 1.5])
    
    with col1:
        st.subheader("1. AI DETECTION")
        type_text(f"VERDICT: {verdict}", speed=0.05)
        
        st.write(f"**Threat Probability:** {int(risk_score*100)}%")
        st.progress(risk_score)
        
        # Data Metrics
        st.metric("📦 Packet Size", f"{p_size} bytes")
        st.metric("🌐 Protocol", protocol)

    with col2:
        st.subheader("2. XAI EXPLANATION (SHAP)")
        st.info("Why? The chart below shows which features triggered the AI.")
        
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
            xaxis=dict(title="Feature Impact (Red=Danger, Green=Safe)"),
            margin=dict(l=0, r=0, t=0, b=0)
        )
        st.plotly_chart(fig, use_container_width=True)

    # 4. FINAL NARRATIVE
    st.divider()
    if risk_score > 0.5:
        st.error(f"❌ **SYSTEM ALERT:** This traffic was blocked mainly because **{max(reasons, key=reasons.get)}** was abnormal.")
    else:
        st.success("✅ **SYSTEM CLEAR:** Traffic patterns match normal user behavior.")

else:
    st.info("Waiting for input... Select a mode and click 'INITIATE SCAN'")
    # Background animation placeholder
    st.image("https://media.giphy.com/media/YQitE4YNQNahy/giphy.gif", caption="Network Monitoring Active", width=400)
