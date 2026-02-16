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
#
                # If they type a safe string
                risk_score = 0.2
                verdict = "BENIGN (Safe Payload)"
                color = "green"
                reasons = {"Text Content": -0.5}

        # MANUAL LOGIC (From previous version)
        else:
            if p_size > 800: risk_score += 0.4; reasons["Packet Size"] = 0.8
            else: reasons["Packet Size"] = -0.2
            if protocol == "UDP": risk_score += 0.3; reasons["Protocol (UDP)"] = 0.5
            
            if risk_score > 0.99: risk_score = 0.99
            if risk_score > 0.5: verdict = "MALICIOUS"; color = "red"
            else: verdict = "BENIGN"; color = "green"
            reasons = {k: abs(v) for k, v in reasons.items() if v > 0}

        # 3. DISPLAY RESULTS
        col1, col2 = st.columns([1, 1.5])
        
        with col1:
            st.subheader("1. AI DETECTION")
            st.write(f"**VERDICT:** :{color}[{verdict}]")
            if risk_score > 0.5:
                st.markdown("""<style>.stProgress > div > div > div > div { background-color: #FF4B4B; }</style>""", unsafe_allow_html=True)
            else:
                st.markdown("""<style>.stProgress > div > div > div > div { background-color: #00FF41; }</style>""", unsafe_allow_html=True)
            st.progress(risk_score)
            
            if scenario == "Log4j":
                st.code(f"PAYLOAD: {payload_input}", language="java")

        with col2:
            st.subheader("2. XAI EXPLANATION")
            st.info("Why did the AI block this?")
            
            # Chart
            features = list(reasons.keys())
            impact = list(reasons.values())
            colors = ['#FF4B4B' if x > 0 else '#00FF41' for x in impact]
            
            fig = go.Figure(go.Bar(x=impact, y=features, orientation='h', marker=dict(color=colors)))
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#00FF41'), xaxis=dict(range=[-1, 1]),
                margin=dict(l=0, r=0, t=0, b=0)
            )
            st.plotly_chart(fig, use_container_width=True)
            
            if scenario == "Log4j" and risk_score > 0.8:
                st.error("DETECTED: The AI identified the 'jndi' command sequence as an attempt to execute remote code.")
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


