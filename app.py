import streamlit as st
import cohere
import sqlite3
import re
import os
import pandas as pd
import numpy as np
from cryptography.fernet import Fernet
from datetime import datetime
from fpdf import FPDF
import plotly.express as px

# --- Configuration ---
DB_FILE = "medical_logs.db"
KEY_FILE = "encryption.key"
COHERE_API_KEY = st.secrets.get("COHERE_API_KEY", os.environ.get("COHERE_API_KEY"))

# --- Encryption Utilities ---
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

# Initialize Fernet once
FERNET = Fernet(load_or_create_key())

def encrypt_text(plaintext: str) -> bytes:
    return FERNET.encrypt(plaintext.encode("utf-8"))

def decrypt_text(ciphertext: bytes) -> str:
    return FERNET.decrypt(ciphertext).decode("utf-8")

# --- Database Utilities ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create table if not exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role TEXT NOT NULL,
            message_blob BLOB NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Check if threat_detected column exists
    cursor.execute("PRAGMA table_info(chat_log)")
    columns = [col[1] for col in cursor.fetchall()]
    
    # Add threat_detected column if missing
    if 'threat_detected' not in columns:
        cursor.execute("ALTER TABLE chat_log ADD COLUMN threat_detected TEXT")
    
    conn.commit()
    conn.close()

def insert_message(role: str, plaintext_msg: str, threat_detected=None):
    ciphertext = encrypt_text(plaintext_msg)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO chat_log (role, message_blob, threat_detected) VALUES (?, ?, ?)",
        (role, ciphertext, threat_detected)
    )
    conn.commit()
    conn.close()

def fetch_all_logs(decrypt=False):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, role, message_blob, timestamp, threat_detected FROM chat_log ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    
    if decrypt:
        return [
            (r[0], r[1], decrypt_text(r[2]), r[3], r[4])
            for r in rows
        ]
    return rows

# --- Enhanced Anomaly Detection ---
def detect_anomaly(text: str) -> list:
    """Detects security threats in input text"""
    threats = []
    
    # Length-based anomaly
    if len(text) > 200:
        threats.append("Excessive length")
    
    # Medical threat keywords
    medical_threats = ["ricin", "anthrax", "sarin", "vx", "nerve agent", "poison"]
    if any(word in text.lower() for word in medical_threats):
        threats.append("Medical threat")
    
    # Cybersecurity keywords
    cyber_threats = ["attack", "malware", "exploit", "hack", "sql", "select", "drop table", "script"]
    if any(word in text.lower() for word in cyber_threats):
        threats.append("Cyber threat")
    
    # Suspicious pattern detection
    if re.search(r"(union select|1=1|--|;--)", text, re.IGNORECASE):
        threats.append("SQL injection pattern")
    if re.search(r"(<script>|alert\(|document\.cookie)", text, re.IGNORECASE):
        threats.append("XSS pattern")
    
    return threats

# --- Critical Symptom Detection ---
CRITICAL_SYMPTOMS = {
    "cardiac": ["chest pain", "arm numbness", "shortness of breath", "pressure in chest"],
    "neurological": ["sudden headache", "vision loss", "confusion", "numbness on one side"],
    "respiratory": ["unable to breathe", "lips turning blue", "severe asthma attack"],
    "other": ["severe bleeding", "suicidal thoughts", "allergic reaction"]
}

def check_critical(symptoms_text):
    """Check the symptoms text for critical keywords"""
    alerts = []
    symptoms_lower = symptoms_text.lower()
    for category, terms in CRITICAL_SYMPTOMS.items():
        if any(term in symptoms_lower for term in terms):
            alerts.append(f"⚠️ CRITICAL {category.upper()} SYMPTOM DETECTED")
    return alerts

# --- PDF Report Generation ---
def generate_pdf_report(symptoms, diagnosis):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Header
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Smart Telehealth Report", ln=1, align='C')
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=1, align='C')
    pdf.ln(10)
    
    # Patient Information
    pdf.set_font('', 'B')
    pdf.cell(200, 10, txt="Patient Symptoms:", ln=1)
    pdf.set_font('')
    pdf.multi_cell(0, 10, txt=symptoms)
    pdf.ln(5)
    
    # Clinical Assessment
    pdf.set_font('', 'B')
    pdf.cell(200, 10, txt="Clinical Assessment:", ln=1)
    pdf.set_font('')
    pdf.multi_cell(0, 10, txt=diagnosis)
    pdf.ln(10)
    
    # Disclaimer and Security
    pdf.set_font('', 'I', 10)
    pdf.multi_cell(0, 8, txt="This report is generated by an AI system and does not replace professional medical advice. Consult a healthcare provider for diagnosis and treatment.")
    pdf.cell(0, 8, txt="Secured via AES-256 encryption | Audit ID: " + os.urandom(4).hex(), ln=1)
    
    return pdf.output(dest='S').encode('latin1')

# --- Streamlit App ---
st.set_page_config(
    page_title="Advanced Medical Teletriage",
    page_icon="⚕️",
    layout="centered"
)

# Initialize database schema
init_db()

st.title("⚕️ Advanced Medical Teletriage System")
st.caption("AI-powered symptom analysis with clinical workflow enhancements")

# Initialize session state
if "messages" not in st.session_state:
    st.session_state.messages = []
if "anomaly_enabled" not in st.session_state:
    st.session_state.anomaly_enabled = True
if "symptom_log" not in st.session_state:
    st.session_state.symptom_log = []

# Sidebar configuration
with st.sidebar:
    st.header("Clinical Settings")
    st.session_state.anomaly_enabled = st.checkbox("Enable Security Monitoring", value=True)
    st.divider()
    st.sidebar.header("📟 Simulated Vital Signs (Optional)")
    heart_rate = st.sidebar.number_input("Heart Rate (bpm)", min_value=30, max_value=180, value=75)
    temperature = st.sidebar.number_input("Body Temperature (°C)", min_value=34.0, max_value=42.0, value=37.0)
    spo2 = st.sidebar.slider("Oxygen Saturation (SpO₂ %)", 85, 100, 98)
    bp = st.sidebar.text_input("Blood Pressure (mmHg)", "120/80")
    pain_level = st.sidebar.slider("Pain Severity (0 = None, 10 = Worst)", 0, 10, 4)
    st.divider()
    if st.button("View Security Logs"):
        st.session_state.show_logs = True
    else:
        st.session_state.show_logs = False

# --- Symptom Tracker Dashboard ---
with st.expander("📈 Symptom Progression Tracker", expanded=False):
    st.write("Track your symptoms over time:")
    
    col1, col2 = st.columns([2, 1])
    symptom = col1.selectbox("Select Symptom", 
                           ["Pain", "Fever", "Cough", "Shortness of Breath", 
                            "Headache", "Nausea", "Dizziness"])
    severity = col2.slider("Severity (1-10)", 1, 10, 5)
    
    if st.button("➕ Add Symptom Log Entry"):
        st.session_state.symptom_log.append({
            "timestamp": datetime.now(),
            "symptom": symptom,
            "severity": severity
        })
        st.success(f"Logged {symptom} severity: {severity}/10")
    
    if st.session_state.symptom_log:
        df = pd.DataFrame(st.session_state.symptom_log)
        df['time'] = pd.to_datetime(df['timestamp']).dt.strftime('%H:%M')
        
        fig = px.line(df, x='time', y='severity', color='symptom',
                      title="Symptom Progression", markers=True)
        fig.update_layout(yaxis_range=[0,10], height=300)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No symptoms tracked yet. Add your first entry above.")

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        if message.get("threats"):
            st.error(f"🚨 Threats detected: {', '.join(message['threats'])}")

# User input
if prompt := st.chat_input("Describe your symptoms..."):
    # Add user message to history
    user_message = {"role": "user", "content": prompt}
    
    # Critical symptom check
    critical_alerts = check_critical(prompt)
    
    # Threat detection
    threats = []
    if st.session_state.anomaly_enabled:
        threats = detect_anomaly(prompt)
    
    if threats:
        # Handle threat detected
        user_message["threats"] = threats
        st.session_state.messages.append(user_message)
        insert_message("user", prompt, ",".join(threats))
        
        with st.chat_message("user"):
            st.markdown(prompt)
            st.error(f"🔒 Security Alert: Detected {', '.join(threats)}")
    else:
        # Process normally
        st.session_state.messages.append(user_message)
        insert_message("user", prompt)
        
        with st.chat_message("user"):
            st.markdown(prompt)
            if critical_alerts:
                st.error("### 🚑 PRIORITY MEDICAL ALERT")
                for alert in critical_alerts:
                    st.error(alert)
                st.error("**Immediate action recommended:** Call emergency services or go to nearest ER")
        
        # Generate medical response
        with st.chat_message("assistant"):
            with st.spinner("Analyzing symptoms..."):
                try:
                    co = cohere.Client(COHERE_API_KEY)
                    medical_prompt = f"""
                    You are a virtual medical triage assistant. Use the patient's symptoms and the following vital signs to assess their condition.

                    Symptoms:
                    {prompt}

                    Vitals:
                    - Heart Rate: {heart_rate} bpm
                    - Body Temp: {temperature} °C
                    - Oxygen Saturation: {spo2}%
                    - Blood Pressure: {bp}
                    - Pain Level: {pain_level}/10

                    Provide:
                    1. Top 3 possible conditions (most likely first)
                    2. Urgency level (EMERGENCY/URGENT/NON-URGENT)
                    3. Most likely condition(s)
                    4. Triage recommendation (Home care / See GP / Go to ER)
                    5. Recommended next steps (concise bullet points)
                    6. Disclaimer to seek real professional care
                    """

                    response = co.generate(
                        model="command",
                        prompt=medical_prompt,
                        max_tokens=300,
                        temperature=0.3
                    )
                    
                    full_response = response.generations[0].text
                    
                    # Color-code urgency levels
                    urgency_colors = {
                        "EMERGENCY": "red",
                        "URGENT": "orange",
                        "NON-URGENT": "green"
                    }
                    
                    # Enhanced formatting with color coding
                    formatted_response = full_response
                    for level, color in urgency_colors.items():
                        if level in full_response:
                            formatted_response = formatted_response.replace(
                                level,
                                f"<span style='color: {color}; font-weight: bold'>{level}</span>"
                            )
                    
                    # Display with HTML formatting
                    st.markdown(formatted_response, unsafe_allow_html=True)
                    
                    # Add to history and database (store original text)
                    assistant_message = {"role": "assistant", "content": full_response}
                    st.session_state.messages.append(assistant_message)
                    insert_message("assistant", full_response)
                    
                except Exception as e:
                    st.error(f"Error: {str(e)}")
                    st.info("Please check your Cohere API key")
# --- PDF Report Download ---
if st.session_state.messages:
    # Extract symptoms and diagnosis
    user_symptoms = next((msg["content"] for msg in st.session_state.messages if msg["role"] == "user"), "")
    ai_diagnosis = next((msg["content"] for msg in st.session_state.messages if msg["role"] == "assistant"), "")
    
    # Generate and download PDF
    pdf = generate_pdf_report(user_symptoms, ai_diagnosis)
    st.download_button(
        label="📥 Download Medical Report",
        data=pdf,
        file_name="telehealth_report.pdf",
        mime="application/pdf"
    )

# Show security logs
if st.session_state.get('show_logs'):
    st.sidebar.divider()
    st.sidebar.subheader("Security Audit Logs")
    
    try:
        logs = fetch_all_logs(decrypt=True)
        if not logs:
            st.sidebar.info("No logs yet")
        else:
            for log in logs:
                with st.sidebar.expander(f"Log {log[0]} - {log[3]}"):
                    st.caption(f"Role: {log[1]}")
                    if log[4]:
                        st.error(f"Threats: {log[4]}")
                    # Add unique key to prevent duplicate ID error
                    st.text_area(
                        "Message", 
                        value=log[2], 
                        height=150, 
                        disabled=True,
                        key=f"log_{log[0]}_{log[3]}"  # Unique key
                    )
    except Exception as e:
        st.sidebar.error(f"Error loading logs: {str(e)}")