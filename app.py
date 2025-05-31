import streamlit as st
import cohere
import sqlite3
import re
import os
from cryptography.fernet import Fernet
from datetime import datetime

# --- Configuration ---
DB_FILE = "medical_logs.db"
KEY_FILE = "encryption.key"
COHERE_API_KEY = st.secrets.get("COHERE_API_KEY", os.environ.get("COHERE_API_KEY", "tkUV4E9TeK8SJt7SEpsEfv8QkvO2ZQTAKmnHWS64"))

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

# --- Database Utilities (UPDATED WITH SCHEMA MIGRATION) ---
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

# --- Improved Urgency Detection ---
def determine_urgency(response_text, symptoms):
    """More accurate urgency classification with symptom-based detection"""
    response_lower = response_text.lower()
    symptoms_lower = symptoms.lower()
    
    # 1. First check for explicit urgency statements in the response
    if "emergency" in response_lower and "urgency level" in response_lower:
        return "EMERGENCY"
    if "urgent" in response_lower and "urgency level" in response_lower:
        return "URGENT"
    
    # 2. Check for emergency symptoms directly
    emergency_symptoms = [
        "chest pain", "radiating", "shortness of breath", 
        "heart attack", "stroke", "aortic dissection",
        "pulmonary embolism", "unconscious", "severe pain",
        "difficulty breathing", "bloody mucus"
    ]
    if any(symptom in symptoms_lower for symptom in emergency_symptoms):
        # Verify with AI response
        if any(phrase in response_lower for phrase in ["call 911", "emergency room", "immediate attention"]):
            return "EMERGENCY"
        return "URGENT"  # Fallback to urgent if not explicitly contradicted
    
    # 3. Check for urgent symptoms
    urgent_symptoms = [
        "high fever", "blood", "vomiting", "worsening",
        "sharp pain", "cannot keep liquids down"
    ]
    if any(symptom in symptoms_lower for symptom in urgent_symptoms):
        return "URGENT"
    
    # 4. Non-urgent by default
    return "NON-URGENT"
    """More accurate urgency classification"""
    response_lower = response_text.lower()
    symptoms_lower = symptoms.lower()
    
    # 1. First check for explicit urgency statements in the response
    if "urgency level: emergency" in response_lower:
        return "EMERGENCY"
    if "urgency level: urgent" in response_lower:
        return "URGENT"
    if "urgency level: non-urgent" in response_lower:
        return "NON-URGENT"
    
    # 2. Check for emergency keywords in context
    emergency_phrases = [
        "call 911", "emergency room", "immediate medical attention",
        "heart attack", "stroke", "aortic dissection", "pulmonary embolism",
        "difficulty breathing", "unconscious", "severe pain", "chest pain radiating"
    ]
    if any(phrase in response_lower for phrase in emergency_phrases):
        return "EMERGENCY"
    
    # 3. Check for urgent keywords in context
    urgent_phrases = [
        "seek medical attention", "urgent care", "within 24 hours",
        "high fever", "bloody mucus", "persistent vomiting", "worsening symptoms",
        "sharp pain", "cannot keep liquids down"
    ]
    if any(phrase in response_lower for phrase in urgent_phrases):
        return "URGENT"
    
    # 4. Check symptom keywords with context awareness
    if any(word in symptoms_lower for word in ["chest pain", "shortness of breath", "bloody"]):
        return "URGENT"  # Not automatically emergency
    
    # 5. Non-urgent by default
    return "NON-URGENT"
# --- Streamlit App ---
st.set_page_config(
    page_title="Secure Medical Teletriage",
    page_icon="🛡️",
    layout="centered"
)

# Initialize database schema
init_db()

st.title("🏥 Secure Medical Teletriage System")
st.caption("AI-powered symptom analysis with cybersecurity monitoring")

# Initialize session state
if "messages" not in st.session_state:
    st.session_state.messages = []
if "anomaly_enabled" not in st.session_state:
    st.session_state.anomaly_enabled = True

# Sidebar configuration
with st.sidebar:
    st.header("Security Settings")
    st.session_state.anomaly_enabled = st.checkbox("Enable Anomaly Detection", value=True)

    st.divider()
    if st.button("View Security Logs"):
        st.session_state.show_logs = True
    else:
        st.session_state.show_logs = False

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
        
        # Generate medical response
        with st.chat_message("assistant"):
            with st.spinner("Analyzing symptoms..."):
                try:
                    co = cohere.Client(COHERE_API_KEY)
                    
                    # Improved prompt for better structure
                    medical_prompt = f"""As a medical expert, analyze these symptoms:
                    {prompt}
                    
                    Provide:
                    1. Top 3 possible conditions (most likely first)
                    2. Urgency level (EMERGENCY/URGENT/NON-URGENT)
                    3. Recommended next steps (concise bullet points)
                    """
                    
                    response = co.generate(
                        model="command",
                        prompt=medical_prompt,
                        max_tokens=250,  # Reduced for more concise responses
                        temperature=0.2   # Lower for more deterministic output
                    )
                    
                    full_response = response.generations[0].text
                    
                    # Use improved urgency detection
                    urgency = determine_urgency(full_response, prompt)
                    
                    # Display urgency alert
                    if urgency == "EMERGENCY":
                        st.error("🚨 EMERGENCY: REQUIRES IMMEDIATE MEDICAL ATTENTION!")
                        st.error("⚠️ CALL 911 OR GO TO NEAREST EMERGENCY ROOM IMMEDIATELY")
                    elif urgency == "URGENT":
                        st.warning("⚠️ URGENT: CONSULT HEALTHCARE PROVIDER WITHIN 24 HOURS")
                    else:
                        st.success("ℹ️ NON-URGENT: MONITOR SYMPTOMS")
                    
                    # Display the full response
                    st.markdown(full_response)
                    
                    # Add to history and database
                    assistant_message = {"role": "assistant", "content": full_response}
                    st.session_state.messages.append(assistant_message)
                    insert_message("assistant", full_response)
                    
                except Exception as e:
                    st.error(f"Error: {str(e)}")
                    st.info("Please check your Cohere API key")

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