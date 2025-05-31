# Secure Medical Teletriage System

An AI-powered telehealth application that provides immediate symptom analysis and care recommendations while ensuring data privacy and system integrity.

## Features

- **AI Symptom Analysis**: Natural language processing of patient symptoms
- **Care Prioritization**: Urgency-based recommendations (Emergency/Urgent/Non-urgent)
- **Privacy-First Approach**: Secure handling of sensitive medical data
- **Interactive Interface**: User-friendly chat-based experience

## Research Alignment

This project implements techniques inspired by cutting-edge research in:
- Telehealth systems
- Medical AI applications
- Secure data processing
- Anomaly detection in sensitive environments

## Setup Instructions

1. Clone repository:
2. git clone https://github.com/wasif350/teletriage-system.git
3. cd teletriage-system
4. Install dependencies:
   pip install -r requirements.txt

## Set Cohere API key:

# Linux/Mac
- export COHERE_API_KEY='your_api_key_here'
# Windows (Command Prompt)
- set COHERE_API_KEY='your_api_key_here'


## Run the application:

- streamlit run app.py

## Usage

1. Describe your symptoms in the chat interface
2. Receive AI-powered medical assessment
3. Follow recommended next steps based on urgency level


## Technology Stack

1. AI Engine: Cohere Medical LLM
2. Frontend: Streamlit
3. Data Security: Fernet Encryption
4. Database: SQLite with HIPAA-compliant logging
