# import os
# import joblib
# import pandas as pd
# import requests
# import base64
# import logging
# from fastapi import FastAPI, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from dotenv import load_dotenv
# from urllib.parse import urlparse

# # Local Imports
# from utils import extract_features
# from scanner import get_domain_info

# # Setup
# load_dotenv()
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)
# app = FastAPI(title="SpecterScan Supreme")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # Load AI
# try:
#     rf_model = joblib.load("models/phishing_random_forest.joblib")
#     xgb_model = joblib.load("models/phishing_xgboost.joblib")
#     FEATURE_NAMES = rf_model.feature_names_in_
#     logger.info("AI Models loaded successfully.")
# except Exception as e:
#     logger.error(f"Model Loading Error: {e}")

# VT_KEY = os.getenv("VT_API_KEY")

# # Root domains of major tech giants that are ALWAYS safe at the domain level
# TRUSTED_DOMAINS = ["google.com", "youtube.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com", "chatgpt.com", "openai.com", "github.com"]

# class URLRequest(BaseModel):
#     url: str

# # --- API HELPER: VirusTotal ---
# def check_virustotal(url):
#     if not VT_KEY or VT_KEY == "your_actual_api_key_here":
#         return {"malicious": 0}
#     try:
#         # Base64 encode the URL for VT API v3
#         url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
#         headers = {"x-apikey": VT_KEY}
#         response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        
#         if response.status_code == 200:
#             return response.json()['data']['attributes']['last_analysis_stats']
#         return {"malicious": 0}
#     except Exception as e:
#         logger.error(f"VT API Error: {e}")
#         return {"malicious": 0}

# @app.post("/predict")
# async def predict(request: URLRequest):
#     url = request.url.lower().strip()
#     parsed = urlparse(url if "://" in url else f"http://{url}")
#     domain = parsed.netloc.replace("www.", "")
    
#     # 1. LIVE DATA (WHOIS & SSL)
#     live = get_domain_info(url)
    
#     # 2. API CHECK (Global Blacklist)
#     vt_stats = check_virustotal(url)
#     vt_hits = vt_stats.get("malicious", 0)

#     # 3. AI SCAN (Pattern Recognition)
#     feat = extract_features(url)
#     df = pd.DataFrame([feat], columns=FEATURE_NAMES)
#     ai_prob = (rf_model.predict_proba(df)[0][1] + xgb_model.predict_proba(df)[0][1]) / 2

#     # 4. SUPREME VOTING LOGIC
#     is_phishing = False
#     verdict = "Legitimate"
#     risk_level = "Low"
#     final_confidence = ai_prob

#     # --- THE SUPREME OVERRIDE ---
    
#     # RULE 1: VirusTotal Blacklist is the highest priority
#     if vt_hits > 1:
#         verdict = "Phishing (Blacklisted by Security Engines)"
#         is_phishing = True
#         risk_level = "High"
    
#     # RULE 2: Infrastructure Trust (Corporate Whitelist & Registrar Check)
#     # If VT is clean AND (Domain is in hardcoded list OR WHOIS says it's old OR it has a Verified Registrar)
#     elif vt_hits == 0 and (domain in TRUSTED_DOMAINS or live["age_days"] >= 365 or "Verified" in str(live.get("registrar", ""))):
#         verdict = "Legitimate (Verified Trusted Domain)"
#         is_phishing = False
#         risk_level = "Low"
#         final_confidence = ai_prob * 0.01  # Suppress the AI suspicion score
    
#     # RULE 3: High AI Suspicion on unknown/new domains
#     elif ai_prob > 0.75:
#         verdict = "Phishing (AI Pattern Match)"
#         is_phishing = True
#         risk_level = "High"
            
#     # RULE 4: Moderate Suspicion
#     elif ai_prob > 0.4:
#         verdict = "Suspicious (Unusual URL Pattern)"
#         risk_level = "Medium"

#     return {
#         "url": url,
#         "verdict": verdict,
#         "is_phishing": is_phishing,
#         "risk_level": risk_level,
#         "scores": {
#             "ai_certainty": f"{round(final_confidence * 100, 1)}%",
#             "virus_total_hits": vt_hits
#         },
#         "security_report": {
#             "domain": live.get("domain", domain),
#             "domain_age": f"{live['age_days']} days",
#             "ssl_active": live["is_ssl"],
#             "registrar": live["registrar"]
#         }
#     }


import os
import joblib
import pandas as pd
import requests
import base64
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from urllib.parse import urlparse

# Local Project Imports
# Ensure 'is_globally_trusted' is defined in your utils.py
from utils import extract_features, is_globally_trusted
from scanner import get_domain_info

# Initial Setup
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SpecterScan Supreme")

# Enable communication between Chrome Extension and Python Backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load AI Models (Random Forest & XGBoost Ensemble)
try:
    rf_model = joblib.load("models/phishing_random_forest.joblib")
    xgb_model = joblib.load("models/phishing_xgboost.joblib")
    FEATURE_NAMES = rf_model.feature_names_in_
    logger.info("✅ AI Models and Feature Names loaded successfully.")
except Exception as e:
    logger.error(f"❌ Model Loading Error: {e}")

# Securely grab the API Key from your .env file
VT_KEY = os.getenv("VT_API_KEY")

class URLRequest(BaseModel):
    url: str

# --- API HELPER: VirusTotal v3 ---
def check_virustotal(url):
    if not VT_KEY:
        logger.warning("⚠️ VT_API_KEY not found in .env. Skipping API check.")
        return {"malicious": 0}
    try:
        # Base64 encode URL for VirusTotal v3 requirement
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats']
        return {"malicious": 0}
    except Exception as e:
        logger.error(f"VT API Error: {e}")
        return {"malicious": 0}

@app.post("/predict")
async def predict(request: URLRequest):
    url = request.url.lower().strip()
    
    # 1. REPUTATION LAYER (Prevents AI false positives on famous sites)
    # This checks the Top 1M list and hardcoded safe domains
    is_trusted = is_globally_trusted(url)
    
    # 2. LIVE INTEL (WHOIS & SSL data)
    # 'live' should contain 'age_days', 'is_ssl', 'registrar', etc.
    live = get_domain_info(url)
    
    # 3. THREAT INTEL (VirusTotal API)
    vt_stats = check_virustotal(url)
    vt_hits = vt_stats.get("malicious", 0)

    # 4. AI ENSEMBLE SCAN
    feat = extract_features(url)
    df = pd.DataFrame([feat], columns=FEATURE_NAMES)
    
    # Average the probability between both models for a balanced verdict
    rf_prob = rf_model.predict_proba(df)[0][1]
    xgb_prob = xgb_model.predict_proba(df)[0][1]
    ai_prob = (rf_prob + xgb_prob) / 2

    # --- THE SUPREME VOTING ENGINE ---
    is_phishing = False
    verdict = "Legitimate"
    risk_level = "Low"
    final_score = ai_prob

    # VETO 1: VirusTotal Blacklist (Highest Priority)
    if vt_hits >= 1:
        verdict = "Phishing (Confirmed by Threat Intelligence)"
        is_phishing = True
        risk_level = "High"
    
    # VETO 2: Global Trust Override (Whitelist/Top 1M/Popular Domains)
    elif is_trusted and vt_hits == 0:
        verdict = "Legitimate (Verified High-Reputation Domain)"
        is_phishing = False
        risk_level = "Low"
        final_score = 0.01  # Suppress AI score for UI display
        
    # VETO 3: Established Domain Check (Age > 1 Year and SSL Active)
    elif live.get("age_days", 0) > 365 and live.get("is_ssl", False) and vt_hits == 0:
        verdict = "Legitimate (Established Official Site)"
        is_phishing = False
        risk_level = "Low"
        # If AI is still suspicious, we scale it way down because safe sites often look "busy"
        final_score = ai_prob * 0.1 
        
    # LOGIC 4: Catching New Threats (New site + High AI suspicion)
    elif ai_prob > 0.75:
        verdict = "Phishing (AI Pattern Match)"
        is_phishing = True
        risk_level = "High"
            
    elif ai_prob > 0.4:
        verdict = "Suspicious (Unusual URL Pattern)"
        risk_level = "Medium"

    return {
        "url": url,
        "verdict": verdict,
        "is_phishing": is_phishing,
        "risk_level": risk_level,
        "scores": {
            "ai_certainty": f"{round(final_score * 100, 1)}%",
            "virus_total_hits": vt_hits
        },
        "security_report": {
            "domain_age": f"{live.get('age_days', 'Unknown')} days",
            "ssl_active": live.get("is_ssl", False),
            "registrar": live.get("registrar", "Unknown"),
            "globally_ranked": is_trusted
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)