import os
import sys
import base64
import logging
import requests
import joblib
import pandas as pd
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Local imports - ensuring they work regardless of how script is called
try:
    from .utils import extract_features, is_globally_trusted, detect_clone
    from .scanner import get_domain_info
except ImportError:
    from utils import extract_features, is_globally_trusted, detect_clone
    from scanner import get_domain_info

load_dotenv()

# Logging Configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SpecterScan Supreme")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Model State
rf_model = None
xgb_model = None
FEATURE_NAMES = None

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = (BASE_DIR / "models") # Adjust this if models are one level up
RF_PATH = MODEL_DIR / "phishing_random_forest.joblib"
XGB_PATH = MODEL_DIR / "phishing_xgboost.joblib"

def load_models():
    global rf_model, xgb_model, FEATURE_NAMES
    try:
        if RF_PATH.exists():
            rf_model = joblib.load(RF_PATH)
            logger.info(f"✅ RF Model Loaded: {RF_PATH}")
        if XGB_PATH.exists():
            xgb_model = joblib.load(XGB_PATH)
            logger.info(f"✅ XGB Model Loaded: {XGB_PATH}")

        # Safe Feature Name extraction (Fixes the ValueError: ambiguous truth value)
        rf_f = getattr(rf_model, "feature_names_in_", None)
        xgb_f = getattr(xgb_model, "feature_names_in_", None)
        
        if rf_f is not None:
            FEATURE_NAMES = rf_f
        elif xgb_f is not None:
            FEATURE_NAMES = xgb_f
        else:
            FEATURE_NAMES = [f"f{i}" for i in range(30)]
            
    except Exception as e:
        logger.error(f"❌ Critical Model Load Error: {e}")

load_models()

VT_KEY = os.getenv("VT_API_KEY")

class URLRequest(BaseModel):
    url: str

def check_virustotal(url: str) -> int:
    """Returns the number of malicious hits from VT."""
    if not VT_KEY or VT_KEY == "your_actual_api_key_here":
        return 0
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    except Exception:
        return 0
    return 0

@app.post("/predict")
async def predict(request: URLRequest):
    if rf_model is None or xgb_model is None:
        raise HTTPException(status_code=503, detail="Models not loaded")

    url = request.url.lower().strip()
    
    # 1. Gather Intelligence
    impersonated = detect_clone(url)   # NEW: Checks for g00gle.com etc.
    is_trusted = is_globally_trusted(url)
    live = get_domain_info(url)
    vt_hits = check_virustotal(url)

    # 2. AI Inference
    feat = extract_features(url)
    df = pd.DataFrame([feat], columns=FEATURE_NAMES)
    
    rf_prob = rf_model.predict_proba(df)[0][1]
    xgb_prob = xgb_model.predict_proba(df)[0][1]
    ai_prob = (rf_prob + xgb_prob) / 2.0

    # 3. SUPREME DECISION ENGINE (The "Law")
    is_phishing = False
    verdict = "Legitimate"
    risk_level = "Low"
    final_score = ai_prob

    # PRIORITY 1: VirusTotal (External Threat Intel)
    if vt_hits >= 1:
        verdict = f"Phishing (Flagged by {vt_hits} Security Engines)"
        is_phishing = True
        risk_level = "High"

    # PRIORITY 2: Clone Detection (Visual Similarity)
    elif impersonated:
        verdict = f"Phishing (Cloned {impersonated} Site Detected)"
        is_phishing = True
        risk_level = "High"

    # PRIORITY 3: Global Reputation Override
    elif is_trusted and vt_hits == 0:
        verdict = "Legitimate (Official Verified Domain)"
        is_phishing = False
        final_score = 0.01 # Force UI to show 1%

    # PRIORITY 4: Domain Age & SSL Logic
    elif live.get("age_days", 0) > 365 and live.get("is_ssl", False) and vt_hits == 0:
        verdict = "Legitimate (Established Site)"
        is_phishing = False
        final_score = ai_prob * 0.1 # Scale down AI suspicion

    # PRIORITY 5: AI Pattern Match
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
            "virus_total_hits": vt_hits,
        },
        "security_report": {
            "domain_age": f"{live.get('age_days', 0)} days",
            "ssl_active": live.get("is_ssl", False),
            "registrar": live.get("registrar", "Unknown"),
            "impersonating": impersonated
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

    