# SpecterScan – Phishing Detection Browser Extension

A browser extension that detects phishing and malicious websites in real-time using 
machine learning and threat intelligence APIs (VirusTotal, Google Safe Browsing, WHOIS).


## 🚀 Demo

- Detects phishing sites instantly
- Shows risk level (Low / Medium / High)
- Displays security insights (domain age, SSL, etc.)


## 🛠 Tech Stack

- Backend: FastAPI (Python)
- ML Models: Random Forest, XGBoost
- APIs: VirusTotal, Google Safe Browsing, WHOIS
- Extension: JavaScript (Manifest V3)
- Deployment: Render


## ✨ Features

- Real-time phishing detection
- AI-based URL analysis
- Clone/impersonation detection
- Domain intelligence (WHOIS, SSL, age)
- External threat validation (VirusTotal)
- Secure backend with rate limiting & API protection


![Demo](assets/image.png)


## 🧠 Architecture

Browser Extension → FastAPI Backend → Threat Intelligence APIs

- Extension sends URL
- Backend analyzes using ML + APIs
- Returns risk score and verdict

## ⚙️ Installation

1. Download the extension folder
2. Open chrome://extensions/ or edge://extensions/
3. Enable Developer Mode
4. Click "Load unpacked"
5. Select the folder

## 🔌 API

POST /predict

Request:
{
  "url": "example.com"
}

Response:
- verdict
- risk level
- AI score
- threat intelligence data

## 🎯 Why this project?

Phishing attacks are increasing rapidly. This project combines machine learning and real-world threat intelligence to provide practical, real-time protection inside the browser.


## 🔒 Security

- API keys stored securely in backend
- Rate limiting implemented
- Token-based request validation
- No sensitive data exposed to client


## 📌 Future Improvements

- Smarter API usage optimization
- User-based rate limiting
- Improved UI/UX
- Chrome Web Store deployment