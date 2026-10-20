# 🛡️ Fraud Detection System

A powerful AI-powered website analysis tool that detects fraudulent websites and protects users from online scams.

## ✨ Features

- **SSL Certificate Analysis** - Validates security certificates
- **Domain Intelligence** - Checks domain age, registrar, and reputation  
- **Content Scanning** - Detects phishing keywords and suspicious patterns
- **Contact Verification** - Cross-references against known fraud database
- **AI Risk Assessment** - Powered by Google Gemini AI
- **Real-time Analysis** - Get instant fraud risk scores

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Setup Environment
Create `.env` file:
```env
GEMINI_API_KEY=your_free_gemini_api_key
SECRET_KEY=your_secret_key
```
Get your free Gemini API key at [Google AI Studio](https://aistudio.google.com/)

### 3. Setup Structure
```
FraudWebsiteDetect/
├── main.py
├── src/feature_extractor.py
├── templates/index.html
├── customer_care_db.json
└── .env
└── data.json
```

### 4. Run Application
```bash
python main.py
```

Visit `http://localhost:5000` and start analyzing websites! 🎉

## 📊 How It Works

1. **Enter URL** → System analyzes the website
2. **Multi-layer Scan** → 5 different analysis methods
3. **Risk Score** → Get 0-100 safety rating
4. **Detailed Report** → See exactly what was found
5. **Auto-Update** → Suspicious contacts added to database

## 🎯 Risk Levels

- **🟢 Low Risk (80-100)** - Safe to visit
- **🟡 Medium Risk (60-79)** - Exercise caution  
- **🟠 High Risk (40-59)** - Potentially dangerous
- **🔴 Critical Risk (0-39)** - Likely fraudulent

## 🔧 API Usage

```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## 💡 Perfect For

- **Personal Protection** - Check suspicious links before clicking
- **Business Security** - Verify vendor websites and partners
- **Educational Use** - Learn about fraud detection techniques
- **Research Projects** - Analyze web security trends

## 🆓 Cost

- **Completely Free** with Gemini's generous free tier
- Analyze ~1,500 websites daily at no cost
- No credit card required to start

---

**Stay Safe Online** 🛡️ | Built with ❤️ and Python
