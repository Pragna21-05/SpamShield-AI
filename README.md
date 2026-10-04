# SpamShield AI — AI-Powered Spam & Phishing Detection Web Application

**SpamShield AI** is an end-to-end, fully functional cybersecurity prototype designed to detect, analyze, and explain spam, smishing, and phishing attacks across Email, SMS, and WhatsApp communications.

---

## 🚀 Key Architectural Modules

### 1. Authentication & Central Navigation
- **Analyst Session Flow**: Clean login/register modal with role assignment and avatar tracking.
- **5-Section Navigation**:
  - ⚡ **Scan Message**: Real-time message analyzer with radar scanner, circular risk gauge, in-text highlighted spans, and multi-stage pipeline transparency.
  - 📜 **Scan History**: Full historical log registry with search, status/risk/channel filtering, deep inspection modal, re-scanning, and CSV/JSON export.
  - 📈 **Risk Analytics**: Aggregate cybersecurity telemetry (Total Scans, Spam %, Ham %, High-Risk Count, Avg Confidence), 7-day timeline trends, risk severity donuts, threat vector frequency, and top trigger keywords.
  - 🛡️ **Safety Hub**: 5 comprehensive educational playbooks (Phishing red flags, Email best practices, Suspicious link safety, OTP protection, Incident recovery) and an interactive **Phishing Threat Simulator**.
  - ⚙️ **Settings**: Risk sensitivity sliders (High/Medium thresholds), model switching (Hybrid Ensemble, Multinomial Naive Bayes, Logistic Regression), and custom blacklist/whitelist keyword managers.

### 2. Text Preprocessing Pipeline
Step-by-step pipeline exposed to the UI for complete transparency:
1. **Character Cleanup & Noise Removal**: Strips invisible unicode, HTML entities, and redundant punctuation.
2. **Lowercasing**: Uniform case standardization.
3. **Word Tokenization**: Regex token segmentation preserving currency markers and key tokens.
4. **Stopword Removal**: Eliminates syntactic filler while preserving critical security markers.
5. **Stemming & Normalization**: Morphological rule conflation (Porter-style stemmer + canonical lemmatization map).

### 3. Feature Extraction & Engineering
- **TF-IDF Vectorizer**: Sublinear term frequency with smoothed inverse document frequency across unigrams and bigrams.
- **Urgency Density**: Detects psychological coercion ("act now", "within 24 hours", "immediate response").
- **Credential Harvesting**: Flags attempts to solicit passwords, PINs, OTPs, or SSNs.
- **Financial / Promotional Lures**: Flags lottery prizes, cryptocurrency airdrops, and wire transfers.
- **Suspicious URL Pattern Analyzer**:
  - Direct IP-based host URLs (e.g. `http://192.168.1.1/...`).
  - Known URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`).
  - High-risk / disposable TLDs (`.xyz`, `.top`, `.buzz`, `.club`, etc.).
  - Domain spoofing (claims to be PayPal/Amazon/Chase but links to an unverified domain).

### 4. ML Classification & Inference
- **Multinomial Naive Bayes**: Laplace-smoothed prior and feature log-likelihoods.
- **Regularized Logistic Regression**: Vectorized gradient descent with L2 regularization.
- **Hybrid Ensemble**: Blends generative and discriminative models for high generalization accuracy.
- **Feature Importance**: Isolates top contributing TF-IDF terms for each prediction.

### 5. Risk & Explainability Analysis
- **Composite Risk Score (0-100%)**: Fuses statistical ML confidence with heuristic security triggers.
- **Risk Level**:
  - 🟢 **Low Risk (0-39%)**: Clean Ham.
  - 🟡 **Medium Risk (40-74%)**: Suspicious Caution.
  - 🔴 **High Risk (75-100%)**: Critical Threat / Spam.
- **Explainability**: Plain-English "Why Was It Detected?" reasons.
- **Actionable Safety Recommendations**: Context-aware defense advice based on detected attack vectors.

### 6. SQLite Persistence & Analytics
- Stored locally in `spamshield.db`.
- Pre-seeded with realistic baseline telemetry for immediate graphical visualization.

---

## 🏃‍♂️ How to Run Locally

```bash
# 1. Start the FastAPI Application Server
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000

# 2. Open in your browser
http://127.0.0.1:8000
```
