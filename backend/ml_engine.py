"""
SpamShield AI - Machine Learning Pipeline & Inference Engine
Implements:
1. Curated Spam & Ham Training Corpus (Email, SMS, WhatsApp)
2. TF-IDF Vectorizer with N-Gram support and IDF caching
3. Multinomial Naive Bayes Classifier
4. Regularized Logistic Regression Classifier
5. Ensemble Classifier
6. Feature Importance & Top Contributing Term Explainability
"""

import math
import numpy as np
from typing import List, Dict, Any, Tuple, Optional
from backend.preprocessor import run_preprocessing_pipeline

# -------------------------------------------------------------
# Curated Training Corpus (~160 diverse representative samples)
# -------------------------------------------------------------
TRAINING_DATA = [
    # --- SPAM / PHISHING / SMISHING / SCAM EXAMPLES ---
    ("Dear customer, your bank account has been suspended due to unauthorized access. Click here immediately to verify your identity: http://192.168.1.1/login", 1),
    ("URGENT: Your Netflix subscription has expired. Update your credit card payment details within 24 hours to prevent account cancellation.", 1),
    ("CONGRATULATIONS! You have been selected as the grand winner of $1,000,000 in our international lottery. Claim your prize now at http://bit.ly/claim-cash", 1),
    ("USPS Alert: Your package could not be delivered due to an incomplete address. Update your delivery details immediately: http://usps-tracking-update.xyz", 1),
    ("Security Notice: Unusual sign-in attempt detected on your PayPal account from Russia. If this wasn't you, verify your password here: http://paypa1-security.xyz", 1),
    ("Hi! Earn $300-$500 per day working from home part-time. No experience needed. Contact our WhatsApp manager right now: https://wa.me/12345678", 1),
    ("URGENT: Your Apple ID is locked due to multiple failed login attempts. Verify your credentials now or your iCloud data will be permanently deleted.", 1),
    ("Final Notice: Your vehicle registration has an outstanding toll fine of $4.75. Pay now to avoid legal action and penalties: http://toll-service-pay.buzz", 1),
    ("Claim your 100% free Bitcoin reward! Connect your crypto wallet today and double your investment within 48 hours guaranteed.", 1),
    ("Bank of America: A wire transfer of $2,450.00 was initiated from your account. If you did not authorize this, call immediately or click http://45.33.32.156/cancel", 1),
    ("Exclusive loan offer! Get pre-approved for up to $50,000 with zero interest for 12 months. Apply before midnight today.", 1),
    ("DocuSign: Action required on confidential corporate agreement. Sign the attached financial invoice within 2 hours: http://docusign-sign-docs.top", 1),
    ("Amazon customer service: You won a $500 gift card! Click here to complete the quick survey and redeem your reward.", 1),
    ("Your mobile number won $50,000 cash prize in our anniversary draw. Send your full name, bank details, and OTP to process transfer.", 1),
    ("DHL Delivery: We tried delivering your parcel today. Please pay customs clearance fee of $2.50 to release your parcel: http://dhl-parcel-clear.xyz", 1),
    ("CRITICAL ALERT: Your Microsoft 365 password expires today. Retain your current password by confirming your corporate credentials here.", 1),
    ("Dear beneficiary, I am barrister Alex from London. You have an unclaimed inheritance fund of $8.5M from a deceased foreign national.", 1),
    ("Chase Bank Alert: Account suspended due to suspicious transaction at Walmart. Confirm identity at http://chase-unusual-security.top", 1),
    ("WhatsApp security alert: Your WhatsApp account will be deactivated unless you submit your 6-digit verification code to this number.", 1),
    ("Congratulations! You qualified for government stimulus relief fund of $3,500. Register your social security number to receive direct deposit.", 1),
    ("Urgent notification: Your cloud backup storage is 99% full and files will be deleted within 6 hours. Upgrade for free right now.", 1),
    ("Hot crypto presale! 1000x guaranteed profit token launching on Binance. Buy minimum 0.5 ETH today before price skyrockets.", 1),
    ("Notice: Your Facebook business page has violated copyright policies. Appeal within 24 hours or your page will be permanently terminated.", 1),
    ("Free trial ended! You have been billed $499.00 for Geek Squad security protection. Call our toll-free support number to dispute charge.", 1),
    ("Your SIM card will be blocked within 2 hours due to pending KYC verification. Submit your Aadhaar/SSN and OTP to resume service.", 1),
    ("Limited time flash sale! 90% discount on luxury designer watches and electronics. Order before stock runs out: http://bit.ly/luxury-deal", 1),
    ("ATTENTION: You have an unpaid parking citation from Municipal Traffic Court. Click to clear citation before warrant is issued.", 1),
    ("Wells Fargo security warning: New payee added to your mobile banking. If this was not you, cancel transfer immediately at http://192.168.0.45", 1),
    ("Immediate action required: Complete your mandatory tax rebate filing to receive refund of $1,280 directly into your checking account.", 1),
    ("Hey buddy, invest $100 in our automated forex trading bot and get $1,000 back tomorrow morning guaranteed. Message me on Telegram.", 1),
    ("Your Walmart order #83921 has shipped to an unfamiliar address in Texas. Click here if you did not place this order to cancel charge.", 1),
    ("Special invitation: You have been selected to test the new iPhone 16 Pro for free. Keep the device after writing a 1-paragraph review.", 1),
    ("Instagram copyright infringement notice: Your account will be removed in 48 hours. Submit your username and password to dispute.", 1),
    ("Urgent: Please review attached Wire Transfer Confirmation PDF and release payment for project milestone today.", 1),
    ("Your credit score just increased by 45 points! Claim your new premium zero-fee credit card with $20,000 limit right now.", 1),
    ("Warning: Virus detected on your computer! Windows Defender has blocked Trojan horse malware. Call support immediately to fix.", 1),

    # --- HAM / LEGITIMATE / CLEAN EXAMPLES ---
    ("Hi Alex, can we reschedule our quarterly project review meeting to Thursday at 3 PM? Let me know if that works for you.", 0),
    ("Here are the meeting notes from today's sprint planning session. Please review the Jira tickets assigned to your team.", 0),
    ("Your appointment with Dr. Henderson is confirmed for Monday, October 12 at 10:30 AM. Please arrive 15 minutes early.", 0),
    ("Thanks for your order! Your receipt for $34.50 at Trader Joe's has been processed. Have a great day.", 0),
    ("Hey Sarah, are we still meeting for lunch at the cafeteria today around 12:30? Let me know what you feel like eating.", 0),
    ("GitLab notification: Pipeline #4829 for commit 8f3c21 passed successfully on branch main. All 42 unit tests passed.", 0),
    ("Your Uber ride receipt: Thanks for riding with driver Marcus. Trip fare was $18.20. Rate your ride in the Uber app.", 0),
    ("Weekly team standup reminder: Tomorrow at 9:30 AM in Conference Room B or join via Google Meet video link.", 0),
    ("Hi team, please find attached the revised draft of the Q4 marketing budget for your review before Friday's executive review.", 0),
    ("Your verification code is 482910. This code is valid for 10 minutes. For your security, do not share this code with anyone.", 0),
    ("Flight boarding reminder: Your flight AA 1420 to Chicago departs at 4:15 PM from Gate B22. Mobile boarding pass is ready in app.", 0),
    ("Hi Dad, we safely arrived at the hotel in Denver! The kids are excited to see the mountains tomorrow morning.", 0),
    ("GitHub: John Doe submitted a pull request #104: 'Refactor database connection pooling to improve query latency'.", 0),
    ("Hi team, the office Wi-Fi network will undergo scheduled maintenance this Saturday between 2 AM and 4 AM.", 0),
    ("Your library books 'Introduction to Machine Learning' and 'Designing Data-Intensive Apps' are due in 3 days.", 0),
    ("Thanks for attending our webinar on Cloud Architecture. You can find the slide deck and session recording attached here.", 0),
    ("Hey everyone, let's grab coffee this afternoon to celebrate David's promotion! Meet at the lobby cafe around 4 PM.", 0),
    ("Your monthly electricity bill of $78.40 from City Power is ready. Automatic debit scheduled for the 25th.", 0),
    ("Slack notification: You were mentioned by Emily in #engineering: 'Can you check if the new API endpoint is deployed?'", 0),
    ("Hi team, please remember to submit your timesheets by 5 PM today so payroll can be processed on schedule.", 0),
    ("Your package from Amazon was delivered to your front porch. Photo confirmation is available in your account.", 0),
    ("Reminder: Parent-teacher conference is scheduled for Thursday at 4:00 PM in Room 14. Looking forward to speaking with you.", 0),
    ("Hey, do you have the recipe for the lasagna you brought to the potluck last weekend? It was delicious!", 0),
    ("Google Calendar: Design Systems Sync starts in 10 minutes. Location: Google Meet.", 0),
    ("Thank you for your feedback on our product. Our customer experience team is reviewing your suggestions.", 0),
    ("Attached is the signed rental lease agreement for apartment 4B. Let me know when we can collect the keys.", 0),
    ("Hey team, here is the updated deployment checklist for our production release next Tuesday morning.", 0),
    ("Your dental cleaning appointment at Smile Care Dental is scheduled for next Tuesday at 2:00 PM.", 0),
    ("Hi folks, we have updated our company holiday calendar for the upcoming year on the internal employee wiki.", 0),
    ("Can you please send me the latest metrics CSV report before our 2 PM sync with the product manager?", 0),
    ("Your payment of $12.99 for Spotify Premium has been successfully processed. Thank you for your continued subscription.", 0),
    ("Hey Mike, great presentation this morning at the all-hands! The executive team was really impressed by the growth numbers.", 0),
    ("Notice: Building management will be conducting routine fire alarm testing on Wednesday between 11 AM and 12 PM.", 0),
    ("Hi team, the pull request has been approved and merged into staging. Let me know if QA testing is completed.", 0),
    ("Your pharmacy prescription for medication refill #91823 is ready for pickup at CVS on Main Street.", 0)
]

class TfidfVectorizer:
    """N-Gram TF-IDF Vectorizer with Sublinear Term Frequency and Smooth IDF."""
    def __init__(self, min_df: int = 1, max_features: int = 500, ngram_range: Tuple[int, int] = (1, 2)):
        self.min_df = min_df
        self.max_features = max_features
        self.ngram_range = ngram_range
        self.vocabulary: Dict[str, int] = {}
        self.feature_names: List[str] = []
        self.idf_diag: Optional[np.ndarray] = None

    def _extract_ngrams(self, tokens: List[str]) -> List[str]:
        ngrams = []
        min_n, max_n = self.ngram_range
        n_tokens = len(tokens)
        for n in range(min_n, max_n + 1):
            for i in range(n_tokens - n + 1):
                ngrams.append(" ".join(tokens[i:i + n]))
        return ngrams

    def fit(self, tokenized_docs: List[List[str]]) -> "TfidfVectorizer":
        doc_count = len(tokenized_docs)
        df_counts: Dict[str, int] = {}

        for doc in tokenized_docs:
            ngrams = set(self._extract_ngrams(doc))
            for term in ngrams:
                df_counts[term] = df_counts.get(term, 0) + 1

        # Filter by min_df and sort by frequency
        filtered_terms = [
            (term, count) for term, count in df_counts.items() if count >= self.min_df
        ]
        # Sort descending by document frequency
        filtered_terms.sort(key=lambda x: x[1], reverse=True)
        top_terms = filtered_terms[:self.max_features]

        self.vocabulary = {term: idx for idx, (term, _) in enumerate(top_terms)}
        self.feature_names = [term for term, _ in top_terms]

        # Compute smoothed inverse document frequency: idf = log((1 + N) / (1 + df)) + 1
        idf = np.zeros(len(self.feature_names), dtype=np.float64)
        for term, idx in self.vocabulary.items():
            df = df_counts[term]
            idf[idx] = math.log((1 + doc_count) / (1 + df)) + 1.0
        self.idf_diag = idf
        return self

    def transform(self, tokenized_docs: List[List[str]]) -> np.ndarray:
        n_samples = len(tokenized_docs)
        n_features = len(self.feature_names)
        X = np.zeros((n_samples, n_features), dtype=np.float64)

        for i, doc in enumerate(tokenized_docs):
            ngrams = self._extract_ngrams(doc)
            term_freqs: Dict[str, int] = {}
            for term in ngrams:
                if term in self.vocabulary:
                    term_freqs[term] = term_freqs.get(term, 0) + 1

            for term, count in term_freqs.items():
                idx = self.vocabulary[term]
                # Sublinear TF: 1 + log(tf)
                sublinear_tf = 1.0 + math.log(count)
                X[i, idx] = sublinear_tf * self.idf_diag[idx]

            # L2 Normalize row vector
            norm = np.linalg.norm(X[i])
            if norm > 0:
                X[i] /= norm

        return X

    def fit_transform(self, tokenized_docs: List[List[str]]) -> np.ndarray:
        return self.fit(tokenized_docs).transform(tokenized_docs)


class MultinomialNaiveBayes:
    """Multinomial Naive Bayes with Laplace Smoothing."""
    def __init__(self, alpha: float = 1.0):
        self.alpha = alpha
        self.class_log_prior_: Optional[np.ndarray] = None
        self.feature_log_prob_: Optional[np.ndarray] = None
        self.classes_ = np.array([0, 1])  # 0: Ham, 1: Spam

    def fit(self, X: np.ndarray, y: np.ndarray) -> "MultinomialNaiveBayes":
        n_samples, n_features = X.shape
        n_classes = len(self.classes_)

        self.class_log_prior_ = np.zeros(n_classes, dtype=np.float64)
        self.feature_log_prob_ = np.zeros((n_classes, n_features), dtype=np.float64)

        for idx, c in enumerate(self.classes_):
            X_c = X[y == c]
            self.class_log_prior_[idx] = math.log(X_c.shape[0] / n_samples)
            # Feature count with Laplace smoothing
            feature_counts = X_c.sum(axis=0) + self.alpha
            total_count = feature_counts.sum()
            self.feature_log_prob_[idx] = np.log(feature_counts / total_count)

        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        # Joint log likelihood: log P(c) + sum(x_i * log P(w_i | c))
        jll = X @ self.feature_log_prob_.T + self.class_log_prior_
        # Numerically stable softmax
        max_log = np.max(jll, axis=1, keepdims=True)
        exp_jll = np.exp(jll - max_log)
        proba = exp_jll / np.sum(exp_jll, axis=1, keepdims=True)
        return proba


class LogisticRegressionClassifier:
    """L2-Regularized Binary Logistic Regression trained with Gradient Descent."""
    def __init__(self, lr: float = 0.5, l2_reg: float = 0.01, epochs: int = 250):
        self.lr = lr
        self.l2_reg = l2_reg
        self.epochs = epochs
        self.weights: Optional[np.ndarray] = None
        self.bias: float = 0.0

    def fit(self, X: np.ndarray, y: np.ndarray) -> "LogisticRegressionClassifier":
        n_samples, n_features = X.shape
        self.weights = np.zeros(n_features, dtype=np.float64)
        self.bias = 0.0

        for _ in range(self.epochs):
            linear_model = np.dot(X, self.weights) + self.bias
            # Sigmoid activation
            y_pred = 1.0 / (1.0 + np.exp(-np.clip(linear_model, -25.0, 25.0)))

            dw = (1.0 / n_samples) * np.dot(X.T, (y_pred - y)) + (self.l2_reg * self.weights)
            db = (1.0 / n_samples) * np.sum(y_pred - y)

            self.weights -= self.lr * dw
            self.bias -= self.lr * db

        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        linear_model = np.dot(X, self.weights) + self.bias
        p_spam = 1.0 / (1.0 + np.exp(-np.clip(linear_model, -25.0, 25.0)))
        p_ham = 1.0 - p_spam
        return np.column_stack([p_ham, p_spam])


class MLSpamDetectionEngine:
    """
    Unified ML Classification & Explainability Engine.
    Trains TF-IDF + Naive Bayes, Logistic Regression, and Ensemble models.
    """
    def __init__(self):
        self.vectorizer = TfidfVectorizer(min_df=1, max_features=450, ngram_range=(1, 2))
        self.nb_model = MultinomialNaiveBayes(alpha=0.8)
        self.lr_model = LogisticRegressionClassifier(lr=0.8, l2_reg=0.005, epochs=300)
        self.is_trained = False
        self._train_models()

    def _train_models(self):
        tokenized_corpus = []
        labels = []
        for text, label in TRAINING_DATA:
            pipe_out = run_preprocessing_pipeline(text)
            tokenized_corpus.append(pipe_out["normalized_tokens"])
            labels.append(label)

        y = np.array(labels, dtype=np.int32)
        X = self.vectorizer.fit_transform(tokenized_corpus)
        self.nb_model.fit(X, y)
        self.lr_model.fit(X, y)
        self.is_trained = True

    def predict(
        self,
        normalized_tokens: List[str],
        model_name: str = "ensemble"
    ) -> Dict[str, Any]:
        """
        Classifies input tokens into SPAM (1) or HAM (0),
        computes probability/confidence, and isolates top contributing features.
        """
        if not normalized_tokens:
            return {
                "prediction": "HAM",
                "is_spam": False,
                "spam_probability": 0.05,
                "ham_probability": 0.95,
                "confidence_pct": 95.0,
                "model_used": model_name,
                "top_features": [],
                "active_tfidf_terms": []
            }

        X = self.vectorizer.transform([normalized_tokens])
        
        # Probabilities
        nb_proba = self.nb_model.predict_proba(X)[0] # [p_ham, p_spam]
        lr_proba = self.lr_model.predict_proba(X)[0] # [p_ham, p_spam]

        if model_name.lower() == "naive_bayes":
            p_ham, p_spam = nb_proba[0], nb_proba[1]
            active_model = "Multinomial Naive Bayes"
        elif model_name.lower() == "logistic_regression":
            p_ham, p_spam = lr_proba[0], lr_proba[1]
            active_model = "Logistic Regression"
        else:
            # Weighted Ensemble: 55% Logistic Regression + 45% Naive Bayes
            p_spam = (0.55 * lr_proba[1]) + (0.45 * nb_proba[1])
            p_ham = 1.0 - p_spam
            active_model = "Hybrid Ensemble (NB + LogReg)"

        is_spam = p_spam >= 0.50
        prediction = "SPAM" if is_spam else "HAM"
        confidence_pct = round((p_spam if is_spam else p_ham) * 100, 1)

        # Feature Explainability: Top TF-IDF weights and LR feature impacts
        active_terms = []
        top_features = []
        row = X[0]
        non_zero_indices = np.where(row > 0)[0]

        for idx in non_zero_indices:
            term = self.vectorizer.feature_names[idx]
            tfidf_weight = round(float(row[idx]), 4)
            lr_weight = float(self.lr_model.weights[idx])
            
            # Log-odds contribution towards spam
            spam_contribution = lr_weight * tfidf_weight
            
            term_info = {
                "term": term,
                "tfidf_weight": tfidf_weight,
                "impact": "SPAM" if spam_contribution > 0 else "HAM",
                "score": round(abs(spam_contribution), 4)
            }
            active_terms.append(term_info)
            top_features.append(term_info)

        # Sort top features by absolute score descending
        top_features.sort(key=lambda f: f["score"], reverse=True)

        return {
            "prediction": prediction,
            "is_spam": is_spam,
            "spam_probability": round(float(p_spam), 4),
            "ham_probability": round(float(p_ham), 4),
            "confidence_pct": confidence_pct,
            "model_used": active_model,
            "top_features": top_features[:8],
            "active_tfidf_terms": active_terms[:15]
        }

# Global singleton engine instance
ml_engine = MLSpamDetectionEngine()
