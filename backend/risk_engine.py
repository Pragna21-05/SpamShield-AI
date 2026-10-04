"""
SpamShield AI - Risk & Explainability Analysis Engine
Integrates:
1. Multi-factor Risk Fusion (ML Model Probability + Heuristic Security Signals)
2. Risk Level Mapping (Low, Medium, High) with configurable thresholds
3. Explicit "Why was it detected?" Explainability Reasoning Generator
4. Actionable, Context-Aware Cybersecurity Safety Recommendations
"""

from typing import List, Dict, Any

def compute_risk_profile(
    ml_result: Dict[str, Any],
    heuristic_result: Dict[str, Any],
    threshold_high: int = 75,
    threshold_med: int = 40
) -> Dict[str, Any]:
    """
    Blends ML statistical confidence with deterministic security heuristics
    to calculate the unified Risk Score (0-100), Risk Level, Explainability Points,
    and Security Recommendations.
    """
    spam_prob = ml_result.get("spam_probability", 0.0)
    heur_score = heuristic_result.get("heuristic_score", 0.0)
    url_analysis = heuristic_result.get("url_analysis", {})

    # Weighted composite score: 60% Statistical ML + 40% Security Heuristics
    composite = (spam_prob * 0.60) + (heur_score * 0.40)

    # Security Floor Overrides for High-Severity Indicators
    if url_analysis.get("has_ip_url") or url_analysis.get("has_mismatched_domain"):
        composite = max(composite, 0.78)

    if heuristic_result.get("credential_count", 0) > 0 and heuristic_result.get("urgency_count", 0) > 0:
        composite = max(composite, 0.80)

    # Scale to 0-100 integer
    risk_score = int(round(min(max(composite * 100, 0), 100)))

    # Determine Risk Level based on thresholds
    if risk_score >= threshold_high:
        risk_level = "High"
        risk_label = "HIGH RISK - CRITICAL THREAT"
        risk_color = "#EF4444" # Neon Red
        status_verdict = "SPAM"
    elif risk_score >= threshold_med:
        risk_level = "Medium"
        risk_label = "MEDIUM RISK - SUSPICIOUS"
        risk_color = "#F59E0B" # Electric Gold
        # If ML is confident spam or heuristics high, flag as spam
        status_verdict = "SPAM" if (spam_prob >= 0.5 or heur_score >= 0.5) else "HAM"
    else:
        risk_level = "Low"
        risk_label = "LOW RISK - SAFE"
        risk_color = "#22C55E" # Neon Lime Green
        status_verdict = "HAM"

    # -------------------------------------------------------------
    # Explicit "Why Was It Detected?" Explanations
    # -------------------------------------------------------------
    detection_reasons = []

    # Reason: ML semantic confidence
    if spam_prob >= 0.70:
        detection_reasons.append(
            f"Machine Learning model identified high semantic similarity ({round(spam_prob*100, 1)}% probability) with documented phishing and fraud patterns."
        )
    elif spam_prob <= 0.20:
        detection_reasons.append(
            f"Machine Learning model recognized vocabulary consistent with authentic business/personal communication ({round((1-spam_prob)*100, 1)}% clean score)."
        )

    # Reason: Urgency pressure
    if heuristic_result.get("urgency_count", 0) > 0:
        terms = heuristic_result.get("urgency_terms", [])
        detection_reasons.append(
            f"Urgency density alert: Found {len(terms)} psychological coercion trigger(s) ({', '.join(terms[:3])}) designed to prompt unthinking action."
        )

    # Reason: Credential harvesting
    if heuristic_result.get("credential_count", 0) > 0:
        terms = heuristic_result.get("credential_terms", [])
        detection_reasons.append(
            f"Credential security flag: Direct solicitation of authentication secrets, OTPs, or identity verifications ({', '.join(terms[:3])})."
        )

    # Reason: Financial / Promotional lure
    if heuristic_result.get("financial_count", 0) > 0:
        terms = heuristic_result.get("financial_terms", [])
        detection_reasons.append(
            f"Financial lure detected: Presence of unsolicited monetary, prize, lottery, or cryptocurrency claims ({', '.join(terms[:3])})."
        )

    # Reason: URL anomalies
    if url_analysis.get("url_reasons"):
        for u_reason in url_analysis["url_reasons"]:
            detection_reasons.append(f"Network anomaly: {u_reason}")

    # Reason: Custom rules
    if heuristic_result.get("custom_blacklist_terms"):
        terms = heuristic_result.get("custom_blacklist_terms")
        detection_reasons.append(f"Policy violation: Matched custom blacklist keyword(s): {', '.join(terms)}")

    # Clean ham fallback
    if not detection_reasons and status_verdict == "HAM":
        detection_reasons.append("No abnormal urgency indicators, deceptive hyperlinks, or credential harvesting triggers were detected.")

    # -------------------------------------------------------------
    # Actionable Safety Recommendations
    # -------------------------------------------------------------
    recommendations = []

    if risk_level == "High":
        recommendations.append("Do not click any embedded links, buttons, or downloadable attachments.")
        if heuristic_result.get("credential_count", 0) > 0:
            recommendations.append("Never enter passwords, PINs, or share one-time authentication codes (OTPs). Official organizations will never request your OTP.")
        if url_analysis.get("has_ip_url") or url_analysis.get("has_shortener") or url_analysis.get("has_mismatched_domain"):
            recommendations.append("Destination URL appears masked or deceptive. Access your account only by typing the official company URL manually into your browser address bar.")
        recommendations.append("Flag, report, and delete this message from your inbox or messaging app to prevent accidental interaction.")
        recommendations.append("If you have already disclosed sensitive details or credentials, change passwords immediately and alert your bank's fraud desk.")

    elif risk_level == "Medium":
        recommendations.append("Treat this message with caution: inspect the sender's full email address and domain closely.")
        recommendations.append("Do not wire money or confirm personal account details through links provided in this communication.")
        recommendations.append("Hover over or inspect links without clicking to confirm that the domain corresponds with the legitimate service provider.")
        recommendations.append("When in doubt, contact the sender through a known, independent phone number or verified portal.")

    else:
        recommendations.append("This message demonstrates standard conversational patterns and contains no known phishing signatures.")
        recommendations.append("Always maintain standard vigilance: do not share private credentials or financial authentication codes.")
        recommendations.append("Ensure your multi-factor authentication (MFA/2FA) remains activated across your primary accounts.")

    return {
        "final_risk_score": risk_score,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "risk_color": risk_color,
        "status_verdict": status_verdict,
        "detection_reasons": detection_reasons,
        "recommendations": recommendations
    }
