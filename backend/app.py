"""
SpamShield AI - FastAPI Application Server
Provides REST APIs for:
1. Live Scanning Pipeline (Preprocessing -> Heuristics -> ML Inference -> Explainability)
2. History Management (Search, Multi-Filter, Delete, Export, Report)
3. Security Analytics (Aggregate KPIs, Risk Distributions, 7-Day Trends)
4. System Settings (Thresholds, Blacklists/Whitelists, Model Switching)
5. Test Sample Presets for One-Click Evaluation
6. User Authentication Sessions
7. Static UI Delivery
"""

import os
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.preprocessor import run_preprocessing_pipeline
from backend.heuristics import extract_heuristic_features
from backend.ml_engine import ml_engine
from backend.risk_engine import compute_risk_profile
from backend.storage import (
    init_db,
    save_scan_result,
    get_scans,
    get_scan_by_id,
    delete_scan,
    toggle_report_status,
    get_analytics_metrics,
    get_settings,
    update_settings,
    reset_database
)
from .supabase_client import supabase

# Initialize database on startup
init_db()

app = FastAPI(
    title="SpamShield AI - Defense API",
    description="Next-Generation AI & Heuristic Powered Spam & Phishing Detection Platform",
    version="1.0.0"
)
@app.get("/test-supabase")
def test_supabase():
    response = (
        supabase
        .table("scan_history")
        .select("*")
        .limit(5)
        .execute()
    )

    return {
        "success": True,
        "data": response.data
    }

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------
# Request & Response Schemas
# -------------------------------------------------------------
class ScanRequest(BaseModel):
    message_text: str = Field(..., description="Message/Email body text to scan")
    sender: Optional[str] = Field(default="", description="Sender email, phone, or name")
    subject: Optional[str] = Field(default="", description="Subject line if email")
    link_url: Optional[str] = Field(default="", description="Optional direct URL or link")
    source: Optional[str] = Field(default="Email", description="Email, SMS, or WhatsApp")
    model_name: Optional[str] = Field(default=None, description="naive_bayes, logistic_regression, or ensemble")
    save_to_history: Optional[bool] = Field(default=True, description="Whether to record into history")

class SettingsRequest(BaseModel):
    threshold_high: int = Field(default=75, ge=50, le=95)
    threshold_med: int = Field(default=40, ge=15, le=60)
    active_model: str = Field(default="ensemble")
    custom_blacklist: List[str] = Field(default_factory=list)
    custom_whitelist: List[str] = Field(default_factory=list)

class AuthRequest(BaseModel):
    username: str
    password: str

class ReportRequest(BaseModel):
    report_type: str = Field(..., description="'false_positive' or 'missed_spam'")

# -------------------------------------------------------------
# API Endpoints
# -------------------------------------------------------------
@app.post("/api/scan")
async def scan_message(req: ScanRequest):
    """
    Executes the complete SpamShield AI pipeline:
    1. Preprocessing (5-step transformation)
    2. Heuristic extraction (Urgency, Credentials, URLs, Financial)
    3. Machine Learning inference (TF-IDF vectorization & classification)
    4. Multi-factor Risk Fusion & Explainability derivation
    5. Automatic history persistence
    """
    if not req.message_text.strip():
        raise HTTPException(status_code=400, detail="Message text cannot be empty.")

    # 1. Fetch current settings for custom blacklist/whitelist and thresholds
    settings = get_settings()
    model_to_use = req.model_name or settings["active_model"]

    # 2. Step 1-5: Text Preprocessing Pipeline
    prep_result = run_preprocessing_pipeline(req.message_text)

    # 3. Domain Heuristics & Pattern Analysis
    heuristic_result = extract_heuristic_features(
        text=req.message_text,
        sender=req.sender or "",
        subject=req.subject or "",
        dedicated_url=req.link_url or "",
        custom_blacklist=settings.get("custom_blacklist", []),
        custom_whitelist=settings.get("custom_whitelist", [])
    )

    # 4. Machine Learning Inference & TF-IDF Extraction
    ml_result = ml_engine.predict(
        normalized_tokens=prep_result["normalized_tokens"],
        model_name=model_to_use
    )

    # 5. Risk & Explainability Analysis
    risk_result = compute_risk_profile(
        ml_result=ml_result,
        heuristic_result=heuristic_result,
        threshold_high=settings.get("threshold_high", 75),
        threshold_med=settings.get("threshold_med", 40)
    )

    # 6. Assemble Highlighted Text for frontend UI
    # Build text markup showing matched spans
    full_text = f"{req.subject + ' - ' if req.subject else ''}{req.message_text}"
    
    # 7. Persist to History if requested
    saved_scan_id = None
    if req.save_to_history:
        # Collect matched keywords
        all_kws = (
            heuristic_result.get("urgency_terms", []) +
            heuristic_result.get("credential_terms", []) +
            heuristic_result.get("financial_terms", []) +
            heuristic_result.get("custom_blacklist_terms", [])
        )
        saved_scan_id = save_scan_result({
            "message_text": req.message_text,
            "sender": req.sender or "Unknown Sender",
            "subject": req.subject or "No Subject",
            "source": req.source or "Email",
            "link_url": req.link_url or "",
            "result": risk_result["status_verdict"],
            "risk_level": risk_result["risk_level"],
            "risk_score": risk_result["final_risk_score"],
            "confidence_pct": ml_result["confidence_pct"],
            "model_used": ml_result["model_used"],
            "detection_reasons": risk_result["detection_reasons"],
            "recommendations": risk_result["recommendations"],
            "matched_keywords": list(set(all_kws)),
            "url_flags": heuristic_result.get("url_analysis", {}).get("url_reasons", [])
        })

    return {
        "verdict": risk_result["status_verdict"],
        "is_spam": risk_result["status_verdict"] == "SPAM",
        "risk_level": risk_result["risk_level"],
        "risk_score": risk_result["final_risk_score"],
        "risk_label": risk_result["risk_label"],
        "risk_color": risk_result["risk_color"],
        "confidence_pct": ml_result["confidence_pct"],
        "model_used": ml_result["model_used"],
        "spam_probability": ml_result["spam_probability"],
        "ham_probability": ml_result["ham_probability"],
        "saved_scan_id": saved_scan_id,
        "preprocessing_pipeline": {
            "steps": prep_result["steps"],
            "tokens_count": len(prep_result["raw_tokens"]),
            "normalized_features_count": len(prep_result["normalized_tokens"]),
            "processed_preview": prep_result["processed_text"]
        },
        "heuristics": {
            "heuristic_score": heuristic_result["heuristic_score"],
            "suspicious_keyword_count": heuristic_result["suspicious_keyword_count"],
            "urgency_count": heuristic_result["urgency_count"],
            "credential_count": heuristic_result["credential_count"],
            "financial_count": heuristic_result["financial_count"],
            "urgency_terms": heuristic_result["urgency_terms"],
            "credential_terms": heuristic_result["credential_terms"],
            "financial_terms": heuristic_result["financial_terms"],
            "url_analysis": heuristic_result["url_analysis"],
            "highlight_spans": heuristic_result["highlight_spans"]
        },
        "ml_explainability": {
            "top_features": ml_result["top_features"],
            "active_tfidf_terms": ml_result["active_tfidf_terms"]
        },
        "explainability": {
            "detection_reasons": risk_result["detection_reasons"],
            "recommendations": risk_result["recommendations"]
        }
    }

@app.get("/api/scans")
async def list_scans(
    search: Optional[str] = Query(default=""),
    status: Optional[str] = Query(default="ALL"),
    risk: Optional[str] = Query(default="ALL"),
    source: Optional[str] = Query(default="ALL"),
    limit: Optional[int] = Query(default=50),
    offset: Optional[int] = Query(default=0)
):
    """Lists saved scan records with search and multi-facet filtering."""
    scans = get_scans(
        search_query=search or "",
        status_filter=status or "ALL",
        risk_filter=risk or "ALL",
        source_filter=source or "ALL",
        limit=limit or 50,
        offset=offset or 0
    )
    return {"scans": scans, "count": len(scans)}

@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: int):
    """Retrieves deep inspection payload for a single scan."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return scan

@app.delete("/api/scans/{scan_id}")
async def remove_scan(scan_id: int):
    """Deletes a scan entry from history."""
    success = delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found or already deleted.")
    return {"success": True, "message": f"Scan #{scan_id} successfully deleted."}

@app.post("/api/scans/{scan_id}/report")
async def report_scan(scan_id: int, req: ReportRequest):
    """Reports a scan as false positive or missed spam."""
    success = toggle_report_status(scan_id, req.report_type)
    if not success:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return {"success": True, "message": f"Scan reported as {req.report_type}."}

@app.get("/api/analytics")
async def analytics_dashboard():
    """Returns comprehensive security metrics, 7-day timelines, and risk distributions."""
    return get_analytics_metrics()

@app.get("/api/settings")
async def read_settings():
    """Retrieves user sensitivity thresholds, model preference, and custom rule keywords."""
    return get_settings()

@app.put("/api/settings")
async def save_settings(req: SettingsRequest):
    """Updates user sensitivity thresholds and custom keywords."""
    update_settings(
        threshold_high=req.threshold_high,
        threshold_med=req.threshold_med,
        active_model=req.active_model,
        custom_blacklist=req.custom_blacklist,
        custom_whitelist=req.custom_whitelist
    )
    return {"success": True, "message": "Settings updated successfully."}

@app.post("/api/settings/reset")
async def reset_system_history():
    """Clears history and re-seeds baseline analytics."""
    reset_database()
    return {"success": True, "message": "Database and analytics reseeded to defaults."}

@app.get("/api/samples")
async def get_sample_messages():
    """Provides high-fidelity realistic presets for instant testing across channels."""
    return [
        {
            "id": "bank_phish",
            "title": "Chase Bank Wire Alert",
            "source": "Email",
            "sender": "security-alert@chase-verify-portal.top",
            "subject": "CRITICAL: Unauthorized Wire Transfer Detected",
            "link_url": "http://192.168.1.100/chase-login",
            "text": "Dear Chase customer: An unauthorized wire transfer of $4,920.00 was attempted from your savings account. Act now within 24 hours to cancel this transaction. Verify your identity and update password immediately at our secure server: http://192.168.1.100/chase-login"
        },
        {
            "id": "usps_smishing",
            "title": "USPS Package Delivery SMS",
            "source": "SMS",
            "sender": "+1 (888) 492-0193",
            "subject": "SMS Notification",
            "link_url": "http://bit.ly/usps-package-resolve",
            "text": "USPS Alert: Your shipment #US98213-98 could not be delivered due to incomplete street number. Click here within 12 hours to confirm your address and pay $1.50 redelivery fee: http://bit.ly/usps-package-resolve"
        },
        {
            "id": "whatsapp_job",
            "title": "WhatsApp Crypto Job Scam",
            "source": "WhatsApp",
            "sender": "+44 7700 900142",
            "subject": "Direct Message",
            "link_url": "https://wa.me/447700900142",
            "text": "Congratulations! You have been selected for our daily remote work program. Earn $350-$600 every day by reviewing online products on your phone. Daily Bitcoin payouts guaranteed. Send your full name, bank details, and verification code to claim bonus immediately."
        },
        {
            "id": "netflix_billing",
            "title": "Netflix Account Suspended",
            "source": "Email",
            "sender": "billing-support@netflix-renew.buzz",
            "subject": "Important: Your Membership is on Hold",
            "link_url": "http://netflix-renew.buzz/secure-billing",
            "text": "Your Netflix membership cannot be renewed because your current payment method was declined. Update your credit card and CVV immediately within 24 hours or your streaming profile will be permanently closed: http://netflix-renew.buzz/secure-billing"
        },
        {
            "id": "legit_sprint",
            "title": "Sprint Review Notes (Ham)",
            "source": "Email",
            "sender": "david.chen@enterprise.com",
            "subject": "Sprint 48 Retrospective & Roadmap Notes",
            "link_url": "https://jira.enterprise.com/board/48",
            "text": "Hi team, thanks everyone for joining today's sprint retro. Overall velocity was up 15% and all Q3 milestones are on track. Please check the linked Jira dashboard to verify your assigned tickets before our standup tomorrow morning."
        },
        {
            "id": "legit_2fa",
            "title": "Official 2FA Security Code (Ham)",
            "source": "SMS",
            "sender": "GOOGLE-AUTH (22000)",
            "subject": "2FA Security Code",
            "link_url": "",
            "text": "G-492817 is your Google verification code. Do not share this code with anyone. Google employees will never call to ask for this code."
        }
    ]

@app.post("/api/auth/login")
async def user_login(req: AuthRequest):
    """Simple authentication flow with session token simulation."""
    # Allows standard demo credentials or any test account
    return {
        "success": True,
        "token": "token_session_spamshield_" + req.username,
        "user": {
            "username": req.username,
            "role": "Cybersecurity Analyst",
            "avatar": req.username[:2].upper() if req.username else "SA",
            "email": f"{req.username}@spamshield.ai"
        }
    }

@app.post("/api/auth/register")
async def user_register(req: AuthRequest):
    """Registers a new user session."""
    return {
        "success": True,
        "token": "token_session_spamshield_" + req.username,
        "user": {
            "username": req.username,
            "role": "Security Specialist",
            "avatar": req.username[:2].upper() if req.username else "UN",
            "email": f"{req.username}@spamshield.ai"
        }
    }

# -------------------------------------------------------------
# Static Frontend Files Mount
# -------------------------------------------------------------
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "static")

if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"status": "SpamShield AI Backend active. Static index.html pending."})
