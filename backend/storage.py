"""
SpamShield AI - SQLite Persistence & Security Analytics Storage Engine
Handles:
1. User Authentication Store
2. Scan History Logs Store with full query filtering
3. User Settings & Custom Keyword Rule persistence
4. Real-time Aggregate Security Analytics computation
5. Automatic historical seed generation for immediate visualization
"""

import sqlite3
import json
import os
import datetime
from typing import List, Dict, Any, Optional
from .supabase_client import supabase
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "spamshield.db")
if os.environ.get("VERCEL"): DB_PATH = "/tmp/spamshield.db"

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes tables and seeds initial realistic history if empty."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            avatar_initials TEXT DEFAULT 'SU',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            sender TEXT,
            subject TEXT,
            source TEXT NOT NULL,
            message_text TEXT NOT NULL,
            snippet TEXT NOT NULL,
            link_url TEXT,
            result TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            confidence_pct REAL NOT NULL,
            model_used TEXT NOT NULL,
            detection_reasons TEXT NOT NULL,
            recommendations TEXT NOT NULL,
            matched_keywords TEXT NOT NULL,
            url_flags TEXT,
            reported_status TEXT DEFAULT 'none'
        )
    """)

    # Settings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY,
            threshold_high INTEGER DEFAULT 75,
            threshold_med INTEGER DEFAULT 40,
            active_model TEXT DEFAULT 'ensemble',
            custom_blacklist TEXT DEFAULT '["urgent wire", "crypto gift", "unclaimed prize"]',
            custom_whitelist TEXT DEFAULT '["meeting agenda", "doctor appointment", "jira"]'
        )
    """)

    # Check if settings row exists
    cursor.execute("SELECT id FROM settings WHERE id = 1")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO settings (id) VALUES (1)")

    # Check if default user exists
    cursor.execute("SELECT id FROM users WHERE username = 'security_analyst'")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, avatar_initials)
            VALUES ('security_analyst', 'analyst@spamshield.ai', 'sha256_mock_hash_123', 'SA')
        """)

    # Check if scans exist; if not, seed realistic historical scans
    cursor.execute("SELECT COUNT(*) as cnt FROM scans")
    count = cursor.fetchone()["cnt"]

    if count == 0:
        _seed_initial_history(cursor)

    conn.commit()
    conn.close()

def _seed_initial_history(cursor: sqlite3.Cursor):
    """Populates realistic past scans across the last 6 days for analytics visualization."""
    now = datetime.datetime.now()

    sample_scans = [
        {
            "days_ago": 6,
            "sender": "service@paypa1-update.xyz",
            "subject": "Urgent Security Alert: Account Suspended",
            "source": "Email",
            "message": "Dear client, your PayPal account has been suspended due to unauthorized access. Click here immediately to verify your identity: http://192.168.1.1/login",
            "link_url": "http://192.168.1.1/login",
            "result": "SPAM",
            "risk_level": "High",
            "risk_score": 94,
            "confidence_pct": 96.2,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["Machine Learning identified high semantic similarity (96.2%) with phishing attacks.", "Found direct IP address URL bypassing DNS verification.", "Security credential harvesting keywords detected."],
            "recommendations": ["Do not click links.", "Never share credentials or OTPs."],
            "keywords": ["account suspended", "unauthorized access", "verify your identity", "immediately"]
        },
        {
            "days_ago": 5,
            "sender": "sarah.jenkins@acmecorp.com",
            "subject": "Sprint Review & Planning Notes",
            "source": "Email",
            "message": "Hi team, please find attached the meeting notes and action items from today's sprint planning session. Let's make sure all Jira tickets are updated.",
            "link_url": "",
            "result": "HAM",
            "risk_level": "Low",
            "risk_score": 8,
            "confidence_pct": 98.4,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["No abnormal urgency indicators, deceptive hyperlinks, or credential harvesting triggers were detected."],
            "recommendations": ["Message demonstrates standard authentic communication patterns."],
            "keywords": []
        },
        {
            "days_ago": 5,
            "sender": "+1 (800) 555-0192",
            "subject": "USPS Package Delivery Notice",
            "source": "SMS",
            "message": "USPS: Your delivery has been stopped due to incorrect street number. Please update delivery address within 12 hours: http://usps-track.top",
            "link_url": "http://usps-track.top",
            "result": "SPAM",
            "risk_level": "High",
            "risk_score": 89,
            "confidence_pct": 92.1,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["Urgency pressure indicator detected (within 12 hours).", "High-risk top-level domain (.top) detected."],
            "recommendations": ["Do not access unverified tracking links via SMS."],
            "keywords": ["within 12 hours", "delivery stopped"]
        },
        {
            "days_ago": 4,
            "sender": "no-reply@uber.com",
            "subject": "Your Thursday morning ride with Marcus",
            "source": "Email",
            "message": "Thanks for riding with Uber! Total fare: $22.40. View your trip breakdown and receipt in your mobile app.",
            "link_url": "https://uber.com",
            "result": "HAM",
            "risk_level": "Low",
            "risk_score": 12,
            "confidence_pct": 97.0,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["Standard transactional receipt format recognized by ML model."],
            "recommendations": ["Maintain standard account security and 2FA."],
            "keywords": []
        },
        {
            "days_ago": 4,
            "sender": "WhatsApp: +44 7911 123456",
            "subject": "Online Remote Work Opportunity",
            "source": "WhatsApp",
            "message": "Hello! We offer flexible work from home tasks. Earn $400 daily. Just like videos and get paid immediately. Contact our manager on Telegram @cryptopay",
            "link_url": "",
            "result": "SPAM",
            "risk_level": "High",
            "risk_score": 86,
            "confidence_pct": 91.5,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["Work-from-home financial task scam pattern recognized.", "Immediate financial payout lure."],
            "recommendations": ["Block sender immediately; legitimate companies never recruit via unsolicited WhatsApp messaging."],
            "keywords": ["earn $400", "work from home", "paid immediately"]
        },
        {
            "days_ago": 3,
            "sender": "dr.patel@healthclinic.org",
            "subject": "Appointment Confirmation for Next Tuesday",
            "source": "Email",
            "message": "Dear patient, this is a reminder for your upcoming routine dental appointment on Tuesday at 10:00 AM. Please bring your insurance card.",
            "link_url": "",
            "result": "HAM",
            "risk_level": "Low",
            "risk_score": 6,
            "confidence_pct": 99.1,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["Authentic medical appointment reminder signature."],
            "recommendations": ["Safe communication."],
            "keywords": []
        },
        {
            "days_ago": 3,
            "sender": "security-team@bankofamerica-auth.xyz",
            "subject": "CRITICAL: Wire Transfer of $3,800 Initiated",
            "source": "Email",
            "message": "A wire transfer of $3,800.00 was authorized from your checking account. If you did not initiate this, act now and click http://bit.ly/cancel-wire-boa",
            "link_url": "http://bit.ly/cancel-wire-boa",
            "result": "SPAM",
            "risk_level": "High",
            "risk_score": 96,
            "confidence_pct": 98.7,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["Domain spoofing: Sender claims to be Bank of America but links to bit.ly shortener.", "High-urgency fear-tactic wire transfer warning."],
            "recommendations": ["Never enter banking credentials on external shortened links.", "Call bank fraud desk directly."],
            "keywords": ["wire transfer", "act now", "authorized", "checking account"]
        },
        {
            "days_ago": 2,
            "sender": "notifications@github.com",
            "subject": "[GitHub] Run failed: Build & Test #891",
            "source": "Email",
            "message": "Continuous Integration build failed on commit a9b8c7 in repository backend-api. Click to view failure logs and test traces.",
            "link_url": "https://github.com/project/actions",
            "result": "HAM",
            "risk_level": "Low",
            "risk_score": 14,
            "confidence_pct": 95.8,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["Legitimate developer platform notification."],
            "recommendations": ["Safe communication."],
            "keywords": []
        },
        {
            "days_ago": 2,
            "sender": "+1 (844) 302-8821",
            "subject": "Toll Services Violation Notice",
            "source": "SMS",
            "message": "Final notice: You have unpaid bridge toll of $5.20. Pay before 6:00 PM today to avoid court fee: http://ezpass-toll-clear.top",
            "link_url": "http://ezpass-toll-clear.top",
            "result": "SPAM",
            "risk_level": "High",
            "risk_score": 91,
            "confidence_pct": 93.4,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["Urgency trigger (final notice, pay before today).", "Suspicious TLD (.top)."],
            "recommendations": ["Verify toll violations exclusively on official transportation portal."],
            "keywords": ["final notice", "pay before", "unpaid"]
        },
        {
            "days_ago": 1,
            "sender": "crypto-rewards@invest-hub.buzz",
            "subject": "Claim Your 1.25 BTC AirDrop Bonus",
            "source": "Email",
            "message": "Congratulations! Your wallet address was picked in our 2026 Crypto Community Lottery. Claim your 1.25 Bitcoin prize now: http://bit.ly/btc-airdrop-win",
            "link_url": "http://bit.ly/btc-airdrop-win",
            "result": "SPAM",
            "risk_level": "High",
            "risk_score": 95,
            "confidence_pct": 97.9,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["Lottery and cryptocurrency prize lure.", "Masked URL shortener detected."],
            "recommendations": ["AirDrop lotteries are fraudulent; never connect crypto wallets."],
            "keywords": ["congratulations", "lottery", "claim your", "bitcoin", "prize"]
        },
        {
            "days_ago": 1,
            "sender": "news@techdigest.io",
            "subject": "This Week in Cybersecurity & AI: Issue #42",
            "source": "Email",
            "message": "Welcome to our weekly newsletter covering zero-day disclosures, model alignments, and cloud defensive strategies. Read the full stories inside.",
            "link_url": "https://techdigest.io/issue-42",
            "result": "HAM",
            "risk_level": "Low",
            "risk_score": 15,
            "confidence_pct": 92.6,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["Informational newsletter syntax with verified HTTPS links."],
            "recommendations": ["Safe communication."],
            "keywords": []
        },
        {
            "days_ago": 0,
            "sender": "support@netflix-billing-center.club",
            "subject": "Account Suspension: Update Payment Method",
            "source": "Email",
            "message": "Your Netflix membership cannot be renewed. Update your credit card within 24 hours to keep streaming your favorite shows.",
            "link_url": "http://netflix-billing-center.club/update",
            "result": "SPAM",
            "risk_level": "High",
            "risk_score": 88,
            "confidence_pct": 90.8,
            "model_used": "Hybrid Ensemble (NB + LogReg)",
            "reasons": ["Urgency threat of service termination.", "Suspicious TLD (.club) spoofing Netflix."],
            "recommendations": ["Navigate to netflix.com directly to check billing status."],
            "keywords": ["account suspension", "within 24 hours", "update your credit card"]
        }
    ]

    for item in sample_scans:
        scan_date = now - datetime.timedelta(days=item["days_ago"], hours=2, minutes=15)
        dt_str = scan_date.strftime("%Y-%m-%d %H:%M:%S")
        snippet = (item["message"][:85] + "...") if len(item["message"]) > 85 else item["message"]

        cursor.execute("""
            INSERT INTO scans (
                timestamp, sender, subject, source, message_text, snippet,
                link_url, result, risk_level, risk_score, confidence_pct,
                model_used, detection_reasons, recommendations, matched_keywords,
                url_flags, reported_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            dt_str,
            item["sender"],
            item["subject"],
            item["source"],
            item["message"],
            snippet,
            item["link_url"],
            item["result"],
            item["risk_level"],
            item["risk_score"],
            item["confidence_pct"],
            item["model_used"],
            json.dumps(item["reasons"]),
            json.dumps(item["recommendations"]),
            json.dumps(item["keywords"]),
            json.dumps([]),
            "none"
        ))

def save_scan_result(scan_data: Dict[str, Any]) -> int:
    """Inserts a new scan result into SQLite history."""
    conn = get_db_connection()
    cursor = conn.cursor()

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = scan_data.get("message_text", "")
    snippet = (msg[:85] + "...") if len(msg) > 85 else msg

    cursor.execute("""
        INSERT INTO scans (
            timestamp, sender, subject, source, message_text, snippet,
            link_url, result, risk_level, risk_score, confidence_pct,
            model_used, detection_reasons, recommendations, matched_keywords,
            url_flags, reported_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now_str,
        scan_data.get("sender", "Unknown"),
        scan_data.get("subject", "No Subject"),
        scan_data.get("source", "Email"),
        msg,
        snippet,
        scan_data.get("link_url", ""),
        scan_data.get("result", "HAM"),
        scan_data.get("risk_level", "Low"),
        scan_data.get("risk_score", 0),
        scan_data.get("confidence_pct", 0.0),
        scan_data.get("model_used", "Hybrid Ensemble"),
        json.dumps(scan_data.get("detection_reasons", [])),
        json.dumps(scan_data.get("recommendations", [])),
        json.dumps(scan_data.get("matched_keywords", [])),
        json.dumps(scan_data.get("url_flags", [])),
        "none"
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    try:
        supabase.table("scan_history").insert({
        "message_text": scan_data.get("message_text", ""),
        "sender": scan_data.get("sender", "Unknown"),
        "subject": scan_data.get("subject", "No Subject"),
        "source": scan_data.get("source", "Email"),
        "link_url": scan_data.get("link_url", ""),
        "result": scan_data.get("result", "HAM"),
        "risk_level": scan_data.get("risk_level", "Low"),
        "risk_score": scan_data.get("risk_score", 0),
        "confidence_pct": scan_data.get("confidence_pct", 0),
        "model_used": scan_data.get("model_used", ""),
        "detection_reasons": scan_data.get("detection_reasons", []),
        "recommendations": scan_data.get("recommendations", []),
        "matched_keywords": scan_data.get("matched_keywords", []),
        "url_flags": scan_data.get("url_flags", [])
    }).execute()

    except Exception as e:
        print("Supabase save failed:", e)
    conn.close()
    return scan_id

def get_scans(
    search_query: str = "",
    status_filter: str = "ALL",
    risk_filter: str = "ALL",
    source_filter: str = "ALL",
    limit: int = 50,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """Fetches scans with optional search text and multi-criteria filters."""
    conn = get_db_connection()
    cursor = conn.cursor()

    conditions = ["1=1"]
    params = []

    if status_filter and status_filter.upper() != "ALL":
        conditions.append("result = ?")
        params.append(status_filter.upper())

    if risk_filter and risk_filter.upper() != "ALL":
        conditions.append("risk_level = ?")
        params.append(risk_filter.capitalize())

    if source_filter and source_filter.upper() != "ALL":
        conditions.append("LOWER(source) = ?")
        params.append(source_filter.lower())

    if search_query and search_query.strip():
        q = f"%{search_query.strip()}%"
        conditions.append("(message_text LIKE ? OR sender LIKE ? OR subject LIKE ?)")
        params.extend([q, q, q])

    where_clause = " AND ".join(conditions)
    query = f"""
        SELECT * FROM scans
        WHERE {where_clause}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = cursor.fetchall()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "sender": r["sender"],
            "subject": r["subject"],
            "source": r["source"],
            "message_text": r["message_text"],
            "snippet": r["snippet"],
            "link_url": r["link_url"],
            "result": r["result"],
            "risk_level": r["risk_level"],
            "risk_score": r["risk_score"],
            "confidence_pct": r["confidence_pct"],
            "model_used": r["model_used"],
            "detection_reasons": json.loads(r["detection_reasons"]),
            "recommendations": json.loads(r["recommendations"]),
            "matched_keywords": json.loads(r["matched_keywords"]),
            "url_flags": json.loads(r["url_flags"] or "[]"),
            "reported_status": r["reported_status"]
        })

    conn.close()
    return results

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single scan details by its primary ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    r = cursor.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "id": r["id"],
        "timestamp": r["timestamp"],
        "sender": r["sender"],
        "subject": r["subject"],
        "source": r["source"],
        "message_text": r["message_text"],
        "snippet": r["snippet"],
        "link_url": r["link_url"],
        "result": r["result"],
        "risk_level": r["risk_level"],
        "risk_score": r["risk_score"],
        "confidence_pct": r["confidence_pct"],
        "model_used": r["model_used"],
        "detection_reasons": json.loads(r["detection_reasons"]),
        "recommendations": json.loads(r["recommendations"]),
        "matched_keywords": json.loads(r["matched_keywords"]),
        "url_flags": json.loads(r["url_flags"] or "[]"),
        "reported_status": r["reported_status"]
    }

def delete_scan(scan_id: int) -> bool:
    """Deletes a scan entry by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def toggle_report_status(scan_id: int, report_type: str) -> bool:
    """Records user reporting (e.g. false_positive, missed_spam)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE scans SET reported_status = ? WHERE id = ?", (report_type, scan_id))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated

def get_analytics_metrics() -> Dict[str, Any]:
    """Computes full aggregate security statistics, daily timeline, and distributions."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM scans")
    total_scans = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as spam_cnt FROM scans WHERE result = 'SPAM'")
    spam_count = cursor.fetchone()["spam_cnt"]

    cursor.execute("SELECT COUNT(*) as ham_cnt FROM scans WHERE result = 'HAM'")
    ham_count = cursor.fetchone()["ham_cnt"]

    cursor.execute("SELECT COUNT(*) as high_cnt FROM scans WHERE risk_level = 'High'")
    high_risk_count = cursor.fetchone()["high_cnt"]

    cursor.execute("SELECT COUNT(*) as med_cnt FROM scans WHERE risk_level = 'Medium'")
    med_risk_count = cursor.fetchone()["med_cnt"]

    cursor.execute("SELECT COUNT(*) as low_cnt FROM scans WHERE risk_level = 'Low'")
    low_risk_count = cursor.fetchone()["low_cnt"]

    cursor.execute("SELECT AVG(confidence_pct) as avg_conf, AVG(risk_score) as avg_risk FROM scans")
    avg_row = cursor.fetchone()
    avg_conf = round(avg_row["avg_conf"] or 94.5, 1)
    avg_risk = round(avg_row["avg_risk"] or 45.0, 1)

    spam_pct = round((spam_count / total_scans * 100), 1) if total_scans > 0 else 0.0
    ham_pct = round((ham_count / total_scans * 100), 1) if total_scans > 0 else 0.0

    # Source breakdown
    cursor.execute("SELECT source, COUNT(*) as cnt FROM scans GROUP BY source")
    source_rows = cursor.fetchall()
    source_breakdown = {}
    for r in source_rows:
        source_breakdown[r["source"]] = r["cnt"]

    # 7-Day Timeline activity
    cursor.execute("""
        SELECT substr(timestamp, 1, 10) as scan_date,
               SUM(CASE WHEN result = 'SPAM' THEN 1 ELSE 0 END) as spam_count,
               SUM(CASE WHEN result = 'HAM' THEN 1 ELSE 0 END) as ham_count,
               COUNT(*) as total_count
        FROM scans
        GROUP BY scan_date
        ORDER BY scan_date ASC
        LIMIT 7
    """)
    trend_rows = cursor.fetchall()
    timeline = []
    for r in trend_rows:
        timeline.append({
            "date": r["scan_date"],
            "spam": r["spam_count"],
            "ham": r["ham_count"],
            "total": r["total_count"]
        })

    # Frequency analysis of matched keywords
    cursor.execute("SELECT matched_keywords FROM scans WHERE result = 'SPAM'")
    kw_rows = cursor.fetchall()
    keyword_freq: Dict[str, int] = {}
    for r in kw_rows:
        try:
            kws = json.loads(r["matched_keywords"])
            for kw in kws:
                clean_kw = kw.strip().lower()
                if clean_kw:
                    keyword_freq[clean_kw] = keyword_freq.get(clean_kw, 0) + 1
        except Exception:
            pass

    sorted_kws = sorted(keyword_freq.items(), key=lambda x: x[1], reverse=True)[:8]
    top_keywords = [{"keyword": k, "count": c} for k, c in sorted_kws]

    # Threat Categories estimation
    threat_categories = {
        "Phishing & Credential Harvest": int(round(spam_count * 0.45)),
        "High Urgency Panic Coercion": int(round(spam_count * 0.35)),
        "Financial & Lottery Scams": int(round(spam_count * 0.30)),
        "Malicious & Shortened URLs": int(round(spam_count * 0.40))
    }

    conn.close()

    return {
        "total_scans": total_scans,
        "spam_count": spam_count,
        "ham_count": ham_count,
        "spam_percentage": spam_pct,
        "ham_percentage": ham_pct,
        "high_risk_count": high_risk_count,
        "medium_risk_count": med_risk_count,
        "low_risk_count": low_risk_count,
        "avg_confidence": avg_conf,
        "avg_risk_score": avg_risk,
        "source_breakdown": source_breakdown,
        "timeline_trends": timeline,
        "top_keywords": top_keywords,
        "threat_categories": threat_categories
    }

def get_settings() -> Dict[str, Any]:
    """Reads system and user sensitivity settings."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM settings WHERE id = 1")
    row = cursor.fetchone()
    conn.close()
    if not row:
        return {
            "threshold_high": 75,
            "threshold_med": 40,
            "active_model": "ensemble",
            "custom_blacklist": ["urgent wire", "crypto gift", "unclaimed prize"],
            "custom_whitelist": ["meeting agenda", "doctor appointment", "jira"]
        }
    return {
        "threshold_high": row["threshold_high"],
        "threshold_med": row["threshold_med"],
        "active_model": row["active_model"],
        "custom_blacklist": json.loads(row["custom_blacklist"] or "[]"),
        "custom_whitelist": json.loads(row["custom_whitelist"] or "[]")
    }

def update_settings(
    threshold_high: int,
    threshold_med: int,
    active_model: str,
    custom_blacklist: List[str],
    custom_whitelist: List[str]
) -> bool:
    """Saves updated settings."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE settings SET
            threshold_high = ?,
            threshold_med = ?,
            active_model = ?,
            custom_blacklist = ?,
            custom_whitelist = ?
        WHERE id = 1
    """, (
        threshold_high,
        threshold_med,
        active_model,
        json.dumps(custom_blacklist),
        json.dumps(custom_whitelist)
    ))
    conn.commit()
    conn.close()
    return True

def reset_database() -> bool:
    """Clears history and re-seeds default data."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    _seed_initial_history(cursor)
    conn.commit()
    conn.close()
    return True
