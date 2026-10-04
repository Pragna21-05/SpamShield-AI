"""
SpamShield AI - Heuristic Feature Extraction Engine
Extracts domain-specific security heuristics:
1. Urgency density and high-pressure call-to-action indicators
2. Account & credential compromise trigger words
3. Financial lure, lottery, and promotional keywords
4. Suspicious URL pattern analyzer:
   - IP-based URLs (e.g. http://192.168.1.1)
   - URL Shorteners (bit.ly, tinyurl.com, t.co, etc.)
   - Suspicious / Abuse-heavy TLDs (.xyz, .top, .buzz, etc.)
   - Sender domain vs link destination domain spoofing
   - Embedded credentials / excessive subdomains
5. In-text trigger span locator for UI highlight badges
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

# Grouped keyword dictionaries
URGENCY_PATTERNS = [
    r"\bact now\b", r"\bimmediat(?:e|ely)\b", r"\bwithin \d+ hours?\b",
    r"\bwithin \d+ mins?(?:utes?)?\b", r"\bexpires? today\b", r"\bfinal notice\b",
    r"\bimmediate response\b", r"\baction required\b", r"\btime sensitive\b",
    r"\bdon'?t delay\b", r"\blimited time\b", r"\blast chance\b",
    r"\burgent(?:ly)?\b", r"\bcritical alert\b", r"\brespond promptly\b",
    r"\bterminate[d]? immediately\b", r"\bpermanent(?:ly)? closed\b",
    r"\bvalid for \d+ hours?\b"
]

CREDENTIAL_SECURITY_PATTERNS = [
    r"\baccount suspended\b", r"\bverify your account\b", r"\bconfirm your identity\b",
    r"\bunauthorized access\b", r"\bunusual activity\b", r"\bsecurity alert\b",
    r"\bcompromised\b", r"\bupdate password\b", r"\breset your password\b",
    r"\breactivate\b", r"\blocked account\b", r"\brestricted access\b",
    r"\botp\b", r"\bone-time password\b", r"\bverification code\b",
    r"\bpin code\b", r"\bssn\b", r"\bsocial security\b", r"\bcvv\b",
    r"\bcredit card number\b", r"\bbank details\b", r"\blogin credentials\b",
    r"\bsign in immediately\b", r"\bclick here to verify\b"
]

FINANCIAL_PROMOTIONAL_PATTERNS = [
    r"\bwinner\b", r"\byou have won\b", r"\blottery\b", r"\bcash prize\b",
    r"\bwire transfer\b", r"\bclaim your prize\b", r"\b100% free\b",
    r"\bfree gift\b", r"\bclaim bonus\b", r"\bbitcoin\b", r"\bcrypto(?:currency)?\b",
    r"\binheritance\b", r"\bcompensation fund\b", r"\btax refund\b",
    r"\bpre-approved loan\b", r"\bguaranteed return\b", r"\bmillion dollars?\b",
    r"\bexclusive deal\b", r"\bearn \$\d+\b", r"\bwork from home \$\d+\b",
    r"\bcongratulations\b", r"\bunclaimed funds\b", r"\bdouble your money\b"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "bl.ink"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".buzz", ".club", ".work", ".click", ".loan",
    ".gq", ".tk", ".ml", ".cf", ".online", ".site", ".live", ".icu",
    ".rest", ".ru", ".link", ".monster"
}

KNOWN_TRUSTED_BRANDS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in"],
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "docusign": ["docusign.com"]
}

def extract_urls(text: str, dedicated_url: Optional[str] = None) -> List[str]:
    """Finds all HTTP/HTTPS and www URLs from message text plus dedicated URL field."""
    found = set()
    if dedicated_url and dedicated_url.strip():
        url = dedicated_url.strip()
        if not re.match(r"^https?://", url, re.I):
            url = "http://" + url
        found.add(url)
        
    raw_urls = re.findall(r"(?:https?://|www\.)[^\s<>'\"\)\]]+", text or "", re.IGNORECASE)
    for u in raw_urls:
        if u.startswith("www."):
            u = "http://" + u
        found.add(u.rstrip(".,;!?"))
    return list(found)

def analyze_url_patterns(urls: List[str], sender_info: str = "") -> Dict[str, Any]:
    """Analyzes extracted URLs for known phishing vectors."""
    ip_url_found = False
    shortener_found = False
    suspicious_tld_found = False
    mismatched_domain = False
    excessive_subdomains = False
    reasons = []
    
    sender_lower = (sender_info or "").lower()
    
    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            
            # Check 1: Direct IPv4 address host
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
                ip_url_found = True
                reasons.append(f"Direct IP-based URL detected ({hostname}) bypassing standard domain registration")
                
            # Check 2: Known URL shortener
            for shortener in URL_SHORTENERS:
                if hostname == shortener or hostname.endswith("." + shortener):
                    shortener_found = True
                    reasons.append(f"Obfuscated URL shortener detected ({hostname}) hiding actual destination")
                    break
                    
            # Check 3: Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if hostname.endswith(tld):
                    suspicious_tld_found = True
                    reasons.append(f"High-risk top-level domain detected ({tld}) commonly leveraged in disposable spam")
                    break
                    
            # Check 4: Excessive subdomains (> 3 dots)
            if hostname.count(".") >= 4:
                excessive_subdomains = True
                reasons.append(f"Excessive subdomain nesting detected ({hostname}) indicative of spoofing camouflage")
                
            # Check 5: Domain Spoofing vs Brand / Sender
            for brand, legit_domains in KNOWN_TRUSTED_BRANDS.items():
                if brand in sender_lower or brand in url.lower():
                    # If brand mentioned, check if hostname actually matches official domain
                    is_legit = any(hostname == d or hostname.endswith("." + d) for d in legit_domains)
                    if not is_legit and (brand in hostname or brand in sender_lower):
                        mismatched_domain = True
                        reasons.append(f"Brand spoofing detected: claims to be '{brand.title()}' but links to unaffiliated host '{hostname}'")
                        break
        except Exception:
            continue
            
    # Calculate URL risk sub-score (0.0 to 1.0)
    url_score = 0.0
    if urls:
        url_score = 0.15  # baseline presence of links in unverified messages
        if ip_url_found:
            url_score += 0.45
        if shortener_found:
            url_score += 0.30
        if suspicious_tld_found:
            url_score += 0.35
        if mismatched_domain:
            url_score += 0.50
        if excessive_subdomains:
            url_score += 0.25
        url_score = min(url_score, 1.0)

    return {
        "urls": urls,
        "url_count": len(urls),
        "has_ip_url": ip_url_found,
        "has_shortener": shortener_found,
        "has_suspicious_tld": suspicious_tld_found,
        "has_mismatched_domain": mismatched_domain,
        "has_excessive_subdomains": excessive_subdomains,
        "url_risk_score": round(url_score, 3),
        "url_reasons": list(set(reasons))
    }

def find_matched_spans(text: str, patterns: List[str], category: str) -> List[Dict[str, Any]]:
    """Locates character start and end spans of matching regex patterns for UI text highlighting."""
    spans = []
    if not text:
        return spans
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            spans.append({
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "category": category
            })
    return spans

def extract_heuristic_features(
    text: str,
    sender: str = "",
    subject: str = "",
    dedicated_url: Optional[str] = None,
    custom_blacklist: Optional[List[str]] = None,
    custom_whitelist: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Extracts all heuristic feature vectors, counts, reasons, and text highlight spans.
    """
    full_text = f"{subject} {text}".strip()
    
    # Extract matches for each category
    urgency_spans = find_matched_spans(full_text, URGENCY_PATTERNS, "urgency")
    cred_spans = find_matched_spans(full_text, CREDENTIAL_SECURITY_PATTERNS, "credential")
    financial_spans = find_matched_spans(full_text, FINANCIAL_PROMOTIONAL_PATTERNS, "financial")
    
    # Custom blacklist matches
    custom_blacklist_spans = []
    if custom_blacklist:
        for kw in custom_blacklist:
            if kw.strip():
                pat = r"\b" + re.escape(kw.strip()) + r"\b"
                custom_blacklist_spans.extend(find_matched_spans(full_text, [pat], "custom_blacklist"))

    # Custom whitelist matches
    custom_whitelist_spans = []
    if custom_whitelist:
        for kw in custom_whitelist:
            if kw.strip():
                pat = r"\b" + re.escape(kw.strip()) + r"\b"
                custom_whitelist_spans.extend(find_matched_spans(full_text, [pat], "custom_whitelist"))

    # URL patterns
    all_urls = extract_urls(full_text, dedicated_url)
    url_analysis = analyze_url_patterns(all_urls, sender)

    # Calculate heuristic score
    # Weights: Urgency (0.25), Credential triggers (0.35), Financial (0.20), URL patterns (0.35)
    urgency_count = len(urgency_spans)
    cred_count = len(cred_spans)
    financial_count = len(financial_spans)
    suspicious_keyword_count = urgency_count + cred_count + financial_count + len(custom_blacklist_spans)
    
    heuristic_points = 0.0
    heuristic_points += min(urgency_count * 0.15, 0.40)
    heuristic_points += min(cred_count * 0.20, 0.50)
    heuristic_points += min(financial_count * 0.15, 0.40)
    heuristic_points += url_analysis["url_risk_score"] * 0.50
    
    # Custom blacklist penalty
    if custom_blacklist_spans:
        heuristic_points += 0.40 * len(custom_blacklist_spans)
        
    # Custom whitelist dampener
    if custom_whitelist_spans:
        heuristic_points -= 0.35 * len(custom_whitelist_spans)

    heuristic_score = max(0.0, min(round(heuristic_points, 3), 1.0))
    
    # Merge non-overlapping spans for in-text UI rendering
    all_spans = sorted(
        urgency_spans + cred_spans + financial_spans + custom_blacklist_spans + custom_whitelist_spans,
        key=lambda s: s["start"]
    )
    
    # Assemble human-understandable heuristic reasons
    reasons = []
    if urgency_count > 0:
        terms = list({s["match"].lower() for s in urgency_spans})[:3]
        reasons.append(f"High urgency indicators detected ({', '.join(terms)}) exerting psychological pressure")
    if cred_count > 0:
        terms = list({s["match"].lower() for s in cred_spans})[:3]
        reasons.append(f"Security/credential harvesting triggers identified ({', '.join(terms)})")
    if financial_count > 0:
        terms = list({s["match"].lower() for s in financial_spans})[:3]
        reasons.append(f"Unsolicited financial or prize lure language detected ({', '.join(terms)})")
    if url_analysis["url_reasons"]:
        reasons.extend(url_analysis["url_reasons"])
    if custom_blacklist_spans:
        terms = list({s["match"].lower() for s in custom_blacklist_spans})
        reasons.append(f"Matched user-defined security blacklist keywords ({', '.join(terms)})")
        
    return {
        "heuristic_score": heuristic_score,
        "suspicious_keyword_count": suspicious_keyword_count,
        "urgency_count": urgency_count,
        "credential_count": cred_count,
        "financial_count": financial_count,
        "urgency_terms": list({s["match"] for s in urgency_spans}),
        "credential_terms": list({s["match"] for s in cred_spans}),
        "financial_terms": list({s["match"] for s in financial_spans}),
        "custom_blacklist_terms": list({s["match"] for s in custom_blacklist_spans}),
        "custom_whitelist_terms": list({s["match"] for s in custom_whitelist_spans}),
        "url_analysis": url_analysis,
        "heuristic_reasons": reasons,
        "highlight_spans": all_spans
    }
