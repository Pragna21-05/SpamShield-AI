"""
SpamShield AI - Text Preprocessing Pipeline
Implements:
1. Character Cleanup & Noise Removal
2. Case Folding (Lowercasing)
3. Word Tokenization
4. Stopword Removal
5. Text Normalization (Lemmatization / Stemming)
Provides step-by-step pipeline transparency for user explainability.
"""

import re
import html
from typing import List, Dict, Any, Tuple

# Curated English stopwords list
STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
    "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
    "below", "between", "both", "but", "by", "can", "cannot", "could", "couldn't",
    "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during",
    "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
    "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here",
    "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i",
    "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's",
    "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself",
    "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought",
    "our", "ours", "ourselves", "out", "over", "own", "same", "shan't", "she",
    "she'd", "she'll", "she's", "should", "shouldn't", "so", "some", "such",
    "than", "that", "that's", "the", "their", "theirs", "them", "themselves",
    "then", "there", "there's", "these", "they", "they'd", "they'll", "they're",
    "they've", "this", "those", "through", "to", "too", "under", "until", "up",
    "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were",
    "weren't", "what", "what's", "when", "when's", "where", "where's", "which",
    "while", "who", "who's", "whom", "why", "why's", "with", "won't", "would",
    "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours",
    "yourself", "yourselves"
}

# Common spam/phishing canonical lemmatization mappings
LEMMATIZATION_MAP = {
    "verifying": "verify",
    "verification": "verify",
    "verified": "verify",
    "suspending": "suspend",
    "suspended": "suspend",
    "suspension": "suspend",
    "urgency": "urgent",
    "urgently": "urgent",
    "winners": "winner",
    "winning": "win",
    "won": "win",
    "congratulations": "congratulate",
    "congratulated": "congratulate",
    "claimed": "claim",
    "claiming": "claim",
    "transferred": "transfer",
    "transferring": "transfer",
    "passwords": "password",
    "accounts": "account",
    "notifications": "notification",
    "banking": "bank",
    "banks": "bank",
    "payments": "payment",
    "paying": "pay",
    "paid": "pay",
    "expired": "expire",
    "expiring": "expire",
    "expires": "expire",
    "devices": "device",
    "unauthorized": "unauthorized",
    "authorizing": "authorize",
    "authorizations": "authorize",
    "authorized": "authorize",
    "threats": "threat",
    "blocked": "block",
    "blocking": "block",
    "blocks": "block",
    "logins": "login",
    "logging": "login",
    "logged": "login",
    "updates": "update",
    "updating": "update",
    "updated": "update",
    "clicked": "click",
    "clicking": "click",
    "clicks": "click",
    "rewards": "reward",
    "rewarding": "reward",
    "investments": "investment",
    "investing": "invest",
    "invested": "invest",
    "securities": "security",
    "secured": "security",
    "securing": "security"
}

def clean_characters(text: str) -> str:
    """Removes HTML tags, invisible control chars, normalizes whitespace & quotes."""
    if not text:
        return ""
    # Unescape HTML entities
    text = html.unescape(text)
    # Remove HTML tags if any
    text = re.sub(r"<[^>]+>", " ", text)
    # Remove zero-width & non-printable unicode control characters
    text = re.sub(r"[\u200B-\u200D\uFEFF\u00A0]", " ", text)
    text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)
    # Normalize excessive repetitive punctuation (e.g. !!!!! -> !)
    text = re.sub(r"([!?.,])\1+", r"\1", text)
    # Normalize multiple whitespaces
    text = re.sub(r"\s+", " ", text).strip()
    return text

def tokenize(text: str) -> List[str]:
    """Extracts alphanumeric word tokens, preserving currency symbols and hyphens."""
    # Matches words, handles hyphenated words and words with currency markers
    return re.findall(r"\b[a-zA-Z0-9_\$%-]+\b", text)

def stem_word(word: str) -> str:
    """Lightweight rule-based morphological normalization (Porter-style stemmer)."""
    if len(word) <= 3:
        return word
    
    # Check explicit lemmatization map first
    if word in LEMMATIZATION_MAP:
        return LEMMATIZATION_MAP[word]
    
    # Suffix reduction rules
    if word.endswith("sses"):
        word = word[:-2]
    elif word.endswith("ies") and len(word) > 4:
        word = word[:-3] + "y"
    elif word.endswith("ss"):
        pass
    elif word.endswith("s") and len(word) > 3:
        word = word[:-1]
    
    if word.endswith("eed") and len(word) > 4:
        word = word[:-1]
    elif (word.endswith("ed") or word.endswith("ing")) and len(word) > 5:
        base = word[:-2] if word.endswith("ed") else word[:-3]
        if base.endswith("at") or base.endswith("bl") or base.endswith("iz"):
            word = base + "e"
        elif len(base) > 2 and base[-1] == base[-2] and base[-1] not in "lsz":
            word = base[:-1]
        else:
            word = base

    if word.endswith("tional"):
        word = word[:-4]
    elif word.endswith("ation"):
        word = word[:-5] + "e"
    elif word.endswith("alism"):
        word = word[:-3]
    elif word.endswith("ment") and len(word) > 5:
        word = word[:-4]
    elif word.endswith("able") and len(word) > 5:
        word = word[:-4]
    elif word.endswith("ful") and len(word) > 4:
        word = word[:-3]
    elif word.endswith("ness") and len(word) > 5:
        word = word[:-4]
    elif word.endswith("ly") and len(word) > 4:
        word = word[:-2]

    return word

def run_preprocessing_pipeline(raw_text: str) -> Dict[str, Any]:
    """
    Executes the 5-stage text preprocessing pipeline:
    1. Character Cleanup
    2. Lowercasing
    3. Tokenization
    4. Stopword Removal
    5. Normalization (Stemming & Lemmatization)
    
    Returns transformed outputs and step metadata for UI transparency.
    """
    original = raw_text or ""
    
    # Step 1: Cleanup
    cleaned = clean_characters(original)
    
    # Step 2: Lowercasing
    lowercased = cleaned.lower()
    
    # Step 3: Tokenization
    raw_tokens = tokenize(lowercased)
    
    # Step 4: Stopword Removal
    tokens_no_stopwords = [t for t in raw_tokens if t not in STOPWORDS and len(t) > 1]
    
    # Step 5: Normalization
    normalized_tokens = [stem_word(t) for t in tokens_no_stopwords]
    processed_text = " ".join(normalized_tokens)
    
    steps = [
        {
            "step_id": 1,
            "name": "Character Cleanup",
            "desc": "Stripped HTML tags, hidden unicode, and compacted repetitive punctuation",
            "output_preview": cleaned[:120] + ("..." if len(cleaned) > 120 else ""),
            "stats": f"{len(original)} chars → {len(cleaned)} chars"
        },
        {
            "step_id": 2,
            "name": "Lowercasing",
            "desc": "Standardized all text to uniform lowercase encoding",
            "output_preview": lowercased[:120] + ("..." if len(lowercased) > 120 else ""),
            "stats": "Uniform case-folded"
        },
        {
            "step_id": 3,
            "name": "Word Tokenization",
            "desc": "Segmented text into discrete lexical tokens preserving currency and key symbols",
            "output_preview": ", ".join(raw_tokens[:12]) + ("..." if len(raw_tokens) > 12 else ""),
            "stats": f"{len(raw_tokens)} total tokens"
        },
        {
            "step_id": 4,
            "name": "Stopword Removal",
            "desc": "Eliminated low-information syntactic filler words (articles, auxiliary verbs)",
            "output_preview": ", ".join(tokens_no_stopwords[:12]) + ("..." if len(tokens_no_stopwords) > 12 else ""),
            "stats": f"{len(raw_tokens) - len(tokens_no_stopwords)} stopwords removed ({len(tokens_no_stopwords)} kept)"
        },
        {
            "step_id": 5,
            "name": "Stemming & Normalization",
            "desc": "Conflated morphological variants to root canonical lemmas",
            "output_preview": ", ".join(normalized_tokens[:12]) + ("..." if len(normalized_tokens) > 12 else ""),
            "stats": f"{len(normalized_tokens)} normalized features"
        }
    ]
    
    return {
        "original_text": original,
        "cleaned_text": cleaned,
        "lowercased_text": lowercased,
        "raw_tokens": raw_tokens,
        "tokens_no_stopwords": tokens_no_stopwords,
        "normalized_tokens": normalized_tokens,
        "processed_text": processed_text,
        "steps": steps
    }
