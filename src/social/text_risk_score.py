import re
from typing import Optional, Tuple, List
from keywords import risk_keywords  

def text_risk_score(text: str, whois_data: Optional[dict] = None, html_content: Optional[str] = "") -> Tuple[int, List[str]]:
    combined = (text + " " + html_content).lower()
    score = 0
    keyword_hits = []

    for kw in risk_keywords:
        if kw["keyword"] in combined:
            score += kw["weight"]
            keyword_hits.append(kw["keyword"])

    regex_patterns = {
        "iban": r"\bTR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\b",
        "email": r"\b\S+@\S+\.\S+\b",
        "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "url": r"https?://\S+",
        "phone": r"\b0\d{10}\b"
    }

    for name, pattern in regex_patterns.items():
        if re.search(pattern, combined):
            score += 1
            keyword_hits.append(f"[regex:{name}]")

    if whois_data:
        if whois_data.get("domain_age", 9999) < 30:
            score += 2
            keyword_hits.append("[whois:young_domain]")
        if whois_data.get("registration_length", 9999) < 90:
            score += 2
            keyword_hits.append("[whois:short_registration]")
        if whois_data.get("whois_registered", 1) == 0:
            score += 2
            keyword_hits.append("[whois:unregistered]")

    return score, keyword_hits