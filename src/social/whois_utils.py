import tldextract
import whois
from datetime import datetime

def extract_whois_features(url: str) -> dict:
    try:
        domain = tldextract.extract(url).registered_domain
        w = whois.whois(domain)

        today = datetime.utcnow()
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date

        domain_age = (today - creation_date).days if creation_date else 9999
        registration_length = (expiration_date - creation_date).days if creation_date and expiration_date else 9999
        whois_registered = 1 if w.domain_name else 0

        return {
            "domain_age": domain_age,
            "registration_length": registration_length,
            "whois_registered": whois_registered
        }
    except Exception:
        return {
            "domain_age": 9999,
            "registration_length": 9999,
            "whois_registered": 0
        }