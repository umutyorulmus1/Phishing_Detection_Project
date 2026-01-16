import re
from urllib.parse import unquote, urlparse

# --- Regex: şemalı veya obfuscate edilmiş domain-like ifadeleri yakalar ---
URL_LIKE_RX = re.compile(
    r'(https?://[^\s)>\]]+)|'
    r'([a-zA-Z0-9\-\_\.]+\s*(?:\[dot\]|\(dot\)|\\\.|\s+dot\s+|\.)\s*[a-zA-Z0-9\-\_\.]+(?:[^\s)]*)?)'
)

# --- Yardımcı fonksiyonlar ---
def _deobfuscate_dots(s: str) -> str:
    if not s:
        return s
    s = s.replace('\\', '')
    s = re.sub(r'\[dot\]|\(dot\)|\s+dot\s+|\[.\]|\(.\)', '.', s, flags=re.IGNORECASE)
    s = re.sub(r'\s*\.\s*', '.', s)
    return s.strip()

def _ensure_scheme(u: str) -> str:
    try:
        parsed = urlparse(u)
        if parsed.scheme:
            return u
        return 'https://' + u
    except Exception:
        return 'https://' + u

def _clean_candidate(raw: str) -> str:
    if not raw:
        return ''
    u = unquote(raw).split(')')[0].rstrip('.,;:\'\"')
    u = _deobfuscate_dots(u)
    u = u.strip()
    u = _ensure_scheme(u)
    return u

def _is_valid_url(u: str) -> bool:
    try:
        p = urlparse(u)
        if p.scheme not in ('http', 'https') or not p.netloc:
            return False
        if '.' not in p.netloc:
            return False
        labels = [lab for lab in p.netloc.split('.') if lab]
        if not labels:
            return False
        if len(labels[-1]) < 2:
            return False
        for lab in labels:
            if len(lab) == 1:
                return False
        return True
    except Exception:
        return False

def _strip_likely_sentence_artifacts(u: str) -> str:
    try:
        p = urlparse(u)
        host = p.netloc
        if not host:
            return u
        labels = [lab for lab in host.split('.') if lab]
        if not labels:
            return u
        if len(labels[-1]) == 1:
            labels = labels[:-1]
        if labels and labels[-1][0].isupper() and len(labels[-1]) <= 6 and not labels[-1].islower():
            labels = labels[:-1]
        if not labels:
            return u
        new_host = '.'.join(labels)
        rebuilt = p._replace(netloc=new_host).geturl()
        return rebuilt
    except Exception:
        return u

# --- URL çıkarma ---
def extract_urls_from_text(text: str):
    if not text:
        return [], []
    seen, valid, fragments = set(), [], []
    markdown_matches = re.findall(r'\[.*?\]\((https?://[^\s)]+)\)', text)
    for m in markdown_matches:
        norm = _clean_candidate(m)
        if _is_valid_url(norm):
            if norm not in seen:
                seen.add(norm)
                valid.append(norm)
        else:
            stripped = _strip_likely_sentence_artifacts(norm)
            if _is_valid_url(stripped) and stripped not in seen:
                seen.add(stripped)
                valid.append(stripped)
            elif norm and norm not in seen:
                seen.add(norm)
                fragments.append(norm)
    for raw in re.findall(r'https?://[^\s)>\]]+', text):
        if any(raw in mm for mm in markdown_matches):
            continue
        norm = _clean_candidate(raw)
        if _is_valid_url(norm):
            if norm not in seen:
                seen.add(norm)
                valid.append(norm)
        else:
            stripped = _strip_likely_sentence_artifacts(norm)
            if _is_valid_url(stripped) and stripped not in seen:
                seen.add(stripped)
                valid.append(stripped)
            elif norm and norm not in seen:
                seen.add(norm)
                fragments.append(norm)
    for match in URL_LIKE_RX.findall(text):
        candidate = match[0] or match[1]
        if not candidate:
            continue
        candidate = candidate.strip().rstrip('.,;:\'\"')
        if candidate.startswith('http'):
            continue
        norm = _clean_candidate(candidate)
        if _is_valid_url(norm):
            if norm not in seen:
                seen.add(norm)
                valid.append(norm)
        else:
            stripped = _strip_likely_sentence_artifacts(norm)
            if _is_valid_url(stripped) and stripped not in seen:
                seen.add(stripped)
                valid.append(stripped)
            elif norm and norm not in seen:
                seen.add(norm)
                fragments.append(norm)
    return valid, fragments

# --- Tekil URL temizleme ---
def clean_url_field(raw_url: str):
    if not raw_url:
        return None
    m = re.search(r'\((https?://[^\s)]+)\)', raw_url)
    if m:
        u = unquote(m.group(1)).split(')')[0].rstrip('.,;:')
        u = _deobfuscate_dots(u)
        u = _ensure_scheme(u)
        return u if _is_valid_url(u) else None
    cleaned = unquote(raw_url).split(')')[0]
    if '](' in cleaned:
        cleaned = cleaned.split('](')[-1]
    cleaned = _deobfuscate_dots(cleaned).rstrip('.,;:')
    cleaned = _ensure_scheme(cleaned)
    return cleaned if _is_valid_url(cleaned) else None

# --- Ana fonksiyon ---
def clean_document(doc: dict):
    qc_issues = []
    cleaned = dict(doc) if doc else {}
    text = cleaned.get('text') or ''
    cleaned['text'] = text.strip()

    valid_urls, fragments = extract_urls_from_text(text)
    raw_url_field = cleaned.get('url')
    if raw_url_field:
        primary = clean_url_field(raw_url_field)
        if primary and primary not in valid_urls:
            valid_urls.append(primary)
        if raw_url_field and not primary:
            qc_issues.append('raw_url_field_unparseable')

    valid_urls = [u for u in valid_urls if _is_valid_url(u)]
    if not valid_urls and fragments:
        qc_issues.append('no_valid_url_after_cleanup_but_fragments')
    cleaned['urls'] = list(dict.fromkeys(valid_urls))

    if fragments:
        cleaned['fragments'] = list(dict.fromkeys(fragments))
        qc_issues.append('fragmented_url_detected')

    rs = cleaned.get('risk_score')
    try:
        cleaned['risk_score'] = float(rs) if rs is not None else 0.0
    except Exception:
        cleaned['risk_score'] = 0.0
        qc_issues.append('invalid_risk_score')

    ml_proba = cleaned.get('ml_proba')
    try:
        cleaned['model_score'] = float(ml_proba) if ml_proba is not None else 0.0
    except Exception:
        cleaned['model_score'] = 0.0
        qc_issues.append('invalid_ml_proba')

    ml_result = cleaned.get('ml_result')
    try:
        cleaned['ml_result'] = int(ml_result) if ml_result is not None else None
    except Exception:
        cleaned['ml_result'] = None
        qc_issues.append('invalid_ml_result')

    rf = cleaned.get('rule_flags') or cleaned.get('keyword_hits') or []
    if isinstance(rf, str):
        rf = [rf]
    cleaned['rule_flags'] = list(dict.fromkeys(rf))

    if len(cleaned['text']) < 20:
        qc_issues.append('short_text')
    if len(cleaned['text']) > 5000:
        qc_issues.append('long_text')

    vt_verdict = cleaned.get('vt_summary', {}).get('verdict')
    cleaned['vt_result'] = vt_verdict.capitalize() if vt_verdict else 'Unknown'

    anomali = False
    if cleaned['vt_result'] == 'Malicious' and cleaned['risk_score'] < 10:
        anomali = True
        qc_issues.append('vt_malicious_but_low_risk')
    if len(cleaned['rule_flags']) >= 3 and cleaned['model_score'] < 0.4:
        anomali = True
        qc_issues.append('many_rules_but_low_model_conf')

    cleaned['anomali'] = anomali
    cleaned['qc_issues'] = qc_issues

    return cleaned