import re
from urllib.parse import unquote, urlparse

# Şemalı URL ama obfuscation olabilir → sadece scheme'i kesin kontrol ediyoruz
SCHEMED_OBFUSCATED_RX = re.compile(
    r'(https?://[^\s)>\]]+)',
    flags=re.IGNORECASE
)

def _deobfuscate_dots(s: str) -> str:
    s = s.replace('\\', '')
    s = re.sub(r'\[dot\]|\(dot\)|\s+dot\s+', '.', s, flags=re.IGNORECASE)
    s = re.sub(r'\s*\.\s*', '.', s)   # foo . bar → foo.bar
    return s

def _normalize(u: str) -> str:
    u = unquote(u).strip().rstrip('.,;:\'"')
    u = _deobfuscate_dots(u)
    return u

def _is_valid_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return (
            p.scheme in ("http", "https")
            and p.netloc
            and "." in p.netloc
        )
    except:
        return False

def extract_urls(text: str):
    if not text:
        return []

    urls = set()

    # 1) Markdown URL’leri
    for m in re.findall(r'\[[^\]]*?\]\((https?://[^\s)]+)\)', text, flags=re.IGNORECASE):
        u = _normalize(m)
        if _is_valid_url(u):
            urls.add(u)

    # 2) Şemalı ama obfuscation içerebilecek URL’ler
    for m in SCHEMED_OBFUSCATED_RX.findall(text):
        u = _normalize(m)
        if _is_valid_url(u):
            urls.add(u)

    return list(urls)
