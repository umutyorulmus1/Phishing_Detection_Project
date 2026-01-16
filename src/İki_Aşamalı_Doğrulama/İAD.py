import joblib
import pandas as pd
import urllib.parse, re
from pymongo import MongoClient
import os
from dotenv import load_dotenv

# =============================
#  SABİTLER YOLLAr
# =============================
load_dotenv()

MODEL_PATH = "models/phishing_model_irst.joblib"
SAVED_FEATURES_PATH = "models/features_irst.joblib"
THRESHOLD = 0.71

# MongoDB (env içinden)
client = MongoClient(os.getenv("MONGO_URI"))
db = client["phishing_db"]
collection = db["social_urls"]

# =============================
# FEATURE EXTRACTION
# =============================
def extract_features(url):
    s = str(url)

    def count_char(t, chars):
        return sum(t.count(c) for c in chars)

    try:
        parsed = urllib.parse.urlparse(s)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        port_flag = 1 if parsed.port else 0
    except Exception:
        hostname, path, port_flag = "", "", 0

    return {
        "url_length": len(s),
        "length_hostname": len(hostname),
        "ip": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", hostname) else 0,
        "nb_dots": s.count("."),
        "nb_hyphens": s.count("-"),
        "nb_at": s.count("@"),
        "nb_qm": s.count("?"),
        "nb_and": s.count("&"),
        "nb_eq": s.count("="),
        "nb_underscore": s.count("_"),
        "nb_percent": s.count("%"),
        "nb_slash": s.count("/"),
        "nb_www": s.lower().count("www"),
        "nb_com": s.lower().count(".com"),
        "http_in_path": 1 if "http" in path else 0,
        "ratio_digits_url": sum(c.isdigit() for c in s) / (len(s) or 1),
        "ratio_digits_host": sum(c.isdigit() for c in hostname) / (len(hostname) or 1),
        "punycode": 1 if "xn--" in s else 0,
        "port": port_flag,
        "abnormal_subdomain": 1 if len(hostname.split(".")) > 3 else 0,
        "nb_subdomains": max(len(hostname.split(".")) - 2, 0),
        "prefix_suffix": 1 if "-" in hostname else 0,
        "shortening_service": 1 if any(x in s for x in ["bit.ly","tinyurl","t.co"]) else 0,
        "has_suspicious_keywords": 1 if any(
            k in s.lower()
            for k in ["login","secure","verify","bank","account","update"]
        ) else 0,
        "num_digits": sum(c.isdigit() for c in s),
        "num_special_chars": count_char(s, "?=&%$@!*^~"),
    }

# =============================
# ANA PIPELINE
# =============================
def run_pipeline(limit=1000):
    docs = list(collection.find(#burada önceden kontrolü sağlanmamış bir veriyi çekme işlemini yapıyoruz.
        {"ml_status": {"$exists": False}}
    ).limit(limit))

    if not docs:
        print("Yeni işlenecek kayıt yok.")
        return

    model = joblib.load(MODEL_PATH)
    saved_X = joblib.load(SAVED_FEATURES_PATH)
    model_cols = list(saved_X.columns)

    for doc in docs: #her veri kaydını tek tek işleme alıyoruz ama url i yoksa sonrakine geçiyoruz .
        url = doc.get("url")
        if not url:
            continue

        # --- Feature çıkarımı --- 
        feats = extract_features(url)
        X = pd.DataFrame([feats])

        for c in model_cols:    # özellik kontrolü, eğer özellikler eksik ise 0 olarak işaretleniyor. 
            if c not in X.columns:
                X[c] = 0

        X = X[model_cols].apply(pd.to_numeric, errors="coerce").fillna(0)# özellikler aynı sıraya getirliyor .

        proba = model.predict_proba(X)[:, 1][0]

        # --- ML ön filtre --- 2 adımlı doğrulamada 1. adım 
        if proba >= THRESHOLD:
            ml_status = "şüpheli"
        else:
            ml_status = "güvenli"

        # --- VT verdict (veriden oku) --- 2. adım vt den snouçlar döndürülür
        vt_verdict = doc.get("vt_summary", {}).get("verdict")

        # --- Hibrit karar --- 0 1 2 kararları var 0 güvenli 1 zararlı 2 şüpheli demek 
        if ml_status == "güvenli":
            hibrit_result = 0      # güvenli
        else:
            if vt_verdict == "malicious":
                hibrit_result = 1  # zararlı
            else:
                hibrit_result = 2  # şüpheli burda sonucun ya şüpheli yada güvenli olma ihitmali var iki durumda da şüpheli olarak işratlenir

        # --- MongoDB kayıt  ---
        collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {
                "ml_proba": float(proba),
                "ml_status": ml_status,
                "hibrit_result": hibrit_result
            }}
        )

        print(
            f"[ML:{ml_status}] [VT:{vt_verdict}] "
            f"[SON:{hibrit_result}] → {url}"
        )


if __name__ == "__main__":
    run_pipeline()
