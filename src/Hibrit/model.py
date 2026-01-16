import joblib
import pandas as pd
import urllib.parse, re
from pymongo import MongoClient
import os
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

# Model ve feature dosyaları
MODEL_PATH = "models/phishing_model_irst.joblib"
SAVED_FEATURES_PATH = "models/features_irst.joblib"

# MongoDB bağlantısı
MONGO_URI = os.getenv("MONGO_URI") or "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)
db = client["phishing_db"]
collection = db["social_urls"]

THRESHOLD = 0.75

#  özellik çıkarımı 
def extract_features(url):
    s = str(url)
    def count_char(t, chars): return sum(t.count(c) for c in chars)

# urli parçalara bölme 
    try:
        parsed = urllib.parse.urlparse(s)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        port_flag = 1 if parsed.port else 0
    except Exception as e:
        print(f"⚠️ URL parse hatası: {url} → {e}")
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
        "nb_tilde": s.count("~"),
        "nb_percent": s.count("%"),
        "nb_slash": s.count("/"),
        "nb_star": s.count("*"),
        "nb_colon": s.count(":"),
        "nb_comma": s.count(","),
        "nb_semicolumn": s.count(";"),
        "nb_dollar": s.count("$"),
        "nb_space": s.count(" "),
        "nb_www": s.lower().count("www"),
        "nb_com": s.lower().count(".com"),
        "nb_dslash": s.count("//"),
        "http_in_path": 1 if "http" in path else 0,
        "https_token": 1 if "https" in s[8:] else 0,
        "ratio_digits_url": sum(c.isdigit() for c in s) / (len(s) or 1),
        "ratio_digits_host": sum(c.isdigit() for c in hostname) / (len(hostname) or 1),
        "punycode": 1 if "xn--" in s else 0,
        "port": port_flag,
        "tld_in_path": 1 if re.search(r"\.(com|net|org|xyz|ru|info|io|app)$", path) else 0,
        "tld_in_subdomain": 1 if hostname and re.search(r"\.(com|net|org|xyz|ru|info|io|app)$", hostname.split(".")[0]) else 0,
        "abnormal_subdomain": 1 if len(hostname.split(".")) > 3 else 0,
        "nb_subdomains": len(hostname.split(".")) - 2 if len(hostname.split(".")) > 2 else 0,
        "prefix_suffix": 1 if "-" in hostname else 0,
        "shortening_service": 1 if any(sv in s for sv in ["bit.ly","tinyurl","goo.gl","t.co"]) else 0,
        "path_extension": 1 if re.search(r"\.(php|html|aspx|jsp|exe|zip|msi|png|sh)$", path) else 0,
        "char_repeat": max([path.count(c) for c in set(path)]) if path else 0,
        "shortest_word_path": min([len(p) for p in path.split("/") if p] or [0]),
        "longest_word_path": max([len(p) for p in path.split("/") if p] or [0]),
        "avg_word_path": sum([len(p) for p in path.split("/") if p]) / (len(path.split("/")) or 1),
        "has_suspicious_keywords": 1 if any(kw in s.lower() for kw in ["login","secure","update","verify","bank","account","signin","wp-admin","download","hiddenbin"]) else 0,
        "contains_email": 1 if re.search(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+", s) else 0,
        "is_encoded": 1 if "%" in s else 0,
        "has_double_slash": 1 if s.count("//") > 1 else 0,
        "has_redirect": 1 if "//" in path else 0,
        "num_digits": sum(c.isdigit() for c in s),
        "num_special_chars": count_char(s, "?=&%$@!*^~"),
        "contains_brand_name": 1 if any(b in s.lower() for b in ["paypal","amazon","apple","google","microsoft","facebook","instagram"]) else 0
    }

# Ana fonksiyon: MongoDB kayıtlarını ML ile kontrol et
def run_ml_on_mongo(limit=1000):
    docs = list(collection.find({"ml_result": {"$exists": False}}).limit(limit))
    if not docs:
        print("Kontrol edilecek yeni kayıt yok.")
        return

    model = joblib.load(MODEL_PATH)
    saved_X = joblib.load(SAVED_FEATURES_PATH)
    model_cols = list(saved_X.columns)
    #her url için özellik çıkarımı yapma 
    for doc in docs:
        url = doc.get("url")
        if not url:
            continue
        #eksik klon varsa tamamalama 
        feats = extract_features(url)
        X = pd.DataFrame([feats])
        for c in model_cols:
            if c not in X.columns:
                X[c] = 0
        X = X[model_cols].apply(pd.to_numeric, errors="coerce").fillna(0)

        # tahmin yapma 
        proba = model.predict_proba(X)[:,1][0]
        pred = int(proba > THRESHOLD)

        # sonucu kaydetme 
        collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {"ml_result": pred, "ml_proba": float(proba)}}
        )
        print(f"URL: {url} → ML sonucu: {pred}, olasılık: {proba:.4f}")

if __name__ == "__main__":
    run_ml_on_mongo()