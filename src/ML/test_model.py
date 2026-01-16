# test_known_labels.py
import os
import pandas as pd
import joblib
import urllib.parse
import re
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt

# 🔧 Dosya yolları
INPUT_CSV = r"C:\Users\Umut Yorulmuş\Desktop\phishing_project\data\urldata.csv"
MODEL_PATH = "models/phishing_model_irst.joblib"
SAVED_FEATURES_PATH = "models/features_irst.joblib"
RESULTS_CSV = "models/test_known_labels_results.csv"
WRONG_CSV = "models/test_known_labels_wrong.csv"
PROBA_PNG = "models/test_known_labels_proba.png"


THRESHOLD = 0.75 

#  özellik çıkarımı
def extract_features(url):
    s = str(url)
    parsed = urllib.parse.urlparse(s)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    def count_char(t, chars): return sum(t.count(c) for c in chars)
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
        "port": 1 if parsed.port else 0,
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

# main işlem
def main():
    #csv dosyasının yüklenmesi, url ve label aranması 
    if not os.path.exists(INPUT_CSV):
        print("CSV bulunamadı:", INPUT_CSV); return
    df = pd.read_csv(INPUT_CSV)
    if "url" not in df.columns or "result" not in df.columns:
        print("CSV'de 'url' ve 'result' kolonları yok."); return
    df = df[["url", "result"]].dropna()
    df["label"] = df["result"].astype(int)
    # her url için özellik çıkarımının baaşlatılması 

    print(" Feature extraction başlıyor...")
    feats = []
    for u in df["url"]:
        try:
            feats.append(extract_features(u))
        except Exception:
            #özellik çıkarımında bulunamayn bir değer ise yerine 0 ekleniyor
            feats.append({k: 0 for k in extract_features("")})
    X = pd.DataFrame(feats)
    y_true = df["label"].values
    print(f" Feature set hazır: {X.shape[0]} örnek")
    #modeli yükleme 
    if not os.path.exists(MODEL_PATH):
        print("🔴 Model bulunamadı:", MODEL_PATH); return
    model = joblib.load(MODEL_PATH)
    print("📥 Model yüklendi.")

    # kaydedilen model özellik veri leri ile yeni urllerin özellik verilerinin hizalanması (hizalanamssa yanlış değer verir)
    if os.path.exists(SAVED_FEATURES_PATH):
        saved_X = joblib.load(SAVED_FEATURES_PATH)
        model_cols = list(saved_X.columns)
        for c in model_cols:
            if c not in X.columns:
                X[c] = 0
        X = X[model_cols]
        print("✅ Feature'lar hizalandı.")

    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)
    proba = model.predict_proba(X)[:,1]
    y_pred = (proba > THRESHOLD).astype(int)

    print(f"\n Sınıflandırma Raporu (eşik = {THRESHOLD}):")
    print(classification_report(y_true, y_pred, digits=4, zero_division=0))
    print("\n🧾 Karışıklık Matrisi:")
    print(confusion_matrix(y_true, y_pred))

    out = df.copy()
    out["pred"] = y_pred
    out["proba"] = proba
    out.to_csv(RESULTS_CSV, index=False)
    print(" Sonuçlar kaydedildi ->", RESULTS_CSV)

    wrong = out[out["label"] != out["pred"]]
    wrong.to_csv(WRONG_CSV, index=False)
    print(" Yanlış sınıflananlar kaydedildi ->", WRONG_CSV)

    plt.figure(figsize=(6,4))
    plt.hist(proba, bins=50)
    plt.xlabel("P(phishing)"); plt.ylabel("count")
    plt.title("predict_proba distribution")
    plt.tight_layout()
    plt.savefig(PROBA_PNG)
    print(" proba histogramı kaydedildi ->", PROBA_PNG)

if __name__ == "__main__":
    main()