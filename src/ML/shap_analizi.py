import pandas as pd
import shap
import joblib
import urllib.parse
import re
import matplotlib.pyplot as plt
import os

# 🔧 Dosya yolları
MODEL_PATH = "models/phishing_model_irst.joblib"
FEATURES_PATH = "models/features_irst.joblib"
WRONG_CSV = "models/test_known_labels_post_wrong.csv"
SHAP_PNG = "models/shap_wrong_summary.png"
SHAP_HTML = "models/shap_wrong_summary.html"

# 🔍 Feature extractor
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

# 🚀 SHAP analizi
def main():
    print("🚀 SHAP analizi başlıyor...")

    if not os.path.exists(WRONG_CSV):
        print("❌ Dosya bulunamadı:", WRONG_CSV)
        return
    df = pd.read_csv(WRONG_CSV)
    print("✅ CSV yüklendi. Satır sayısı:", len(df))
    if df.empty:
        print("⚠️ CSV boş, analiz yapılacak örnek yok.")
        return

    urls = df["url"].values[:50]
    print("🔍 İlk 50 URL seçildi.")

    feats = []
    for i, u in enumerate(urls):
        try:
            feats.append(extract_features(u))
        except Exception as e:
            print(f"⚠️ Feature çıkarımı hatası (satır {i}):", e)
            feats.append({k: 0 for k in extract_features("")})
    X = pd.DataFrame(feats)
    print("✅ Feature çıkarımı tamamlandı.")

    if os.path.exists(FEATURES_PATH):
        saved_X = joblib.load(FEATURES_PATH)
        model_cols = list(saved_X.columns)
        for c in model_cols:
            if c not in X.columns:
                X[c] = 0
        X = X[model_cols]
        print("✅ Feature hizalama tamamlandı.")

    model = joblib.load(MODEL_PATH)
    print("✅ Model yüklendi.")

    explainer = shap.Explainer(model, X)
    shap_values = explainer(X)
    print("✅ SHAP değerleri hesaplandı.")

    shap.summary_plot(shap_values, X, show=False)
    plt.tight_layout()
    plt.savefig(SHAP_PNG)
    print("📊 SHAP PNG görseli kaydedildi ->", SHAP_PNG)

    shap.save_html(SHAP_HTML, shap_values)
    print("🌐 SHAP HTML görseli kaydedildi ->", SHAP_HTML)

    print("✅ SHAP analizi tamamlandı.")

if __name__ == "__main__":
    main()