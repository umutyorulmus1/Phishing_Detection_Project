import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import re
import urllib.parse
import tldextract

#  Dosya yolları
MODEL_PATH = "models/phishing_model_irst.joblib"
FEATURE_PATH = "models/features_irst.joblib"
DATA_PATH = r"C:\Users\Umut Yorulmuş\Desktop\phishing_project\data\phishing_site_urls.csv"

#  Özellik çıkarma 
def extract_features(url):
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    def count_char(s, chars):
        return sum(s.count(c) for c in chars)

    return {
        "url_length": len(url),
        "length_hostname": len(hostname),
        "ip": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", hostname) else 0,
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_and": url.count("&"),
        "nb_eq": url.count("="),
        "nb_underscore": url.count("_"),
        "nb_tilde": url.count("~"),
        "nb_percent": url.count("%"),
        "nb_slash": url.count("/"),
        "nb_star": url.count("*"),
        "nb_colon": url.count(":"),
        "nb_comma": url.count(","),
        "nb_semicolumn": url.count(";"),
        "nb_dollar": url.count("$"),
        "nb_space": url.count(" "),
        "nb_www": url.lower().count("www"),
        "nb_com": url.lower().count(".com"),
        "nb_dslash": url.count("//"),
        "http_in_path": 1 if "http" in path else 0,
        "https_token": 1 if "https" in url[8:] else 0,
        "ratio_digits_url": sum(c.isdigit() for c in url) / len(url),
        "ratio_digits_host": sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0,
        "punycode": 1 if "xn--" in url else 0,
        "port": 1 if parsed.port else 0,
        "tld_in_path": 1 if re.search(r"\.(com|net|org|xyz|ru|info)", path) else 0,
        "tld_in_subdomain": 1 if re.search(r"\.(com|net|org|xyz|ru|info)", hostname.split(".")[0]) else 0,
        "abnormal_subdomain": 1 if len(hostname.split(".")) > 3 else 0,
        "nb_subdomains": len(hostname.split(".")) - 2 if len(hostname.split(".")) > 2 else 0,
        "prefix_suffix": 1 if "-" in hostname else 0,
        "shortening_service": 1 if any(s in url for s in ["bit.ly", "tinyurl", "goo.gl", "t.co"]) else 0,
        "path_extension": 1 if re.search(r"\.(php|html|aspx|jsp|exe|zip)$", path) else 0,
        "char_repeat": max([path.count(c) for c in set(path)]) if path else 0,
        "shortest_word_path": min([len(p) for p in path.split("/") if p] or [0]),
        "longest_word_path": max([len(p) for p in path.split("/") if p] or [0]),
        "avg_word_path": sum([len(p) for p in path.split("/") if p]) / (len(path.split("/")) or 1),
        "has_suspicious_keywords": 1 if any(kw in url.lower() for kw in ["login", "secure", "update", "verify", "bank", "account", "signin", "wp-admin"]) else 0,
        "contains_email": 1 if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", url) else 0,
        "is_encoded": 1 if "%" in url else 0,
        "has_double_slash": 1 if url.count("//") > 1 else 0,
        "has_redirect": 1 if "//" in path else 0,
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": count_char(url, "?=&%$@!*^~"),
        "contains_brand_name": 1 if any(b in url.lower() for b in ["paypal", "amazon", "apple", "google", "microsoft", "facebook", "instagram"]) else 0
    }

def main():
    #veri yükleme
    print(" Veri yükleniyor...")
    df = pd.read_csv(DATA_PATH)
    df.rename(columns={"URL": "url", "Label": "label"}, inplace=True)
    df["label"] = df["label"].map({"good": 0, "bad": 1})
    df = df.dropna(subset=["url", "label"])
    print(f" Toplam veri: {len(df)} satır")
    #özellik çıkarımı
    print(" Feature extraction başlıyor...")
    feature_list = [extract_features(url) for url in df["url"]]
    X = pd.DataFrame(feature_list)
    y = df["label"]
    print(f" Feature set oluşturuldu: {X.shape[0]} örnek, {X.shape[1]} özellik")
    #özellik çıkarımların kaydı
    print(" Feature set .joblib olarak kaydediliyor (models klasörüne)...")
    os.makedirs("models", exist_ok=True)
    joblib.dump(X, FEATURE_PATH)
    print(f" Feature dosyası kaydedildi: {FEATURE_PATH}")
    #model eğitimi 80 lik eğitimi 20 lik test verisi 
    print(" Model eğitimi başlıyor...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    model = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
    model.fit(X_train, y_train)
    print(" Model eğitimi tamamlandı.")
    #test perormansının ölçülmesi
    print("\n Test set performansı:")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))
    #modelin kaydı
    print(" Model .joblib olarak kaydediliyor (models klasörüne)...")
    joblib.dump(model, MODEL_PATH)
    print(f" Model kaydedildi: {MODEL_PATH}")

if __name__ == "__main__":
    main()