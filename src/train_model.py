# phishing_train_modified.py

import os
import sys
import re
import time
import joblib
import socket
import urllib.parse
from functools import partial

import pandas as pd
import numpy as np
from tqdm import tqdm
import requests
from bs4 import BeautifulSoup
import tldextract

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.feature_selection import VarianceThreshold
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

# ---------- Ayarlar ----------
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model_modified.joblib")
FEATURES_PATH = os.path.join(MODEL_DIR, "feature_names_modified.joblib")

DATA_PATH = r"C:\Users\Umut Yorulmuş\Desktop\phishing_project\data\phishing_site_urls.csv"
FETCH_HTML = False
REQUEST_TIMEOUT = 4
REQUEST_RETRIES = 1
RANDOM_STATE = 42
# -----------------------------

def safe_request_get(url, timeout=REQUEST_TIMEOUT, retries=REQUEST_RETRIES):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; PhishDetector/1.0; +https://example.com/bot)"
    }
    for attempt in range(retries + 1):
        try:
            return requests.get(url, headers=headers, timeout=timeout)
        except (requests.RequestException, socket.timeout):
            if attempt == retries:
                return None
            time.sleep(0.5)
    return None

def count_char(s, chars):
    return sum(s.count(c) for c in chars)

def safe_len(s):
    return len(s) if s is not None else 0

def extract_features(url, fetch_html=FETCH_HTML):
    if not isinstance(url, str):
        url = str(url)

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    domain_parts = tldextract.extract(url)
    domain = domain_parts.domain or ""
    suffix = domain_parts.suffix or ""

    # HTML tabanlı özelliklerin defaultları
    login_form = external_favicon = iframe = popup_window = onmouseover = empty_title = 0

    if fetch_html:
        resp = safe_request_get(url)
        if resp and resp.status_code == 200 and resp.text:
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
                forms = soup.find_all("form")
                login_form = 1 if any("login" in (f.get_text() or "").lower() for f in forms) else (1 if forms else 0)
                link_icon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
                external_favicon = 1 if link_icon and link_icon.get("href", "").startswith("http") else 0
                iframe = 1 if soup.find("iframe") else 0
                popup_window = 1 if "window.open" in resp.text else 0
                onmouseover = 1 if "onmouseover" in resp.text else 0
                empty_title = 1 if (not soup.title or not (soup.title.string or "").strip()) else 0
            except Exception:
                pass

    hostname_parts = hostname.split(".") if hostname else []
    nb_subdomains = max(0, len(hostname_parts) - 2) if hostname else 0

    ratio_digits_url = sum(c.isdigit() for c in url) / safe_len(url) if safe_len(url) > 0 else 0
    ratio_digits_host = sum(c.isdigit() for c in hostname) / safe_len(hostname) if safe_len(hostname) > 0 else 0

    path_segments = [p for p in path.split("/") if p]
    if path_segments:
        shortest_word_path = min(len(p) for p in path_segments)
        longest_word_path = max(len(p) for p in path_segments)
        avg_word_path = sum(len(p) for p in path_segments) / len(path_segments)
        char_repeat = max(path.count(c) for c in set(path)) if path else 0
    else:
        shortest_word_path = longest_word_path = avg_word_path = char_repeat = 0

    features = {
        "url_length": safe_len(url),
        "length_hostname": safe_len(hostname),
        "ip_in_host": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", hostname) else 0,
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
        "nb_semicolon": url.count(";"),
        "nb_dollar": url.count("$"),
        "nb_space": url.count(" "),
        "nb_www": url.lower().count("www"),
        "nb_com": url.lower().count(".com"),
        "nb_dslash": url.count("//"),
        "http_in_path": 1 if "http" in path else 0,
        "https_token": 1 if "https" in url[8:] else 0,
        "ratio_digits_url": ratio_digits_url,
        "ratio_digits_host": ratio_digits_host,
        "punycode": 1 if "xn--" in url else 0,
        "port": 1 if parsed.port else 0,
        "tld_in_path": 1 if re.search(r"\.(com|net|org|xyz|ru|info|gov|edu)", path) else 0,
        "tld_in_subdomain": 1 if hostname_parts and re.search(r"\.(com|net|org|xyz|ru|info|gov|edu)", hostname_parts[0]) else 0,
        "abnormal_subdomain": 1 if len(hostname_parts) > 3 else 0,
        "nb_subdomains": nb_subdomains,
        "prefix_suffix": 1 if "-" in hostname else 0,
        "shortening_service": 1 if any(s in url for s in ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd"]) else 0,
        "path_extension": 1 if re.search(r"\.(php|html|aspx|jsp|exe|zip|rar)$", path) else 0,
        "char_repeat": char_repeat,
        "shortest_word_path": shortest_word_path,
        "longest_word_path": longest_word_path,
        "avg_word_path": avg_word_path,
        "has_suspicious_keywords": 1 if any(kw in url.lower() for kw in ["login","secure","update","verify","bank","account","signin","wp-admin","confirm"]) else 0,
        "contains_email": 1 if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", url) else 0,
        "is_encoded": 1 if "%" in url else 0,
        "has_double_slash": 1 if url.count("//") > 1 else 0,
        "has_redirect": 1 if "//" in path else 0,
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": count_char(url, "?=&%$@!*^~()[]{}"),
        "contains_brand_name": 1 if any(b in url.lower() for b in ["paypal","amazon","apple","google","microsoft","facebook","instagram","bank"]) else 0,
        "login_form": login_form,
        "external_favicon": external_favicon,
        "iframe": iframe,
        "popup_window": popup_window,
        "onmouseover": onmouseover,
        "empty_title": empty_title
    }

    return features

def train_and_save_model(data_path=DATA_PATH, model_path=MODEL_PATH, features_path=FEATURES_PATH, fetch_html=FETCH_HTML):
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"CSV bulunamadı: {data_path}")

    df = pd.read_csv(data_path)
    df.columns = [c.strip() for c in df.columns]

    url_col = None
    label_col = None
    for c in df.columns:
        if c.lower() in ("url", "link", "website"):
            url_col = c
        if c.lower() in ("label", "class"):
            label_col = c

    if url_col is None or label_col is None:
        raise ValueError("CSV'de 'URL' ve 'Label' kolonları bulunamadı.")

    df = df[[url_col, label_col]].dropna()
    df = df.rename(columns={url_col: "url", label_col: "label"})

    # --------- BURADA LABELLERİ TERS ÇEVİRDİK ---------
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df["label"] = df["label"].map({
        "good": 1, "legitimate": 1, "benign": 1,
        "bad": 0, "phishing": 0, "malicious": 0
    }).fillna(df["label"])

    if df["Label"].dtype == object:
        df["Label"] = df["Label"].astype(int)
    # ---------------------------------------------------

    print(f"📦 Toplam veri: {len(df)} satır. HTML fetch: {fetch_html}")

    feature_list = []
    errors = 0
    for url in tqdm(df["url"].tolist(), desc="Özellik çıkarılıyor"):
        try:
            feats = extract_features(url, fetch_html=fetch_html)
            feature_list.append(feats)
        except Exception:
            feature_list.append({k: 0 for k in extract_features("http://example.com", fetch_html=False).keys()})
            errors += 1

    if errors:
        print(f"⚠️ {errors} URL için özellik çıkarma hatası oluştu.")

    X = pd.DataFrame(feature_list)
    y = df["label"].reset_index(drop=True)

    vt = VarianceThreshold(threshold=0.0)
    try:
        vt.fit(X.fillna(0))
        mask = vt.get_support()
        kept_columns = X.columns[mask]
        X = X[kept_columns]
        print(f"🔍 Sabit/sabitleşmiş özellikler çıkarıldı. Kalan özellik sayısı: {len(kept_columns)}")
    except Exception:
        kept_columns = X.columns

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1
        ))
    ])

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    print("🔁 5-fold cross-validation (f1 macro):")
    try:
        cv_scores = cross_val_score(pipeline, X, y, cv=skf, scoring="f1_macro", n_jobs=-1)
        print("CV F1 macro scores:", np.round(cv_scores, 4))
        print("CV F1 macro mean:", np.round(cv_scores.mean(), 4))
    except Exception as e:
        print("CV sırasında hata:", e)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, stratify=y, random_state=RANDOM_STATE)
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    print("\n📊 Model Performansı (test set):")
    print(classification_report(y_test, y_pred, digits=4))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    clf = pipeline.named_steps["clf"]
    feature_names = list(X.columns)
    try:
        importances = clf.feature_importances_
        fi_df = pd.DataFrame({"feature": feature_names, "importance": importances}).sort_values("importance", ascending=False)
        print("\n🔎 En önemli 20 özellik:")
        print(fi_df.head(20).to_string(index=False))
    except Exception:
        pass

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(pipeline, model_path)
    joblib.dump(feature_names, features_path)
    print(f"\n✅ Model kaydedildi: {model_path}")
    print(f"✅ Feature isimleri kaydedildi: {features_path}")

    return pipeline, feature_names

def predict_url(url, model_path=MODEL_PATH, features_path=FEATURES_PATH):
    if not os.path.exists(model_path) or not os.path.exists(features_path):
        raise FileNotFoundError("Model veya feature_names dosyası bulunamadı.")

    pipeline = joblib.load(model_path)
    feature_names = joblib.load(features_path)

    feats = extract_features(url, fetch_html=False)
    X = pd.DataFrame([feats])
    for f in feature_names:
        if f not in X.columns:
            X[f] = 0
    X = X[feature_names]

    pred = pipeline.predict(X)[0]
    proba = pipeline.predict_proba(X)[0].max() if hasattr(pipeline, "predict_proba") else None

    return int(pred), float(proba) if proba is not None else None

if __name__ == "__main__":
    try:
        model, feature_names = train_and_save_model(data_path=DATA_PATH, model_path=MODEL_PATH, features_path=FEATURES_PATH, fetch_html=FETCH_HTML)
        print("\nÖrnek tahmin:")
        example_url = "http://example.com/login"
        pred, proba = predict_url(example_url)
        print(f"URL: {example_url} -> Tahmin: {'PHISHING' if pred==0 else 'LEGIT'} (prob: {proba})")
    except KeyboardInterrupt:
        print("\n🛑 Kullanıcı tarafından durduruldu (Ctrl+C).")
        sys.exit(0)
    except Exception as e:
        print("Beklenmeyen hata:", e)
        sys.exit(1)
