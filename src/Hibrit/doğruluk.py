# compare_ml_vs_vt_minimal.py
import os
import json
import pandas as pd
from pymongo import MongoClient
from dotenv import load_dotenv
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI") or "mongodb://localhost:27017/"
DB_NAME = "phishing_db"
COLLECTION_NAME = "social_urls"

OUT_DIR = "models/compare_outputs_minimal"
OUT_CSV = os.path.join(OUT_DIR, "ml_vs_vt_rows_minimal.csv")
os.makedirs(OUT_DIR, exist_ok=True)

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

def vt_to_label(vt_summary):
    if not vt_summary:
        return None
    verdict = vt_summary.get("verdict")
    if verdict:
        v = str(verdict).lower()
        if v in ("malicious", "suspicious", "phishing", "malware"):
            return 1
        if v in ("clean", "harmless", "benign"):
            return 0
        return None
    positives = vt_summary.get("positives")
    try:
        if positives is not None:
            if int(positives) > 0:
                return 1
            if int(positives) == 0:
                return 0
    except Exception:
        pass
    return None

def fetch_rows(limit=None):
    proj = {"_id": 1, "vt_summary": 1, "ml_result": 1}
    cursor = collection.find({}, proj)
    if limit:
        cursor = cursor.limit(int(limit))
    rows = []
    for doc in cursor:
        vt_label = vt_to_label(doc.get("vt_summary") or {})
        if vt_label is None:
            continue
        ml_res = doc.get("ml_result")
        if ml_res is None:
            continue
        rows.append({
            "_id": str(doc.get("_id")),
            "vt_label": int(vt_label),
            "ml_result": int(ml_res)
        })
    return pd.DataFrame(rows)

def evaluate(df):
    df_eval = df.copy()
    if df_eval.empty:
        print("Değerlendirilecek veri yok.")
        return
    y_true = df_eval["vt_label"].values
    y_pred = df_eval["ml_result"].values
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    print("=== ML vs VT (sadece ml_result ve vt verdict) ===")
    print(f"Toplam örnek: {len(df_eval)}")
    print(f"Accuracy: {acc:.4f}, Precision: {prec:.4f}, Recall: {rec:.4f}, F1: {f1:.4f}")
    print("Confusion matrix (tn, fp, fn, tp):", cm.ravel() if cm.size==4 else cm)
    print("\nClassification report:")
    print(classification_report(y_true, y_pred, digits=4, zero_division=0))
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "confusion_matrix": cm.tolist()}

def main(limit=None):
    df = fetch_rows(limit=limit)
    print(f"Toplanan satır sayısı (VT net + ml_result mevcut): {len(df)}")
    if df.empty:
        return
    df.to_csv(OUT_CSV, index=False)
    print("Ham veri kaydedildi ->", OUT_CSV)
    evaluate(df)

if __name__ == "__main__":
    # test için limit=1000 yazabilirsin; production için None
    main(limit=None)