#!/usr/bin/env python3
# compare_thresholds_with_075.py
import os
import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

# CSV yolunu gerektiği gibi değiştir
CSV_PATH = "models/threshold_tuning_outputs/ml_reproba_rows.csv"

def load_data(path):
    if not os.path.exists(path):
        raise SystemExit(f"CSV bulunamadı: {path}")
    df = pd.read_csv(path)
    if "proba" not in df.columns or "vt_label" not in df.columns:
        raise SystemExit("CSV içinde 'proba' veya 'vt_label' sütunu bulunamadı.")
    return df

def evaluate_thresholds(df, thresholds):
    y = df["vt_label"].values
    proba = df["proba"].values
    results = {}
    for thr in thresholds:
        preds = (proba >= thr).astype(int)
        prec = precision_score(y, preds, zero_division=0)
        rec = recall_score(y, preds, zero_division=0)
        f1 = f1_score(y, preds, zero_division=0)
        cm = confusion_matrix(y, preds)
        if cm.size == 4:
            tn, fp, fn, tp = cm.ravel()
        else:
            # Tek sınıflı durumlarda uygun doldurma
            tn = fp = fn = tp = 0
            if cm.shape == (1,1):
                if (y == 0).all():
                    tn = int(cm[0,0])
                else:
                    tp = int(cm[0,0])
        results[thr] = {"precision": prec, "recall": rec, "f1": f1,
                        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    return results

def print_comparison(results, reference=0.71):
    ref = results.get(reference)
    if ref is None:
        raise SystemExit(f"Referans eşiği ({reference}) sonuçlarda yok.")
    header = f"{'thr':>6}  {'prec':>6}  {'rec':>6}  {'f1':>6}    tn   fp   fn   tp   ΔTP  ΔFP"
    print(header)
    for thr in sorted(results.keys()):
        r = results[thr]
        delta_tp = r["tp"] - ref["tp"]
        delta_fp = r["fp"] - ref["fp"]
        print(f"{thr:6.2f}  {r['precision']:.4f}  {r['recall']:.4f}  {r['f1']:.4f}  "
              f"{r['tn']:4d} {r['fp']:4d} {r['fn']:4d} {r['tp']:4d}  {delta_tp:4d} {delta_fp:4d}")

def main():
    df = load_data(CSV_PATH)
    thresholds = [0.71, 0.75, 0.80, 0.85]
    results = evaluate_thresholds(df, thresholds)
    print_comparison(results, reference=0.71)

if __name__ == "__main__":
    main()