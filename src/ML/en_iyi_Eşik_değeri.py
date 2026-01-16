# apply_threshold_postprocess.py
import pandas as pd
import os
from sklearn.metrics import classification_report, confusion_matrix

# 🔧 Dosya yolları
INPUT_CSV = "models/test_known_labels_results.csv"
OUTPUT_CSV = "models/test_known_labels_post.csv"
WRONG_CSV = "models/test_known_labels_post_wrong.csv"
THRESHOLD = 0.75  # En iyi eşik değeri

# 📥 Veri yükle
if not os.path.exists(INPUT_CSV):
    raise SystemExit(f"CSV bulunamadı: {INPUT_CSV}")

df = pd.read_csv(INPUT_CSV)
if "proba" not in df.columns or "label" not in df.columns:
    raise SystemExit("CSV'de 'proba' veya 'label' kolonu eksik.")

# 🔁 Yeni tahminleri üret
df["pred_post"] = (df["proba"] >= THRESHOLD).astype(int)

# 📊 Performans raporu
print(f"\n📊 Yeni eşik: {THRESHOLD}")
print(classification_report(df["label"], df["pred_post"], digits=4, zero_division=0))
print("\n🧾 Karışıklık Matrisi:")
print(confusion_matrix(df["label"], df["pred_post"]))

# 💾 Kaydet
os.makedirs(os.path.dirname(OUTPUT_CSV) or ".", exist_ok=True)
df.to_csv(OUTPUT_CSV, index=False)
print(f"\n💾 Güncellenmiş tahminler kaydedildi -> {OUTPUT_CSV}")

wrong = df[df["label"] != df["pred_post"]]
wrong.to_csv(WRONG_CSV, index=False)
print(f"⚠️ Yanlış sınıflananlar kaydedildi -> {WRONG_CSV}")