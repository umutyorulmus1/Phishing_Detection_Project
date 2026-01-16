import pandas as pd
import re
import os
import random
from dotenv import load_dotenv
from pymongo import MongoClient
from keywords import risk_keywords
from src.social.save_social_to_mongo import save_social_data

# 📁 CSV dosyasının yolu
csv_path = r"C:\Users\Umut Yorulmuş\Desktop\phishing_project\data\phishing_url.csv"

# Mongo bağlantısı
load_dotenv()
client = MongoClient(os.getenv("MONGO_URI"))
db = client["phishing_db"]
collection = db["social_urls"]

# Risk skoru hesaplama fonksiyonu
def text_risk_score(text: str) -> int:
    text = text.lower()
    score = 0

    # Anahtar kelime eşleşmeleri
    score += sum(1 for word in risk_keywords if word in text)

    # Regex kalıpları
    regex_patterns = {
        "iban": r"\bTR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\b",
        "email": r"\b\S+@\S+\.\S+\b",
        "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "url": r"https?://\S+",
        "phone": r"\b0\d{10}\b"
    }

    for pattern in regex_patterns.values():
        if re.search(pattern, text):
            score += 1

    return score

# Kaggle verisini MongoDB'ye kaydeden fonksiyon
def import_kaggle_urls():
    df = pd.read_csv(csv_path)
    print("📄 CSV sütunları:", df.columns.tolist())

    if "Domain" not in df.columns:
        print("❌ 'Domain' sütunu bulunamadı.")
        return

    urls = df["Domain"].dropna().tolist()

    # 🔀 Verileri karıştır ve ilk 100 tanesini al
    random.shuffle(urls)
    urls = urls[:100]

    saved_count = 0
    print("🚀 Kaggle verisi MongoDB'ye aktarılıyor...\n")

    for i, raw_url in enumerate(urls, 1):
        # 🔧 Normalize et
        normalized_url = raw_url
        if not normalized_url.startswith("http"):
            normalized_url = "https://" + normalized_url

        # 🔍 Aynı URL daha önce kaydedilmiş mi?
        if collection.find_one({"urls": [normalized_url]}):
            print(f"⏩ Zaten kayıtlı, atlandı: {normalized_url}")
            continue

        # 🔢 Risk skoru hesapla
        score = text_risk_score(normalized_url)
        if score < 2:
            score = 2

        # 🏷️ Label varsa al
        label = None
        if "Label" in df.columns:
            label_row = df[df["Domain"] == raw_url]
            if not label_row.empty:
                label = int(label_row["Label"].values[0])

        # 📦 Kayıt oluştur
        doc = {
            "text": normalized_url,
            "urls": [normalized_url],
            "text_risk_score": score,
            "source": "kaggle"
        }

        if label is not None:
            doc["label"] = label  # ✅ Zararlı (1) / Zararsız (0)

        save_social_data(doc)
        saved_count += 1
        print(f"✅ {saved_count}. kayıt eklendi | Skor: {score} | Label: {label} | URL: {normalized_url}")

    print(f"\n📦 Toplam kaydedilen yeni Kaggle verisi: {saved_count}")



# Ana çalıştırma bloğu
if __name__ == "__main__":
    import_kaggle_urls()
    
#python -m src.ML.test_data