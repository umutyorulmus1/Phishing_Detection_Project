import os
import base64
import time
import requests
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
MONGO_URI = os.getenv("MONGO_URI") or "mongodb://localhost:27017/"

client = MongoClient(MONGO_URI)
db = client["phishing_db"]
social_collection = db["social_urls"]

#virus totale url i gönderiyoruz tarama yapması için
def submit_to_vt(url: str) -> bool:
    if not VT_API_KEY:
        return False
    headers = {"x-apikey": VT_API_KEY}
    submit_url = "https://www.virustotal.com/api/v3/urls"
    try:
        response = requests.post(submit_url, headers=headers, data={"url": url}, timeout=15)
    except Exception as e:
        print(f"[submit_to_vt] exception for {url}: {e}")
        return False
    return response.status_code in (200, 201, 202)

# urlin vt analiz sonuçlarını alıyoruz
def get_vt_result(url: str) -> dict:
    if not VT_API_KEY:
        return {"error": "VT_API_KEY bulunamadı"}
    headers = {"x-apikey": VT_API_KEY}
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    try:
        response = requests.get(vt_url, headers=headers, timeout=15)
    except Exception as e:
        return {"error": f"request_exception: {e}"}
    if response.status_code == 200:
        try:
            data = response.json()
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        except Exception:
            return {"error": "Beklenmeyen API yanıt formatı"}
    elif response.status_code == 404:
        return {"error": "URL VirusTotal veritabanında bulunamadı"}
    elif response.status_code == 429:
        # rate limit
        retry_after = response.headers.get("Retry-After")
        return {"error": "rate_limited", "retry_after": int(retry_after) if retry_after and retry_after.isdigit() else None}
    else:
        return {"error": f"Status code {response.status_code}"}

#vt nin analiz sonuçlarından zararlı mı güvenli mi olduğunu hesaplama
def summarize_vt_entry(vt_entry: dict) -> dict:
    if not vt_entry or "error" in vt_entry:
        # hata veya boşsa unknown döndür
        return {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "timeout": 0,
            "total": 0,
            "positives": 0,
            "ratio": None,
            "verdict": "unknown",
            "note": vt_entry.get("error") if isinstance(vt_entry, dict) else None
        }

    stats = vt_entry
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    timeout = int(stats.get("timeout", 0))
    total = malicious + suspicious + harmless + undetected + timeout
    positives = malicious + suspicious
    ratio = (positives / total) if total > 0 else None

    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0 or (ratio is not None and ratio >= 0.1):
        verdict = "suspicious"
    elif total == 0:
        verdict = "unknown"
    else:
        verdict = "clean"

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "total": total,
        "positives": positives,
        "ratio": ratio,
        "verdict": verdict
    }

# risk skoru 1 den büyük olanları ve vt kontrolü yapılmayanları işleme alıyoruz
def run_vt_checker(limit=400, delay=120, max_retries=10):
    urls_cursor = list(social_collection.find({
        "risk_score": {"$gte": 1},
        "vt_checked": {"$exists": False}
    }).limit(limit))

    total_urls = len(urls_cursor)
    print(f"🚀 GET işlemi başlatıldı... Toplam {total_urls} URL kontrol edilecek.")

    # İlk submit sadece virus total kontrol edilmemişse ve submit atılmamışsa yapılıyor
    for item in urls_cursor:
        url = item.get("url")
        if url and not item.get("submit") and not item.get("vt_checked"):
            if submit_to_vt(url):
                social_collection.update_one({"_id": item["_id"]}, {"$set": {"submit": True}})
                item["submit"] = True
                print(f"🚀 Submit edildi: {url}")

    attempt = 0
    remaining = total_urls

    while remaining > 0 and attempt < max_retries:
        attempt += 1
        for item in urls_cursor:
            if item.get("vt_checked"):
                continue
            url = item.get("url")
            if not url:
                continue

            vt_result = get_vt_result(url)
            # rate limit handling: eğer rate limited döndüyse bekle ve devam et
            if isinstance(vt_result, dict) and vt_result.get("error") == "rate_limited":
                ra = vt_result.get("retry_after") or 30
                print(f"429 rate limit alındı, {ra}s bekleniyor...")
                time.sleep(ra)
                continue

            summary = summarize_vt_entry(vt_result)

            if summary["verdict"] != "unknown":
                # vt_note varsa silinsin: $unset eklendi
                social_collection.update_one(
                    {"_id": item["_id"]},
                    {
                        "$set": {"vt_checked": True, "vt_summary": summary},
                        "$unset": {"vt_note": ""}
                    }
                )
                item["vt_checked"] = True
                print(f"✅ Sonuç alındı: {url} -> {summary['verdict']}")
            else:
                if attempt >= 5 and not item.get("vt_checked"):
                    print(f"🔄 {url} için tekrar submit ediliyor (deneme {attempt})...")
                    if submit_to_vt(url):
                        social_collection.update_one({"_id": item["_id"]}, {"$set": {"submit": True}})
                        item["submit"] = True
                        print(f"✅ Tekrar submit başarılı: {url}")

        checked = sum(1 for item in urls_cursor if item.get("vt_checked"))
        remaining = total_urls - checked

        print(f"✅ Alınan: {checked} | ⏳ Alınamayan: {remaining}")

        if remaining > 0 and attempt < max_retries:
            print(f"⏳ Bekleniyor... {delay} sn sonra tekrar denenecek. (Deneme {attempt}/{max_retries})")
            time.sleep(delay)

    # Eğer hâlâ alınamayan sonuç varsa bilinmiyor olarak işaretle ve vt_note sil
    if remaining > 0:
        for item in urls_cursor:
            if not item.get("vt_checked"):
                social_collection.update_one(
                    {"_id": item["_id"]},
                    {
                        "$set": {"vt_checked": True, "vt_summary": {"verdict": "timeout"}},
                        "$unset": {"vt_note": ""}
                    }
                )
        print(f"⚠️ {remaining} URL için sonuç alınamadı, timeout olarak işaretlendi.")
    else:
        print("🎉 Tüm sonuçlar alındı, işlem bitti.")

if __name__ == "__main__":
    run_vt_checker()