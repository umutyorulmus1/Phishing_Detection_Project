from dotenv import load_dotenv
load_dotenv()

import os
from pymongo import MongoClient
from src.threat_analysis.virustotal_check import check_virustotal
from src.threat_analysis.save_to_mongo import save_result

def summarize_vt_entry(vt_entry):
    """Bir VT cevabını özetler ve verdict çıkarır."""
    stats = vt_entry.get("last_analysis_stats") or {}
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

    needs_submit = (total == 0)

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "total": total,
        "positives": positives,
        "ratio": ratio,
        "verdict": verdict,
        "needs_submit": needs_submit
    }

def analyze_existing_social_urls():
    client = MongoClient(os.getenv("MONGO_URI"))
    db = client["phishing_db"]
    social_collection = db["social_urls"]

    # ✅ Daha önce VT kontrolü yapılmamış ve risk skoru ≥ 1 olanları al
    urls_cursor = social_collection.find({
        "text_risk_score": {"$gte": 1},
        "vt_checked": {"$exists": False}
    })

    for item in urls_cursor:
        url_list = item["urls"]
        source_text = item.get("source_text", "")

        vt_summaries = []

        for url in url_list:
            vt_result = check_virustotal(url)
            summary = summarize_vt_entry(vt_result)
            vt_summaries.append(summary)

        # ✅ Toplu verdict hesapla (unknown da dahil)
        overall_verdict = "clean"
        needs_submit_any = False
        for s in vt_summaries:
            if s.get("verdict") == "malicious":
                overall_verdict = "malicious"
                break
            elif s.get("verdict") == "suspicious":
                overall_verdict = "suspicious"
            elif s.get("verdict") == "unknown" and overall_verdict == "clean":
                overall_verdict = "unknown"
            if s.get("needs_submit"):
                needs_submit_any = True

        # ✅ VT sonucu ayrı koleksiyona kaydet
        result = {
            "urls": url_list,
            "text_risk_score": item["text_risk_score"],
            "source_text": source_text,
            "vt_summary": {
                "per_entry": vt_summaries,
                "overall_verdict": overall_verdict,
                "needs_submit": needs_submit_any
            }
        }
        save_result(result)

        # ✅ VT kontrolü yapıldığını işaretle
        social_collection.update_one(
            {"_id": item["_id"]},
            {"$set": {"vt_checked": True}}
        )

        print(f"✅ VT özet kaydedildi: {url_list} | Verdict: {overall_verdict}")

if __name__ == "__main__":
    analyze_existing_social_urls()

#python -m src.threat_analysis.threat_analysis_pipeline