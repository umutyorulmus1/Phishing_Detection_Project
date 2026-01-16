import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI") or "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)
db = client["phishing_db"]
social_collection = db["social_urls"]

def verdict_to_binary(verdict: str, ml_result: int) -> int:
    """
    VT verdict değerini 0/1'e indirger.
    malicious/suspicious → 1 (phishing)
    clean → 0 (güvenli)
    unknown → ML sonucuna bak sadece
    """
    if verdict in ["malicious", "suspicious"]:
        return 1
    elif verdict == "clean":
        return 0
    elif verdict == "unknown":
        return ml_result
    return ml_result  # sadece ml sonucu al 

def run_hibrit(limit=1000):
    """
    MongoDB'den hibrit_result olmayan kayıtları alır,
    ML ve VT sonuçlarını karşılaştırır, hibrit_result yazar.
    """
    docs = social_collection.find({"hibrit_result": {"$exists": False}}).limit(limit)

    for doc in docs:
        ml_result = doc.get("ml_result")
        vt_summary = doc.get("vt_summary", {})
        vt_verdict = vt_summary.get("overall_verdict")

        # Eğer ML sonucu yoksa hibrit yapılamaz
        if ml_result is None:
            continue

        # Eğer VT sonucu yoksa → sadece ML kararını al
        if vt_verdict is None:
            hibrit_result = ml_result
            vt_note = "VT not checked"
        else:
            vt_binary = verdict_to_binary(vt_verdict, ml_result)
            hibrit_result = 1 if (ml_result == 1 or vt_binary == 1) else 0
            vt_note = f"VT checked: {vt_verdict}"

        # MongoDB güncelleme
        social_collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {
                "hibrit_result": hibrit_result,
                "vt_note": vt_note
            }}
        )

        print(f"✅ Hibrit: URL={doc.get('url')} | ML={ml_result}, VT={vt_note}, Hibrit={hibrit_result}")

if __name__ == "__main__":
    run_hibrit()