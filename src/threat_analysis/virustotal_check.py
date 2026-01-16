import requests
import base64
import os
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def check_virustotal(url: str) -> dict:
    """
    Verilen URL'yi VirusTotal API'sine gönderir ve analiz sonuçlarını döndürür.
    """
    if not VT_API_KEY:
        return {"error": "VT_API_KEY bulunamadı (.env dosyasını kontrol et)"}

    # URL'yi Base64 ile encode et (VT formatı)
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(vt_url, headers=headers)

    if response.status_code == 200:
        try:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return stats
        except KeyError:
            return {"error": "Beklenmeyen API yanıt formatı"}
    elif response.status_code == 404:
        return {"error": "URL VirusTotal veritabanında bulunamadı (önce submit etmen gerekebilir)"}
    elif response.status_code == 401:
        return {"error": "API anahtarı geçersiz veya eksik"}
    else:
        return {"error": f"Status code {response.status_code}"}
