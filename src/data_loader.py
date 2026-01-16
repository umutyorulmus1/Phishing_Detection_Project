import pandas as pd

def load_data(safe_path: str, malicious_path: str) -> pd.DataFrame:
    # Güvenli siteleri oku (her satır bir domain)
    with open(safe_path, "r", encoding="utf-8") as f:
        safe_domains = [line.strip() for line in f if line.strip()]
    safe_df = pd.DataFrame({'url': safe_domains, 'label': 0})

    # Zararlı siteleri oku (CSV gibi satırlar)
    try:
        malicious_df_raw = pd.read_csv(malicious_path, sep=",", encoding="utf-8", on_bad_lines='skip')
        if 'url' in malicious_df_raw.columns:
            malicious_urls = malicious_df_raw['url'].dropna().tolist()
        else:
            # Eğer 'url' sütunu yoksa tüm satırları al
            malicious_urls = [line.strip() for line in open(malicious_path, "r", encoding="utf-8") if line.strip()]
    except Exception as e:
        print(f"Hata oluştu: {e}")
        malicious_urls = []

    malicious_df = pd.DataFrame({'url': malicious_urls, 'label': 1})

    # Veri setlerini birleştir
    df = pd.concat([safe_df, malicious_df], ignore_index=True)
    return df