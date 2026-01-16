from src.social.url_extractor import extract_urls
from src.social.link_expander import expand_url
from src.social.whois_utils import extract_whois_features
from src.social.html_utils import get_html_content
from src.social.save_social_to_mongo import save_social_data
from src.social.reddit_scraper import fetch_posts
from src.social.text_risk_score import text_risk_score
# from src.social.twitter_scraper import fetch_tweets  # istersen açabilirsin


def collect_social_urls():
    texts = fetch_posts()
    # texts = fetch_tweets()  # Twitter kullanmak istersen aç
    saved_count = 0

    try:
        for i, text in enumerate(texts, 1):

            # -----------------------------
            # URL ÇIKARMA
            # -----------------------------
            urls = extract_urls(text)
            if not urls:
                continue

            # URL genişlet (t.co vb.)
            expanded_urls = []
            for u in urls:
                try:
                    expanded_urls.append(expand_url(u))
                except Exception as e:
                    print(f"⚠ URL genişletilemedi: {u} | Hata: {e}")
                    continue

            for url in expanded_urls:
                try:
                    # -----------------------------
                    # WHOIS - HTML - RİSK ANALİZİ
                    # -----------------------------
                    whois_data = extract_whois_features(url)
                    html_content = get_html_content(url)
                    score, hits = text_risk_score(text, whois_data, html_content)

                    # düşük riskliyse kaydetme
                    if score < 2:
                        continue

                    # -----------------------------
                    # MONGOYA KAYDET
                    # -----------------------------
                    save_social_data({
                        "url": url,
                        "text": text,
                        "risk_score": score,
                        "keyword_hits": hits
                    })

                    saved_count += 1
                    print(f"✅ {saved_count}. kayıt eklendi | URL: {url} | Risk: {score:.2f}")

                except Exception as e:
                    print(f"⚠ İşlem sırasında hata: {url} | Hata: {e}")
                    continue

    except KeyboardInterrupt:
        print(f"\n🛑 Kullanıcı durdurdu. Toplam {saved_count} URL kaydedildi.")

    print(f"\n📦 Toplam kaydedilen URL sayısı: {saved_count}")


if __name__ == "__main__":
    collect_social_urls()
