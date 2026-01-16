import praw
import os
import time
from dotenv import load_dotenv
from keywords import risk_keywords  

load_dotenv()
REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID")
REDDIT_SECRET = os.getenv("REDDIT_SECRET")
REDDIT_USER_AGENT = "phishing-detector"

reddit = praw.Reddit(
    client_id=REDDIT_CLIENT_ID,
    client_secret=REDDIT_SECRET,
    user_agent=REDDIT_USER_AGENT
)

def fetch_posts(limit_per_keyword=10, sleep_time=5):
    posts = []
    print("🚀 Reddit veri çekme işlemi başladı...\n")

    try:
        for kw in [k["keyword"] for k in risk_keywords]:
            print(f"🔍 '{kw}' kelimesi aranıyor...")
            time.sleep(sleep_time)
            try:
                results = reddit.subreddit("phishing").search(kw, limit=limit_per_keyword)
                count = 0
                for post in results:
                    posts.append(post.title + " " + (post.selftext or ""))
                    count += 1
                print(f"✅ {count} post eklendi.\n")
            except Exception as e:
                print(f"❌ Hata oluştu: {e}\n")

    except KeyboardInterrupt:
        print(f"\n🛑 Veri çekme durduruldu. Toplam {len(posts)} post alındı.\n")
        return posts

    print(f"🏁 Reddit veri çekme tamamlandı. Toplam {len(posts)} post alındı.\n")
    return posts