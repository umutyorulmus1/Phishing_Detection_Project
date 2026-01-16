import tweepy
import os
import time
from dotenv import load_dotenv
from keywords import risk_keywords  
from tweepy.errors import TooManyRequests

load_dotenv()
bearer_token = os.getenv("TWITTER_BEARER_TOKEN")
client = tweepy.Client(bearer_token=bearer_token)

def fetch_tweets(limit=10, sleep_time=5):
    tweets = []
    print("🚀 Twitter veri çekme işlemi başladı...\n")

    # 🔍 İlk 15 riskli kelimeyi al
    keywords_to_search = [kw["keyword"] for kw in risk_keywords][:15]
    query = " OR ".join(keywords_to_search)

    try:
        print(f"🔍 Sorgu: {query}")
        time.sleep(sleep_time)

        response = client.search_recent_tweets(
            query=query,
            max_results=limit,
            tweet_fields=["text", "lang"]
        )

        if response.data:
            for tweet in response.data:
                tweets.append(tweet.text)
            print(f"✅ {len(tweets)} tweet çekildi.\n")
        else:
            print("⚠️ Hiç tweet bulunamadı.\n")

    except TooManyRequests:
        print("⏳ Twitter API limiti aşıldı, 60 saniye bekleniyor...\n")
        time.sleep(60)
    except Exception as e:
        print(f"❌ Hata oluştu: {e}\n")
        time.sleep(30)

    return tweets