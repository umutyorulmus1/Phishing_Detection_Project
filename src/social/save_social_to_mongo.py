from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()
client = MongoClient(os.getenv("MONGO_URI"))
db = client["phishing_db"]
collection = db["social_urls"]  # 🔄 Yeni koleksiyon adı

def save_social_data(data):
    collection.insert_one(data)