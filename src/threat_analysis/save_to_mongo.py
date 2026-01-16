from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")

def save_result(data: dict):
    client = MongoClient(MONGO_URI)
    db = client["phishing_db"]
    collection = db["url_analysis"]
    collection.insert_one(data)