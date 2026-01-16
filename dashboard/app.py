import os
from dotenv import load_dotenv
from flask import Flask, render_template
from pymongo import MongoClient
from bson import ObjectId
from cleaner import clean_document, clean_url_field, _is_valid_url

load_dotenv()
app = Flask(__name__, static_folder="static", template_folder="templates")

MONGO_URI = os.getenv("MONGO_URI") or "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)
db = client["phishing_db"]
collection = db["social_urls"]


# --------------------
# DURUM MOTORU (TEK YER)
# --------------------
def get_status(doc):
    verdict = doc.get("vt_summary", {}).get("verdict")

    if verdict == "malicious":
        return "zararli"
    if verdict == "suspicious":
        return "supheli"

    if doc.get("ml_result") == 1:
        return "supheli"

    return None  # güvenli → gösterme


# --------------------
# INDEX VERİ ÇEKME
# --------------------
def fetch_posts(limit=50):
    pipeline = [
        {
            "$match": {
                "$or": [
                    {"vt_summary.verdict": {"$in": ["malicious", "suspicious"]}},
                    {"ml_result": 1}
                ]
            }
        },
        {
            "$group": {
                "_id": "$text",
                "first_doc": {"$first": "$$ROOT"},
                "urls": {"$push": "$url"}
            }
        },
        {"$sort": {"first_doc.risk_score": -1}},
        {"$limit": limit}
    ]

    results = []
    for g in collection.aggregate(pipeline):
        first = g["first_doc"]
        status = get_status(first)

        if not status:
            continue

        cleaned = clean_document(first)

        urls = []
        for u in g.get("urls", []):
            cu = clean_url_field(u)
            if cu and _is_valid_url(cu):
                urls.append(cu)

        cleaned["urls"] = list(set(urls))

        results.append({
            "_id": str(first["_id"]),
            "text": (g["_id"][:120] + "...") if g["_id"] else "",
            "status": status,
            "risk_score": first.get("risk_score", 0)
        })

    return results


@app.route("/")
def index():
    posts = fetch_posts()

    total = collection.count_documents({})
    flagged = collection.count_documents({
        "$or": [
            {"vt_summary.verdict": {"$in": ["malicious", "suspicious"]}},
            {"ml_result": 1}
        ]
    })

    return render_template(
        "index.html",
        posts=posts,
        total=total,
        flagged=flagged
    )


@app.route("/detail/<post_id>")
def detail(post_id):
    doc = collection.find_one({"_id": ObjectId(post_id)})
    if not doc:
        return render_template("detail.html", post=None)

    status = get_status(doc)
    if not status:
        return render_template("detail.html", post=None)

    cleaned = clean_document(doc)
    cleaned["status"] = status
    cleaned["rules"] = doc.get("keyword_hits", [])
    cleaned["vt"] = doc.get("vt_summary", {})

    related = collection.find({"text": doc.get("text")}, {"url": 1})
    urls = []
    for r in related:
        cu = clean_url_field(r.get("url"))
        if cu and _is_valid_url(cu):
            urls.append(cu)

    cleaned["urls"] = list(set(urls))

    return render_template("detail.html", post=cleaned)


if __name__ == "__main__":
    app.run(debug=True)
