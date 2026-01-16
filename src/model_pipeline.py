from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

def get_pipeline() -> Pipeline:
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5))),
        ('clf', LogisticRegression(max_iter=1000))
    ])
    return pipeline