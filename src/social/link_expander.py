import requests

def expand_url(short_url):
    try:
        response = requests.head(short_url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return short_url