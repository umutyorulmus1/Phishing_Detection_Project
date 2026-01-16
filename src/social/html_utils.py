import requests

def get_html_content(url: str) -> str:
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
        return ""
    except Exception:
        return ""