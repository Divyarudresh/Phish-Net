import re
import tldextract
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np

suspicious_words = [
    "urgent", "verify", "login", "password",
    "bank", "click", "confirm", "account",
    "limited", "security", "update"
]

def extract_email_features(text):
    features = {}

    text_lower = text.lower()

    # Suspicious word count
    features["suspicious_word_count"] = sum(
        word in text_lower for word in suspicious_words
    )

    # Number of links
    features["link_count"] = len(re.findall(r"http[s]?://", text_lower))

    # Special character count
    features["special_char_count"] = len(re.findall(r"[!@#$%^&*()]", text))

    # Length of email
    features["email_length"] = len(text)

    return list(features.values())


def extract_url_features(url):
    features = {}

    parsed = urlparse(url)

    features["url_length"] = len(url)
    features["dot_count"] = url.count(".")
    features["has_at_symbol"] = 1 if "@" in url else 0
    features["has_https"] = 1 if "https" in parsed.scheme else 0
    features["has_ip"] = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", parsed.netloc) else 0

    return list(features.values())