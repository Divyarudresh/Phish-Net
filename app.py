import os
import email
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template
import joblib

app = Flask(__name__)

# Trusted domains whitelist — always return benign for these (model can misclassify)
TRUSTED_DOMAINS = frozenset({
    "google.com", "www.google.com", "google.co.in", "google.co.uk", "google.ca",
    "google.com.au", "google.de", "google.fr", "google.es", "google.it", "google.co.jp",
    "google.com.br", "google.ru", "google.co.kr", "google.com.mx", "google.com.hk",
    "youtube.com", "www.youtube.com",
    "facebook.com", "www.facebook.com", "fb.com",
    "twitter.com", "x.com", "www.twitter.com",
    "instagram.com", "www.instagram.com",
    "linkedin.com", "www.linkedin.com",
    "microsoft.com", "www.microsoft.com", "outlook.com", "live.com", "hotmail.com",
    "apple.com", "www.apple.com", "icloud.com",
    "amazon.com", "www.amazon.com", "amazon.co.uk", "amazon.in",
    "github.com", "www.github.com",
    "wikipedia.org", "www.wikipedia.org", "en.wikipedia.org",
    "yahoo.com", "www.yahoo.com",
    "netflix.com", "www.netflix.com",
    "paypal.com", "www.paypal.com",
    "reddit.com", "www.reddit.com",
    "cloudflare.com", "www.cloudflare.com",
    "stackoverflow.com", "www.stackoverflow.com",
    "mozilla.org", "www.mozilla.org", "firefox.com",
    "adobe.com", "www.adobe.com",
    "zoom.us", "www.zoom.us",
    "dropbox.com", "www.dropbox.com",
    "spotify.com", "www.spotify.com",
    "nvidia.com", "www.nvidia.com",
    "intel.com", "www.intel.com",
    "ibm.com", "www.ibm.com",
    "oracle.com", "www.oracle.com",
    "samsung.com", "www.samsung.com",
})
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB max file size

# Load trained models
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EMAIL_MODEL_PATH = os.path.join(BASE_DIR, "phishnet_model.pkl")
URL_MODEL_PATH = os.path.join(BASE_DIR, "url_model.pkl")

email_model = None
url_model = None

if os.path.exists(EMAIL_MODEL_PATH):
    email_model = joblib.load(EMAIL_MODEL_PATH)

if os.path.exists(URL_MODEL_PATH):
    url_model = joblib.load(URL_MODEL_PATH)


def extract_text_from_eml(file_content):
    """Extract plain text body from .eml file content."""
    try:
        msg = email.message_from_bytes(file_content)
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode(errors="ignore")
                    break
                elif content_type == "text/html" and not body:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode(errors="ignore")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore")
        return body.strip() if body else ""
    except Exception:
        return ""


def predict_email(text):
    """Run spam/phishing prediction on email text."""
    if email_model is None:
        return None, None, "Model not loaded. Run train_model.py first."
    if not text or not str(text).strip():
        return None, None, "No email content provided."
    text = str(text).strip()
    prediction = email_model.predict([text])[0]
    proba = email_model.predict_proba([text])[0]
    # 0 = Safe, 1 = Phishing/Spam
    spam_prob = float(proba[1])
    return prediction, spam_prob, None


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    text = None
    error = None

    # Check for file upload
    if "file" in request.files:
        file = request.files["file"]
        if file and file.filename:
            content = file.read()
            if file.filename.lower().endswith(".eml"):
                text = extract_text_from_eml(content)
            else:
                text = content.decode(errors="ignore")
            if not text.strip():
                error = "Could not extract text from the uploaded file."

    # Check for raw text (form or JSON)
    if text is None and error is None:
        if request.is_json:
            data = request.get_json()
            text = data.get("text", "")
        else:
            text = request.form.get("text", "")

    if error:
        return jsonify({"success": False, "error": error}), 400

    prediction, spam_prob, err = predict_email(text)
    if err:
        return jsonify({"success": False, "error": err}), 500

    is_spam = bool(prediction == 1)
    spam_pct = float(round(spam_prob * 100, 2))
    safe_pct = float(round((1 - spam_prob) * 100, 2))

    # Avoid returning raw numpy types; send only plain Python primitives
    return jsonify(
        {
            "success": True,
            "prediction": "Spam" if is_spam else "Safe",
            "is_spam": bool(is_spam),
            "spam_probability": spam_pct,
            "safe_probability": safe_pct,
        }
    )


def _get_domain(url_str: str) -> str:
    """Extract hostname from URL, normalized to lowercase."""
    url_str = str(url_str).strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "https://" + url_str
    try:
        parsed = urlparse(url_str)
        host = (parsed.netloc or parsed.path or "").lower()
        return host.split(":")[0] if host else ""
    except Exception:
        return ""


def predict_url(url: str):
    """Run multi-class URL classification (benign / phishing / malware / defacement)."""
    if url_model is None:
        return None, None, "URL model not loaded. Run train_url_model.py first."

    if not url or not str(url).strip():
        return None, None, "No URL provided."

    url = str(url).strip()
    domain = _get_domain(url)

    # Trusted domains whitelist — always benign (avoids false positives like google.com)
    if domain and domain in TRUSTED_DOMAINS:
        return "benign", {"benign": 100.0}, None

    # Also check base domain without www (e.g. google.com from www.google.com)
    base_domain = domain[4:] if domain.startswith("www.") else domain
    if base_domain and base_domain in TRUSTED_DOMAINS:
        return "benign", {"benign": 100.0}, None

    label = url_model.predict([url])[0]

    probabilities = None
    if hasattr(url_model, "predict_proba"):
        proba_vec = url_model.predict_proba([url])[0]
        classes = list(url_model.classes_)
        probabilities = {
            str(cls): float(round(float(p) * 100, 2)) for cls, p in zip(classes, proba_vec)
        }
    else:
        # Fallback when model has no predict_proba
        label_str = str(label)
        probabilities = {label_str: 100.0}

    return label, probabilities, None


@app.route("/predict_url", methods=["POST"])
def predict_url_route():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    label, probabilities, err = predict_url(url)
    if err:
        return jsonify({"success": False, "error": err}), 400

    label_str = str(label)
    risk = "Safe" if label_str.lower() == "benign" else "Suspicious / Malicious"

    return jsonify(
        {
            "success": True,
            "url": url,
            "label": label_str,
            "risk": risk,
            "probabilities": probabilities,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
