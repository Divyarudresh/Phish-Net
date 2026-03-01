import os
import email
import joblib
import gdown
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# ===============================
# TRUSTED DOMAINS
# ===============================
TRUSTED_DOMAINS = frozenset({
    "google.com", "www.google.com",
    "youtube.com", "www.youtube.com",
    "facebook.com", "www.facebook.com",
    "twitter.com", "x.com",
    "instagram.com",
    "linkedin.com",
    "microsoft.com", "outlook.com", "live.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.in",
    "github.com",
    "paypal.com",
})

# ===============================
# PATHS
# ===============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EMAIL_MODEL_PATH = os.path.join(BASE_DIR, "phishnet_model.pkl")
URL_MODEL_PATH = os.path.join(BASE_DIR, "url_model.pkl")

# Google Drive FILE ID
URL_MODEL_FILE_ID = "1hh9wldFW9V7YJSbfHRhUxDNoIjEnm01V"

email_model = None
url_model = None


# ===============================
# LOAD EMAIL MODEL
# ===============================
if os.path.exists(EMAIL_MODEL_PATH):
    print("Loading Email Model...")
    email_model = joblib.load(EMAIL_MODEL_PATH)
else:
    print("Email model not found!")


# ===============================
# DOWNLOAD + LOAD URL MODEL
# ===============================
if not os.path.exists(URL_MODEL_PATH):
    print("Downloading URL model from Google Drive...")
    gdown.download(
        f"https://drive.google.com/uc?id={URL_MODEL_FILE_ID}",
        URL_MODEL_PATH,
        quiet=False
    )

if os.path.exists(URL_MODEL_PATH):
    print("Loading URL Model...")
    url_model = joblib.load(URL_MODEL_PATH)
else:
    print("URL model not found!")


# ===============================
# EMAIL EXTRACTION
# ===============================
def extract_text_from_eml(file_content):
    try:
        msg = email.message_from_bytes(file_content)
        body = ""

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode(errors="ignore")
                        break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore")

        return body.strip()
    except:
        return ""


# ===============================
# EMAIL PREDICTION
# ===============================
def predict_email(text):
    if email_model is None:
        return None, None, "Email model not loaded."

    if not text.strip():
        return None, None, "No email content provided."

    prediction = email_model.predict([text])[0]
    proba = email_model.predict_proba([text])[0]
    spam_prob = float(proba[1])

    return prediction, spam_prob, None


# ===============================
# URL DOMAIN EXTRACTOR
# ===============================
def _get_domain(url_str):
    if not url_str.startswith(("http://", "https://")):
        url_str = "https://" + url_str

    parsed = urlparse(url_str)
    return parsed.netloc.lower().split(":")[0]


# ===============================
# URL PREDICTION
# ===============================
def predict_url(url):
    if url_model is None:
        return None, None, "URL model not loaded."

    if not url.strip():
        return None, None, "No URL provided."

    domain = _get_domain(url)

    # Whitelist override
    if domain in TRUSTED_DOMAINS:
        return "benign", {"benign": 100.0}, None

    label = url_model.predict([url])[0]

    if hasattr(url_model, "predict_proba"):
        proba_vec = url_model.predict_proba([url])[0]
        classes = list(url_model.classes_)
        probabilities = {
            str(cls): float(round(float(p) * 100, 2))
            for cls, p in zip(classes, proba_vec)
        }
    else:
        probabilities = {str(label): 100.0}

    return label, probabilities, None


# ===============================
# ROUTES
# ===============================
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    text = request.form.get("text", "")

    prediction, spam_prob, err = predict_email(text)

    if err:
        return jsonify({"success": False, "error": err}), 400

    spam_pct = round(spam_prob * 100, 2)
    safe_pct = round((1 - spam_prob) * 100, 2)

    return jsonify({
        "success": True,
        "prediction": "Spam" if prediction == 1 else "Safe",
        "spam_probability": spam_pct,
        "safe_probability": safe_pct
    })


@app.route("/predict_url", methods=["POST"])
def predict_url_route():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    label, probabilities, err = predict_url(url)

    if err:
        return jsonify({"success": False, "error": err}), 400

    risk = "Safe" if str(label).lower() == "benign" else "Suspicious / Malicious"

    return jsonify({
        "success": True,
        "url": url,
        "label": str(label),
        "risk": risk,
        "probabilities": probabilities
    })


if __name__ == "__main__":
    app.run()


