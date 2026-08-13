# Phish-Net
# Phish-Net — AI-Powered Phishing Detection System

## Overview

**Phish-Net** is an AI-powered phishing detection system designed to identify malicious and fraudulent websites, URLs, and online content. The system analyzes different characteristics of a URL and applies machine learning techniques to determine whether it is **legitimate or potentially phishing-related**.

The project aims to provide users with a simple and efficient way to detect suspicious links before interacting with them, helping reduce the risk of credential theft, financial fraud, and other cyber threats.

## Key Features

* **Phishing URL Detection** – Analyzes URLs and predicts whether they are legitimate or malicious.
* **Machine Learning-Based Classification** – Uses trained ML models to identify phishing patterns.
* **URL Feature Extraction** – Extracts security-related characteristics from submitted URLs.
* **Real-Time Prediction** – Provides an immediate prediction for a given URL.
* **User-Friendly Interface** – Allows users to enter and analyze URLs easily.
* **Threat Awareness** – Helps users understand the risks associated with suspicious links.
* **Scalable Architecture** – Can be extended with additional datasets, models, and security features.

## System Workflow

1. The user enters a URL into the Phish-Net interface.
2. The system validates and preprocesses the URL.
3. Relevant URL features are extracted.
4. The extracted features are provided to the trained machine learning model.
5. The model analyzes the characteristics of the URL.
6. Phish-Net classifies the URL as **Legitimate** or **Phishing**.
7. The prediction is displayed to the user.

## Technologies Used

* **Programming Language:** Python
* **Machine Learning:** Scikit-learn
* **Data Processing:** Pandas, NumPy
* **Web Framework:** Flask / Streamlit
* **Frontend:** HTML, CSS, JavaScript
* **Model:** Machine Learning Classification Model
* **Dataset:** Phishing and legitimate URL dataset

## Project Structure

```text
Phish-Net/
│
├── app.py                  # Main application
├── model/
│   └── phishing_model.pkl  # Trained ML model
│
├── dataset/
│   └── phishing_dataset.csv
│
├── templates/
│   └── index.html           # Web interface
│
├── static/
│   ├── css/
│   └── js/
│
├── utils/
│   └── feature_extraction.py
│
├── requirements.txt         # Python dependencies
├── README.md
└── .gitignore
```

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd Phish-Net
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

Activate the environment on Windows:

```bash
.venv\Scripts\activate
```

On Linux/macOS:

```bash
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Running the Application

Start the application using:

```bash
python app.py
```

If the project uses Streamlit:

```bash
streamlit run app.py
```

After starting the application, open the local URL displayed in the terminal and enter a URL for analysis.

## Example

**Input:**

```text
http://secure-login-example.com/verify-account
```

**Output:**

```text
Prediction: Phishing
```

For a safe website:

```text
https://www.example.com
```

**Output:**

```text
Prediction: Legitimate
```

## Machine Learning Approach

Phish-Net uses URL-based characteristics to distinguish phishing websites from legitimate websites. Possible features include:

* URL length
* Number of dots
* Number of special characters
* Presence of an IP address
* Use of HTTPS
* Number of subdomains
* Presence of suspicious keywords
* Domain-related characteristics
* URL shortening services
* Presence of abnormal symbols

These features are processed and supplied to a trained classification model that generates the final prediction.

## Advantages

* Detects suspicious URLs before users access them.
* Reduces dependence on manual inspection.
* Provides fast predictions.
* Can be integrated into browsers, email systems, or security platforms.
* Can be enhanced with advanced machine learning and deep learning models.

## Future Enhancements

* Browser extension for real-time phishing detection.
* Deep learning-based URL classification.
* Integration with threat intelligence APIs.
* QR-code phishing detection.
* Email phishing detection.
* Screenshot and webpage-content analysis.
* Explainable AI to show why a URL was classified as phishing.
* Continuous model retraining using newly identified phishing URLs.
* Blacklist and reputation database integration.

## Disclaimer

Phish-Net is intended for **educational, research, and cybersecurity awareness purposes**. Machine learning predictions may not always be accurate. Users should avoid opening suspicious links and verify websites through trusted sources.

## License

This project is developed for academic and educational purposes. The licensing terms can be updated according to the project's requirements.
