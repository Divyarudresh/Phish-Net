import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

print("Loading dataset...")

df = pd.read_csv("Phishing_Email.csv")

df = df.rename(columns={
    "Email Text": "text",
    "Email Type": "type"
})

df["label"] = df["type"].apply(lambda x: 1 if "phishing" in str(x).lower() else 0)

df = df.dropna(subset=["text"])

X = df["text"]
y = df["label"]

print("Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("Building TF-IDF + RandomForest pipeline...")

pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(
        stop_words="english",
        max_features=5000
    )),
    ("classifier", RandomForestClassifier(
        n_estimators=200,
        random_state=42
    ))
])

print("Training model...")

pipeline.fit(X_train, y_train)

accuracy = pipeline.score(X_test, y_test)
print("Model Accuracy:", accuracy)

print("\nClassification Report:")
print(classification_report(y_test, pipeline.predict(X_test)))

joblib.dump(pipeline, "phishnet_model.pkl")
print("Improved model saved successfully!")