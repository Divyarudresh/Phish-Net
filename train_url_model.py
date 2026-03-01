import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report


def main() -> None:
    print("Loading URL dataset (malicious_phish.csv)...")
    df = pd.read_csv("malicious_phish.csv")

    # Basic cleaning
    df = df.dropna(subset=["url", "type"])
    df["url"] = df["url"].astype(str)
    df["type"] = df["type"].astype(str).str.lower()

    X = df["url"]
    y = df["type"]

    print("Splitting URL dataset...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Building character-level TF-IDF + SGDClassifier pipeline...")
    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 6),
                    max_features=80000,
                    min_df=2,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                SGDClassifier(
                    loss="log_loss",
                    max_iter=50,
                    n_jobs=-1,
                    random_state=42,
                    class_weight="balanced",
                ),
            ),
        ]
    )

    print("Training URL model...")
    pipeline.fit(X_train, y_train)

    accuracy = pipeline.score(X_test, y_test)
    print("URL Model Accuracy:", accuracy)

    print("\nURL Classification Report:")
    print(classification_report(y_test, pipeline.predict(X_test)))

    output_path = "url_model.pkl"
    joblib.dump(pipeline, output_path)
    print(f"URL model saved successfully to {output_path}!")


if __name__ == "__main__":
    main()

