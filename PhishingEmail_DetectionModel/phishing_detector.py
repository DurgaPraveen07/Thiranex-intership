"""Train and evaluate a phishing email text classifier.

The script expects a labeled CSV file with one text column and one label
column. Labels are normalized to phishing or safe classes.
"""

from __future__ import annotations

import argparse
import pickle
import re
import math
from pathlib import Path

import pandas as pd
from nltk import download as nltk_download
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC


DEFAULT_TEXT_COLUMN = "text"
DEFAULT_LABEL_COLUMN = "label"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train and evaluate a phishing email classifier")
    parser.add_argument("--data", required=True, help="Path to a labeled CSV dataset")
    parser.add_argument(
        "--text-column",
        default=DEFAULT_TEXT_COLUMN,
        help="Name of the column containing email text",
    )
    parser.add_argument(
        "--label-column",
        default=DEFAULT_LABEL_COLUMN,
        help="Name of the column containing spam/ham or phishing/safe labels",
    )
    parser.add_argument(
        "--model",
        choices=("naive_bayes", "svm"),
        default="naive_bayes",
        help="Classifier to train",
    )
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split fraction")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed for splitting")
    parser.add_argument("--save-model", help="Optional output path for the trained model pipeline")
    return parser


def ensure_stopwords() -> set[str]:
    try:
        return set(stopwords.words("english"))
    except LookupError:
        nltk_download("stopwords", quiet=True)
        return set(stopwords.words("english"))


def normalize_label(value: object) -> int:
    text = str(value).strip().lower()
    if text in {"spam", "phishing", "phish", "1", "true", "yes", "malicious"}:
        return 1
    if text in {"ham", "safe", "legit", "0", "false", "no", "benign"}:
        return 0
    try:
        return 1 if float(text) >= 1 else 0
    except ValueError as exc:
        raise ValueError(
            "Labels must be recognizable as phishing/spam or safe/ham values"
        ) from exc


def clean_text(text: object, stop_words: set[str], stemmer: PorterStemmer) -> str:
    content = re.sub(r"[^a-zA-Z\s]", " ", str(text).lower())
    tokens = [token for token in content.split() if token not in stop_words]
    return " ".join(stemmer.stem(token) for token in tokens)


def load_dataset(path: str, text_column: str, label_column: str) -> pd.DataFrame:
    dataset_path = Path(path)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    frame = pd.read_csv(dataset_path)
    missing = {text_column, label_column} - set(frame.columns)
    if missing:
        raise ValueError(f"Dataset is missing required column(s): {', '.join(sorted(missing))}")

    subset = frame[[text_column, label_column]].copy()
    subset[text_column] = subset[text_column].fillna("")
    subset[label_column] = subset[label_column].map(normalize_label)
    return subset


def make_pipeline(model_name: str) -> Pipeline:
    if model_name == "svm":
        classifier = LinearSVC()
    else:
        classifier = MultinomialNB()

    return Pipeline(
        [
            ("vectorizer", TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
            ("classifier", classifier),
        ]
    )


def main() -> int:
    args = build_parser().parse_args()
    stop_words = ensure_stopwords()
    stemmer = PorterStemmer()

    data = load_dataset(args.data, args.text_column, args.label_column)
    data["clean_text"] = data[args.text_column].apply(lambda value: clean_text(value, stop_words, stemmer))

    features = data["clean_text"]
    labels = data[args.label_column]
    class_counts = labels.value_counts()
    class_count = len(class_counts)
    requested_test_count = math.ceil(len(data) * args.test_size)
    test_count = min(len(data) - 1, max(requested_test_count, class_count))
    can_stratify = class_counts.min() >= 2 and test_count >= class_count

    X_train, X_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=test_count,
        random_state=args.random_state,
        stratify=labels if can_stratify else None,
    )

    if not can_stratify:
        print("Warning: using an unstratified split because the dataset is too small for class-balanced splitting.")

    pipeline = make_pipeline(args.model)
    pipeline.fit(X_train, y_train)
    predictions = pipeline.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    report = classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Safe", "Phishing"],
        zero_division=0,
    )
    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])

    print(f"Model: {args.model}")
    print(f"Samples: {len(data)}")
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    print(f"Accuracy: {accuracy:.4f}")
    print("Confusion matrix:")
    print(matrix)
    print("Classification report:")
    print(report)

    if args.save_model:
        output_path = Path(args.save_model)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("wb") as file_handle:
            pickle.dump(
                {
                    "pipeline": pipeline,
                    "text_column": args.text_column,
                    "label_column": args.label_column,
                    "model": args.model,
                },
                file_handle,
            )
        print(f"Saved model to: {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())