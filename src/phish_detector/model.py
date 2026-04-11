import os
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib


FEATURE_COLUMNS = [
    "from_is_free_provider",
    "reply_to_differs_from",
    "return_path_differs",
    "from_has_numbers",
    "from_domain_length",
    "from_display_name_mismatch",
    "url_count",
    "urls_with_ip",
    "urls_with_at_symbol",
    "urls_with_redirect",
    "urls_with_shortener",
    "urls_with_https",
    "urls_with_suspicious_tld",
    "urls_subdomain_depth",
    "urgency_word_count",
    "has_html_body",
    "html_to_text_ratio",
    "body_length",
    "body_has_form",
    "body_has_script",
    "body_has_hidden_elements",
    "spf_pass",
    "dkim_pass",
    "dmarc_pass",
    "has_x_mailer",
    "attachment_count",
    "has_suspicious_attachment",
]


def train(data_path: Path, model_path: Path) -> dict:
    df = pd.read_csv(data_path)

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns in dataset: {missing}")

    X = df[FEATURE_COLUMNS].fillna(0)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_path)

    return report


def load_model(model_path: Path) -> RandomForestClassifier:
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found at {model_path}")

    # Basic safety check before loading
    if model_path.stat().st_size > 500 * 1024 * 1024:  # 500MB limit
        raise ValueError("Model file is suspiciously large, refusing to load")

    return joblib.load(model_path)


def predict(features: dict, model_path: Path) -> dict:
    clf = load_model(model_path)

    row = {col: features.get(col, 0) for col in FEATURE_COLUMNS}
    X = pd.DataFrame([row])

    prediction = clf.predict(X)[0]
    probabilities = clf.predict_proba(X)[0]
    classes = clf.classes_

    prob_dict = {cls: round(float(prob), 4) for cls, prob in zip(classes, probabilities)}

    return {
        "verdict": prediction,
        "confidence": round(float(max(probabilities)), 4),
        "probabilities": prob_dict,
    }