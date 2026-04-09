"""
Train and export CyberSentinel Random Forest model.

Usage:
  python backend/train_rf.py --dataset path/to/dataset.csv

Expected dataset columns (configurable by args):
  - url
  - label (0/1 or phishing/legitimate-like strings)

Output:
  ml/rf_model.pkl containing:
    {
      "model": RandomForestClassifier,
      "accuracy": float,
      "f1": float
    }
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split

# Keep these feature constants aligned with backend/app.py
SUSPICIOUS_KW = [
    "login", "verify", "secure", "account", "update", "confirm", "bank", "paypal",
    "apple", "amazon", "google", "microsoft", "password", "credential", "suspend",
    "urgent", "free", "prize", "winner", "claim", "signin", "billing", "support",
    "security", "alert", "notice", "limited", "expire", "validate", "authenticate",
]

TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "twitter.com", "github.com", "linkedin.com", "youtube.com",
    "wikipedia.org", "reddit.com", "instagram.com", "netflix.com", "ebay.com",
]

PHISHING_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".info", ".biz", ".pw", ".cc", ".su",
]


def extract_features(url: str) -> dict[str, float]:
    url = str(url).strip()
    try:
        parsed = urlparse(url if url.startswith("http") else "https://" + url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query
    except Exception:
        domain = url.lower()
        path = ""
        query = ""

    url_lower = url.lower()

    kw = sum(1 for k in SUSPICIOUS_KW if k in url_lower)
    brand = next(
        (
            td.split(".")[0]
            for td in TRUSTED_DOMAINS
            if td.split(".")[0] in url_lower and not domain.endswith(td)
        ),
        None,
    )

    return {
        "is_https": 1 if url.startswith("https://") else 0,
        "url_length": min(len(url), 200) / 200,
        "domain_length": min(len(domain), 100) / 100,
        "is_ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(":")[0]) else 0,
        "hyphen_count": min(domain.count("-"), 10) / 10,
        "dot_count": min(domain.count("."), 8) / 8,
        "subdomain_count": min(max(len(domain.split(".")) - 2, 0), 5) / 5,
        "suspicious_tld": 1 if any(domain.endswith(t) for t in PHISHING_TLDS) else 0,
        "keyword_count": min(kw, 10) / 10,
        "brand_mismatch": 1 if brand else 0,
        "at_symbol": 1 if "@" in url else 0,
        "double_slash": 1 if "//" in path else 0,
        "encoded_chars": min(len(re.findall(r"%[0-9a-fA-F]{2}", url)), 10) / 10,
        "digit_ratio": sum(c.isdigit() for c in domain) / max(len(domain), 1),
        "path_length": min(len(path), 150) / 150,
        "has_port": 1 if ":" in domain and domain.split(":")[-1].isdigit() else 0,
        "has_query": 1 if query else 0,
        "special_chars": min(len(re.findall(r"[!$&'()*+,;=]", url)), 10) / 10,
    }


def parse_label(value) -> int:
    # Accept common numeric and string label variants.
    if isinstance(value, bool):
        return int(value)

    s = str(value).strip().lower()
    if s in {"1", "true", "phishing", "phish", "malicious", "bad", "suspicious"}:
        return 1
    if s in {"0", "false", "legitimate", "legit", "safe", "benign", "good"}:
        return 0

    try:
        n = int(float(s))
        return 1 if n > 0 else 0
    except Exception as exc:
        raise ValueError(f"Unsupported label value: {value}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and export rf_model.pkl for CyberSentinel")
    parser.add_argument("--dataset", required=True, help="Path to CSV dataset")
    parser.add_argument("--url-col", default="url", help="URL column name (default: url)")
    parser.add_argument("--label-col", default="label", help="Label column name (default: label)")
    parser.add_argument("--output", default="ml/rf_model.pkl", help="Output model path")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split ratio")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)
    if args.url_col not in df.columns or args.label_col not in df.columns:
        raise ValueError(
            f"Dataset must contain columns '{args.url_col}' and '{args.label_col}'. "
            f"Found: {list(df.columns)}"
        )

    work = df[[args.url_col, args.label_col]].dropna().copy()
    work[args.url_col] = work[args.url_col].astype(str).str.strip()
    work = work[work[args.url_col] != ""]
    work["y"] = work[args.label_col].map(parse_label)

    if work["y"].nunique() < 2:
        raise ValueError("Need at least two classes in labels to train the model.")

    X = pd.DataFrame([extract_features(u) for u in work[args.url_col]])
    y = work["y"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=args.random_state,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    accuracy = float(accuracy_score(y_test, pred))
    f1 = float(f1_score(y_test, pred))

    payload = {
        "model": model,
        "accuracy": accuracy,
        "f1": f1,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, output_path)

    print("Saved Random Forest model")
    print(f"  output:   {output_path.resolve()}")
    print(f"  samples:  {len(work)}")
    print(f"  accuracy: {accuracy:.4f}")
    print(f"  f1:       {f1:.4f}")


if __name__ == "__main__":
    main()
