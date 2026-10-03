"""
src/classifier.py
NGFW - ML Traffic Classifier

Multi-class classifier that labels network flows as:
- normal, port_scan, ddos, or exfiltration

Uses a Random Forest ensemble with engineered flow features.

Author: Allben Rakgoale
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix


# Features used by the classifier
CLASSIFIER_FEATURES = [
    "packet_size",
    "duration_ms",
    "packets_sent",
    "bytes_sent",
    "flags_syn",
    "flags_ack",
    "flags_fin",
    "payload_entropy",
    "dst_port",
]


class TrafficClassifier:
    """
    Multi-class network traffic classifier.

    Trains a Random Forest on labelled flow data and predicts
    the attack type for unseen flows.
    """

    def __init__(self):
        self.scaler = StandardScaler()
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",
        )

    def train(self, df: pd.DataFrame) -> dict:
        """Train on labelled data and return evaluation metrics."""
        X = df[CLASSIFIER_FEATURES].fillna(0).values
        y = df["label"].values

        # Train/test split (stratified)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y,
        )

        # Scale
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Train
        self.model.fit(X_train_scaled, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        report = classification_report(y_test, y_pred, output_dict=True)

        return {
            "accuracy": round(report["accuracy"], 4),
            "macro_f1": round(report["macro avg"]["f1-score"], 4),
            "weighted_f1": round(report["weighted avg"]["f1-score"], 4),
            "per_class": {
                label: {
                    "precision": round(report[label]["precision"], 3),
                    "recall": round(report[label]["recall"], 3),
                    "f1": round(report[label]["f1-score"], 3),
                }
                for label in report
                if label not in ["accuracy", "macro avg", "weighted avg"]
            },
        }

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Predict attack labels and confidence for unseen flows."""
        X = df[CLASSIFIER_FEATURES].fillna(0).values
        X_scaled = self.scaler.transform(X)

        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)

        results = df.copy()
        results["predicted_label"] = predictions
        results["confidence"] = probabilities.max(axis=1).round(4)

        # Flag if the prediction is malicious
        results["is_malicious"] = (~results["predicted_label"].isin(["normal"])).astype(int)

        return results

    def feature_importance(self) -> pd.DataFrame:
        """Return feature importance ranking."""
        importance = self.model.feature_importances_
        return pd.DataFrame({
            "feature": CLASSIFIER_FEATURES,
            "importance": importance.round(4),
        }).sort_values("importance", ascending=False).reset_index(drop=True)


def train_and_evaluate(df: pd.DataFrame):
    """Convenience function that trains + predicts in one call."""
    classifier = TrafficClassifier()
    metrics = classifier.train(df)
    return classifier, metrics
