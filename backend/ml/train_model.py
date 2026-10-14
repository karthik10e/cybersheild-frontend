"""
CyberShield ML Model Training Pipeline.
Trains supervised multi-class classifiers (Random Forest, Decision Tree)
and unsupervised Zero-Day Anomaly Detector (Isolation Forest).
Evaluates comprehensive metrics (Accuracy, Precision, Recall, F1, Confusion Matrix, Feature Importance)
and serializes artifacts for production inference.
"""

import os
import json
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support

from ml.dataset_generator import generate_nids_dataset

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "count", "srv_count", "serror_rate",
    "rerror_rate", "same_srv_rate", "diff_srv_rate",
    "dst_host_count", "dst_host_srv_count"
]


def train_models():
    print("[*] Generating benchmark NIDS dataset...")
    df = generate_nids_dataset(num_samples=12000)
    
    # Save a copy of sample data for testing
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(samples_dir, exist_ok=True)
    
    sample_csv = os.path.join(samples_dir, "sample_capture.csv")
    df.head(250).to_csv(sample_csv, index=False)
    print(f"[*] Saved test sample to {sample_csv}")

    X = df[CATEGORICAL_FEATURES + NUMERIC_FEATURES]
    y = df["label"]

    print("[*] Encoding target labels...")
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    class_names = list(le.classes_)

    # Preprocessing Pipeline: OneHot for categories, StandardScaler for numerics
    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL_FEATURES),
            ("num", StandardScaler(), NUMERIC_FEATURES)
        ]
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    print("[*] Fitting feature preprocessor...")
    X_train_transformed = preprocessor.fit_transform(X_train)
    X_test_transformed = preprocessor.transform(X_test)

    # Feature names after one-hot encoding
    cat_feature_names = preprocessor.named_transformers_["cat"].get_feature_names_out(CATEGORICAL_FEATURES)
    all_feature_names = list(cat_feature_names) + NUMERIC_FEATURES

    # 1. Train Random Forest (Primary Multi-Class Classifier)
    print("[*] Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        n_jobs=-1,
        random_state=42
    )
    rf_model.fit(X_train_transformed, y_train)

    # 2. Train Decision Tree (Comparison Baseline)
    print("[*] Training Decision Tree Classifier...")
    dt_model = DecisionTreeClassifier(max_depth=12, random_state=42)
    dt_model.fit(X_train_transformed, y_train)

    # 3. Train Isolation Forest (Zero-Day Anomaly Detection)
    print("[*] Training Isolation Forest for Zero-Day Anomaly Detection...")
    # Train on normal traffic representations to establish baseline
    normal_idx = (y_train == le.transform(["Normal"])[0])
    iso_forest = IsolationForest(
        contamination=0.08,
        random_state=42,
        n_estimators=100
    )
    iso_forest.fit(X_train_transformed[normal_idx])

    # Evaluate Random Forest
    print("[*] Evaluating Random Forest model...")
    y_pred_rf = rf_model.predict(X_test_transformed)
    rf_acc = float(accuracy_score(y_test, y_pred_rf))
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred_rf, average="macro")
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(y_test, y_pred_rf, average="weighted")
    
    # Evaluate Decision Tree
    y_pred_dt = dt_model.predict(X_test_transformed)
    dt_acc = float(accuracy_score(y_test, y_pred_dt))
    _, _, dt_f1, _ = precision_recall_fscore_support(y_test, y_pred_dt, average="macro")

    # Classification report
    clf_report = classification_report(y_test, y_pred_rf, target_names=class_names, output_dict=True)

    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred_rf).tolist()

    # Feature Importances
    importances = rf_model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = []
    for idx in sorted_idx[:12]:
        top_features.append({
            "feature": all_feature_names[idx],
            "importance": round(float(importances[idx]), 4),
            "percentage": round(float(importances[idx] * 100), 2)
        })

    print(f"[+] Random Forest Accuracy: {rf_acc * 100:.2f}% | F1 Macro: {f1_macro:.4f}")
    print(f"[+] Decision Tree Accuracy: {dt_acc * 100:.2f}% | F1 Macro: {dt_f1:.4f}")

    # Serialize Artifacts
    print("[*] Serializing trained models and preprocessors...")
    joblib.dump(rf_model, os.path.join(models_dir, "cybershield_rf.joblib"))
    joblib.dump(dt_model, os.path.join(models_dir, "cybershield_dt.joblib"))
    joblib.dump(iso_forest, os.path.join(models_dir, "cybershield_iso.joblib"))
    joblib.dump(preprocessor, os.path.join(models_dir, "preprocessor.joblib"))
    joblib.dump(le, os.path.join(models_dir, "label_encoder.joblib"))

    # Metadata & Performance Metrics JSON
    metadata = {
        "model_version": "CyberShield-RF-v1.0",
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "classes": class_names,
        "features": {
            "categorical": CATEGORICAL_FEATURES,
            "numeric": NUMERIC_FEATURES,
            "all_encoded_count": len(all_feature_names)
        },
        "metrics": {
            "random_forest": {
                "accuracy": round(rf_acc, 4),
                "precision_macro": round(float(p_macro), 4),
                "recall_macro": round(float(r_macro), 4),
                "f1_macro": round(float(f1_macro), 4),
                "f1_weighted": round(float(f1_weighted), 4)
            },
            "decision_tree": {
                "accuracy": round(dt_acc, 4),
                "f1_macro": round(float(dt_f1), 4)
            },
            "isolation_forest": {
                "type": "Unsupervised Zero-Day Outlier Detector",
                "contamination": 0.08
            }
        },
        "classification_report": clf_report,
        "confusion_matrix": {
            "labels": class_names,
            "matrix": cm
        },
        "top_feature_importance": top_features
    }

    metadata_path = os.path.join(models_dir, "metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Metadata written to: {metadata_path}")
    print("[+] Model training pipeline completed successfully!")
    return metadata


if __name__ == "__main__":
    train_models()
