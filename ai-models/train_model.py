#!/usr/bin/env python3
"""
PhishLens ML Training Pipeline
Trains a Machine Learning Classifier on the Phishing Dataset (Phising_Testing_Dataset.csv)
and exports the serialized model and feature metadata for real-time inference.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

DATASET_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Phising_Testing_Dataset.csv")
MODEL_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_ml_model.joblib")
METADATA_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_metadata.json")


def load_and_preprocess_data():
    """Loads and preprocesses the dataset"""
    print(f"📂 Loading dataset from: {DATASET_PATH}", flush=True)
    df = pd.read_csv(DATASET_PATH)
    print(f"📊 Dataset Shape: {df.shape[0]} rows, {df.shape[1]} columns", flush=True)

    if "key" in df.columns:
        df_clean = df.drop(columns=["key"])
    else:
        df_clean = df.copy()

    feature_cols = [col for col in df_clean.columns if col != "Statistical_report"]
    X = df_clean[feature_cols]
    
    # Calculate composite multi-factor phishing ground truth
    # Features with -1 represent phishing/suspicious indicators
    phishing_indicator_count = (X == -1).sum(axis=1)
    y_composite = np.where((df_clean["Statistical_report"] == -1) | (phishing_indicator_count >= 5), 1, 0)

    print(f"🎯 Target Distribution: Phishing={np.sum(y_composite == 1)} ({np.mean(y_composite==1)*100:.1f}%), Safe={np.sum(y_composite == 0)} ({np.mean(y_composite==0)*100:.1f}%)", flush=True)
    print(f"🏷️ Features ({len(feature_cols)}): {feature_cols}", flush=True)

    return X, y_composite, feature_cols


def train_and_evaluate_models(X, y, feature_names):
    """Trains ensemble models and selects the highest-performing model"""
    print("\n🔬 Splitting data (80% Train, 20% Test with Stratification)...", flush=True)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)

    models = {
        "RandomForestClassifier": RandomForestClassifier(
            n_estimators=120, max_depth=12, min_samples_split=4, min_samples_leaf=2, random_state=42, n_jobs=1
        ),
        "ExtraTreesClassifier": ExtraTreesClassifier(
            n_estimators=120, max_depth=12, min_samples_split=4, random_state=42, n_jobs=1
        ),
        "GradientBoostingClassifier": GradientBoostingClassifier(
            n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42
        )
    }

    best_model_name = None
    best_model = None
    best_f1 = 0.0
    best_metrics = {}

    print("\n🚀 Training & Evaluating Machine Learning Models:", flush=True)
    print("=" * 75, flush=True)
    print(f"{'Model':<30} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1-Score':<10}", flush=True)
    print("-" * 75, flush=True)

    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        auc = roc_auc_score(y_test, y_prob) if y_prob is not None else 0.0

        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(model, X, y, cv=cv, scoring='f1', n_jobs=1)

        print(f"{name:<30} {acc*100:>8.2f}%   {prec*100:>8.2f}%   {rec*100:>8.2f}%   {f1*100:>8.2f}%  (CV: {cv_scores.mean()*100:.1f}%)", flush=True)

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model = model
            best_metrics = {
                "model_name": name,
                "accuracy": round(float(acc), 4),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1_score": round(float(f1), 4),
                "roc_auc": round(float(auc), 4),
                "cv_mean_f1": round(float(cv_scores.mean()), 4),
                "cv_std": round(float(cv_scores.std()), 4),
                "train_samples": int(len(X_train)),
                "test_samples": int(len(X_test))
            }

    print("=" * 75, flush=True)
    print(f"🏆 Best Performing Model: {best_model_name} (F1-Score: {best_metrics['f1_score']*100:.2f}%, Accuracy: {best_metrics['accuracy']*100:.2f}%)", flush=True)

    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        feature_importance_map = {feat: round(float(imp), 4) for feat, imp in zip(feature_names, importances)}
        sorted_importances = sorted(feature_importance_map.items(), key=lambda x: x[1], reverse=True)
        print("\n📈 Top 10 Most Predictive Phishing Features:", flush=True)
        for rank, (feat, imp) in enumerate(sorted_importances[:10], 1):
            print(f"  {rank:>2}. {feat:<30} Importance: {imp*100:>5.2f}%", flush=True)
        best_metrics["feature_importances"] = feature_importance_map
        best_metrics["top_features"] = [f[0] for f in sorted_importances[:10]]

    return best_model, best_metrics, feature_names


def save_model_and_metadata(model, metrics, feature_names):
    """Saves model to joblib and metadata to JSON"""
    print(f"\n💾 Serializing trained model to: {MODEL_OUTPUT_PATH}", flush=True)
    joblib.dump(model, MODEL_OUTPUT_PATH)

    metadata = {
        "version": "1.0.0",
        "description": "Trained Ensemble Classifier for Real-Time URL Phishing Feature Scoring",
        "trained_date": "2026-09-01",
        "dataset": "Phising_Testing_Dataset.csv",
        "features": feature_names,
        "metrics": metrics
    }

    print(f"📝 Saving model metadata to: {METADATA_OUTPUT_PATH}", flush=True)
    with open(METADATA_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("✅ Model Training & Serialization Complete!", flush=True)


if __name__ == "__main__":
    X, y, feature_names = load_and_preprocess_data()
    best_model, best_metrics, feature_names = train_and_evaluate_models(X, y, feature_names)
    save_model_and_metadata(best_model, best_metrics, feature_names)
