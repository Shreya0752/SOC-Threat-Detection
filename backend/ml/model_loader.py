"""
Model Loader Module for Milestone 2.
Provides reusable functions to save, load, and version trained ML models
and fitted preprocessing pipelines using joblib.
"""
import os
import sys
import joblib

DEFAULT_MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../models/ml_models"))

def ensure_model_dir(model_dir=DEFAULT_MODEL_DIR):
    """Ensures the directory for storing trained ML artifacts exists."""
    os.makedirs(model_dir, exist_ok=True)
    return model_dir

def save_model(model, filepath=None):
    """
    Serializes and saves a trained machine learning model to disk.
    """
    if filepath is None:
        model_dir = ensure_model_dir()
        filepath = os.path.join(model_dir, "isolation_forest_v1.pkl")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    
    joblib.dump(model, filepath)
    print(f"[Model Loader] Model saved successfully to: {filepath}")
    return filepath

def load_model(filepath=None):
    """
    Loads a serialized machine learning model from disk.
    """
    if filepath is None:
        model_dir = ensure_model_dir()
        filepath = os.path.join(model_dir, "isolation_forest_v1.pkl")

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"[Model Loader Error] Model file not found at: {filepath}")

    model = joblib.load(filepath)
    print(f"[Model Loader] Model loaded successfully from: {filepath}")
    return model

def save_preprocessor(preprocessor, filepath=None):
    """
    Serializes and saves a fitted ThreatDataPreprocessor / ColumnTransformer instance to disk.
    """
    if filepath is None:
        model_dir = ensure_model_dir()
        filepath = os.path.join(model_dir, "preprocessing_v1.pkl")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)

    joblib.dump(preprocessor, filepath)
    print(f"[Model Loader] Preprocessor saved successfully to: {filepath}")
    return filepath

def load_preprocessor(filepath=None):
    """
    Loads a serialized fitted preprocessor pipeline from disk.
    """
    if filepath is None:
        model_dir = ensure_model_dir()
        filepath = os.path.join(model_dir, "preprocessing_v1.pkl")

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"[Model Loader Error] Preprocessor file not found at: {filepath}")

    preprocessor = joblib.load(filepath)
    print(f"[Model Loader] Preprocessor loaded successfully from: {filepath}")
    return preprocessor
