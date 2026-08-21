"""
ML Preprocessing Module for Milestone 2.
Implements scikit-learn preprocessing pipeline with ColumnTransformer for
numerical scaling and categorical one-hot encoding.
"""
import os
import sys
import pandas as pd
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer

NUMERICAL_FEATURES = [
    "failed_login_count",
    "hour_of_day",
    "after_hours_flag",
    "severity_score",
    "event_frequency",
    "alerts_per_user",
    "malicious_ip_flag",
    "malware_detected_encoded",
    "cvss_score_final",
    "impossible_travel_flag"
]

CATEGORICAL_FEATURES = [
    "protocol"
]

def build_preprocessor():
    """
    Constructs a reusable scikit-learn ColumnTransformer pipeline for M2 ML features.
    
    - Numerical Pipeline: SimpleImputer (median) -> StandardScaler
    - Categorical Pipeline: SimpleImputer (most_frequent) -> OneHotEncoder
    """
    num_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler())
    ])

    cat_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False))
    ])

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", num_pipeline, NUMERICAL_FEATURES),
            ("cat", cat_pipeline, CATEGORICAL_FEATURES)
        ],
        remainder="drop"
    )

    return preprocessor

class ThreatDataPreprocessor:
    """
    Wrapper class for training, transforming, and inspecting feature preprocessing.
    """
    def __init__(self):
        self.preprocessor = build_preprocessor()
        self.feature_names = []
        self.is_fitted = False

    def fit_transform(self, X_raw):
        """
        Fits the preprocessor on raw features DataFrame and returns scaled/encoded numpy matrix.
        """
        X_processed = self.preprocessor.fit_transform(X_raw)
        self.is_fitted = True
        
        # Extract feature names after one-hot encoding
        num_cols = NUMERICAL_FEATURES
        cat_encoder = self.preprocessor.named_transformers_["cat"].named_steps["onehot"]
        cat_cols = list(cat_encoder.get_feature_names_out(CATEGORICAL_FEATURES))
        self.feature_names = num_cols + cat_cols

        return X_processed

    def transform(self, X_raw):
        """
        Transforms new raw features using already fitted pipeline.
        """
        if not self.is_fitted:
            raise ValueError("Preprocessor must be fitted before calling transform().")
        return self.preprocessor.transform(X_raw)

    def get_feature_names(self):
        return self.feature_names
