"""Data Processing Module.

Converts raw DataFrames into model-ready form:
  * imputation of missing values            -> SimpleImputer
  * label-encoding of categorical columns   -> LabelEncoder
  * train / validation / test splitting     -> train_test_split, KFold
"""
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.model_selection import KFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder

from features import LABEL


def load_csv(path):
    return pd.read_csv(path)


def clean_dataframe(df):
    """Impute missing values and label-encode categorical columns.

    Returns (clean_df, info) where info describes what was done (shown on the View Data page).
    """
    df = df.copy()
    info = {"rows": len(df), "cols": df.shape[1], "missing_before": int(df.isna().sum().sum()),
            "dropped_empty": [], "encoded": {}}

    empty = [c for c in df.columns if df[c].isna().all()]       # nothing to impute from
    if empty:
        df = df.drop(columns=empty)
        info["dropped_empty"] = empty

    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    cat_cols = [c for c in df.columns if c not in num_cols]

    if num_cols:
        df[num_cols] = SimpleImputer(strategy="median").fit_transform(df[num_cols])
    for c in cat_cols:
        col = df[[c]].astype(object)
        col = SimpleImputer(strategy="most_frequent").fit_transform(col).ravel()
        col = pd.Series(col).astype(str).str.strip().str.lower()
        le = LabelEncoder()
        df[c] = le.fit_transform(col)
        info["encoded"][c] = {str(k): int(i) for i, k in enumerate(le.classes_)}

    info["missing_after"] = int(df.isna().sum().sum())
    return df, info


def split_data(X, y, test_size=0.2, seed=42):
    """Hold-out split (stratified so both classes appear in train and test)."""
    return train_test_split(X, y, test_size=test_size, random_state=seed, stratify=y)


def kfold_accuracy(model, X, y, k=5, seed=42):
    """Average accuracy over k folds (k-fold cross-validation)."""
    scores = cross_val_score(model, X, y, cv=KFold(n_splits=k, shuffle=True, random_state=seed),
                             scoring="accuracy")
    return float(np.mean(scores))


def label_summary(df):
    if LABEL in df.columns:
        vc = df[LABEL].value_counts().to_dict()
        return {int(k) if str(k).lstrip("-").isdigit() else str(k): int(v) for k, v in vc.items()}
    return None
