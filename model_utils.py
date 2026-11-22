"""Shared model construction so the /algo scores and the /prediction model use the same preprocessing."""
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler


def with_scaling(estimator):
    """Traffic features are heavy-tailed (bytes, packet rates), so log-scale then standardise
    (the 'normalization' step of the report) before the classifier."""
    return make_pipeline(FunctionTransformer(np.log1p), StandardScaler(), estimator)


def candidate_models():
    """The five algorithms compared on the /algo page (report section 5.4)."""
    return {
        "Logistic Regression": with_scaling(LogisticRegression(max_iter=500)),
        "Naive Bayes":         with_scaling(GaussianNB()),
        "KNN":                 with_scaling(KNeighborsClassifier(n_neighbors=5)),
        "Random Forest":       with_scaling(RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)),
        "Gradient Boosting":   with_scaling(GradientBoostingClassifier(random_state=42)),
    }


def logistic_regression():
    """Model retrained on cleaned_dataset.csv for every /prediction request (report section 5.5)."""
    return with_scaling(LogisticRegression(max_iter=500))
