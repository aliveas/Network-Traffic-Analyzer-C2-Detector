"""
ml/trainer.py
==============
Trains an Isolation Forest anomaly detection model on extracted
network flow features.

Why Isolation Forest?
---------------------
- Unsupervised: no labelled dataset of "C2 flows" needed
- Works well on high-dimensional tabular data
- Fast training even on large datasets
- Explicitly designed for anomaly detection
- contamination parameter lets you tune sensitivity

The model learns what "normal" traffic looks like from your
PCAP. Flows that deviate significantly from normal patterns
get negative anomaly scores and are flagged as anomalous.
"""

import numpy as np
from sklearn.ensemble        import IsolationForest
from sklearn.preprocessing   import StandardScaler
from colorama import Fore

from features.extractor import ML_FEATURE_COLS


def train_model(feature_df, contamination: float = 0.05,
                verbose: bool = False):
    """
    Fit a StandardScaler + IsolationForest on the feature DataFrame.

    Parameters
    ----------
    feature_df    : pd.DataFrame from extractor.extract_features()
    contamination : float — expected proportion of anomalies (0–0.5)
                    0.05 = expect 5% of flows to be anomalous
    verbose       : bool

    Returns
    -------
    (model, scaler) — fitted IsolationForest and StandardScaler
    """
    X = feature_df[ML_FEATURE_COLS].fillna(0).values

    # Scale features to zero mean, unit variance
    # This ensures no single feature dominates because of scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train Isolation Forest
    # n_estimators=200 gives stable results
    # random_state=42 makes results reproducible
    model = IsolationForest(
        n_estimators  = 200,
        contamination = contamination,
        random_state  = 42,
        n_jobs        = -1,    # use all CPU cores
    )
    model.fit(X_scaled)

    if verbose:
        scores = model.decision_function(X_scaled)
        print(f"{Fore.CYAN}    [ml] Anomaly score range: "
              f"{scores.min():.3f} to {scores.max():.3f}")
        print(f"    [ml] Contamination: {contamination} "
              f"({int(contamination * len(feature_df))} flows expected anomalous)")

    return model, scaler
