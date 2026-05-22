

import numpy as np
from sklearn.ensemble        import IsolationForest
from sklearn.preprocessing   import StandardScaler
from colorama import Fore

from features.extractor import ML_FEATURE_COLS


def train_model(feature_df, contamination: float = 0.05,
    
    X = feature_df[ML_FEATURE_COLS].fillna(0).values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    
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
