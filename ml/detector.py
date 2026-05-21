"""
ml/detector.py
===============
Runs the trained Isolation Forest model against the feature
DataFrame and appends anomaly scores and labels to each row.

Adds two columns to the DataFrame:
  ml_score   : float — anomaly score (more negative = more anomalous)
  ml_anomaly : bool  — True if model classified flow as anomalous
"""

import numpy as np
import pandas as pd
from colorama import Fore

from features.extractor import ML_FEATURE_COLS


def run_detection(model, scaler, feature_df: pd.DataFrame,
                  verbose: bool = False) -> pd.DataFrame:
    """
    Score every flow with the trained Isolation Forest.

    Parameters
    ----------
    model      : trained IsolationForest
    scaler     : fitted StandardScaler
    feature_df : pd.DataFrame
    verbose    : bool

    Returns
    -------
    pd.DataFrame with added ml_score and ml_anomaly columns
    """
    df = feature_df.copy()
    X  = df[ML_FEATURE_COLS].fillna(0).values

    X_scaled = scaler.transform(X)

    # decision_function: negative score = anomalous
    # predict: -1 = anomaly, 1 = normal
    scores      = model.decision_function(X_scaled)
    predictions = model.predict(X_scaled)

    df["ml_score"]   = scores
    df["ml_anomaly"] = predictions == -1

    anomalous = df[df["ml_anomaly"] == True]

    if verbose:
        for _, row in anomalous.iterrows():
            print(
                f"{Fore.YELLOW}    [ml] Anomaly: "
                f"{row['src_ip']}→{row['dst_ip']}:{int(row['dst_port'])}"
                f"  score={row['ml_score']:.3f}"
                f"  cv_iat={row['coeff_var_iat']:.3f}"
                f"  std_sz={row['std_pkt_size']:.1f}"
            )

    print(f"{Fore.CYAN}    Anomaly scores — "
          f"min: {scores.min():.3f}  "
          f"max: {scores.max():.3f}  "
          f"mean: {scores.mean():.3f}")

    return df
