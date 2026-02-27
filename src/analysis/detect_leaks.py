import pandas as pd
import numpy as np
from sklearn.linear_model import LinearRegression


def detect_leaks(file_path):
    columns = ["timestamp", "stack_id", "alloc_count", "symbol_path"]

    if not pd.io.common.file_exists(file_path):
        return []

    df = pd.read_csv(file_path, names=columns)
    detected_paths = []

    MIN_SAMPLES = 5
    VELOCITY_THRESHOLD = 0.01
    CONFIDENCE_THRESHOLD = 0.85

    for (stack_id, symbol_path), group in df.groupby(["stack_id", "symbol_path"]):
        if len(group) < MIN_SAMPLES:
            continue

        X = (group["timestamp"] - group["timestamp"].min()).values.reshape(-1, 1)
        y = group["alloc_count"].values

        model = LinearRegression()
        model.fit(X, y)

        slope = model.coef_[0]
        r_squared = model.score(X, y)

        if slope > VELOCITY_THRESHOLD and r_squared > CONFIDENCE_THRESHOLD:
            print(f"   [LEAK CONFIRMED]")
            print(f"   Path Trace: {symbol_path}")
            print(f"   Confidence: {r_squared:.2%}")
            detected_paths.append(symbol_path)

    return detected_paths
