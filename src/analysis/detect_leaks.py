import pandas as pd
import numpy as np
from sklearn.linear_model import LinearRegression  # type: ignore


def detect_leaks(file_path):
    columns = ["timestamp", "pid", "stack_id", "alloc_count", "symbol_path"]

    if not pd.io.common.file_exists(file_path):
        return []

    df = pd.read_csv(file_path, names=columns, header=0)
    detected_leaks = []

    MIN_SAMPLES = 5
    VELOCITY_THRESHOLD = 0.01
    CONFIDENCE_THRESHOLD = 0.85

    for (pid, stack_id, symbol_path), group in df.groupby(
        ["pid", "stack_id", "symbol_path"]
    ):
        if len(group) < MIN_SAMPLES:
            continue

        X = (group["timestamp"] - group["timestamp"].min()).values.reshape(-1, 1)
        y = group["alloc_count"].values

        model = LinearRegression()
        model.fit(X, y)

        slope = model.coef_[0]
        r_squared = model.score(X, y)

        if slope > VELOCITY_THRESHOLD and r_squared > CONFIDENCE_THRESHOLD:
            proc_name = "Unknown"
            try:
                with open(f"/proc/{int(pid)}/comm", "r") as f:
                    proc_name = f.read().strip()
            except:
                pass
            print(f"   [LEAK CONFIRMED] Process: {proc_name} (PID: {pid})")
            print(f"   Path Trace: {symbol_path}")
            print(f"   Confidence: {r_squared:.2%}")
            detected_leaks.append(
                {
                    "pid": int(pid),
                    "process_name": proc_name,
                    "symbol_path": symbol_path,
                    "confidence": r_squared,
                    "velocity": slope,
                }
            )

    return detected_leaks
