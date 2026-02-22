import pandas as pd
import numpy as np
from sklearn.linear_model import LinearRegression


def detect_leaks(file_path):
    columns = ["timestamp", "stack_id", "alloc_count", "symbol_path"]
    df = pd.read_csv(file_path, names=columns)

    VELOCITY_THRESHOLD = 0.05
    CONFIDENCE_THRESHOLD = 0.85

    print(f"--- Running AI Analysis on {len(df)} Data Points ---\n")

    for (stack_id, symbol_path), group in df.groupby(["stack_id", "symbol_path"]):
        if len(group) < 10:
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
            print(f"   Growth Rate: {slope:.4f} allocs/sec")
            print("-" * 30)


if __name__ == "__main__":
    detect_leaks("./data/memory_telemetry.csv")
