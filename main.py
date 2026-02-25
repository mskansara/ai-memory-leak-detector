import argparse
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from collector.sniffer import start_sniffing
from analysis.detect_leaks import detect_leaks
from analysis.ai_diagnosis import diagnosis_leak


def main():
    parser = argparse.ArgumentParser(description="AI-Powered eBPF Memory Leak Detector")
    parser.add_argument("pid", type=int, help="Target PID")
    parser.add_argument("--duration", type=int, default=30, help="Seconds to sniff")
    parser.add_argument("--ai", action="store_true", help="Enable LLM Diagnosis")

    args = parser.parse_args()

    csv_path = "./data/memory_telemetry.csv"

    # Phase 1 - Sniff
    start_sniffing(args.pid, args.duration, csv_path)

    # Phase 2 - Detect
    leaks = detect_leaks(csv_path)

    # Phase 3 - Diagnose
    if leaks and args.ai:
        for leak in leaks:
            diagnosis_leak(leak)


if __name__ == "__main__":
    main()
