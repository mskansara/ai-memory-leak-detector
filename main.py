import argparse
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from collector.sniffer import start_sniffing
from analysis.detect_leaks import detect_leaks
from analysis.ai_diagnosis import diagnosis_leak


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ Guardian eBPF: Autonomous Memory Leak Detector (Phase 1)"
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Seconds to sniff global system allocations (default: 60)",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable Autonomous LLM Diagnosis for all detected leaks",
    )

    args = parser.parse_args()

    csv_path = "./data/memory_telemetry.csv"
    print("=" * 60)
    print("🛡️  GUARDIAN eBPF: GLOBAL WATCHER MODE")
    print(f"[*] Duration: {args.duration}s")
    print(f"[*] AI Diagnosis: {'ENABLED' if args.ai else 'DISABLED'}")
    print("=" * 60)
    # Phase 1 - Sniff
    try:
        start_sniffing(args.duration, csv_path)
    except Exception as e:
        print(f"❌ Critical Error in Sniffer: {e}")
        sys.exit(1)

    # Phase 2 - Detect
    print("\n[*] Starting Linear Regression Analysis on global telemetry...")
    leaks = detect_leaks(csv_path)

    # Phase 3 - Diagnose
    if leaks:
        print(f"\n✅ Found {len(leaks)} potential leak(s) across the system.")
        if args.ai:
            for leak in leaks:
                print("-" * 30)
                diagnosis_leak(leak)
        else:
            print("[!] AI Diagnosis skipped. Use --ai to generate root-cause reports.")
    else:
        print(
            "\n[!] Analysis complete: No linear memory leaks detected with high confidence."
        )

    print("\n[*] Guardian eBPF has finished the current cycle.")


if __name__ == "__main__":
    main()
