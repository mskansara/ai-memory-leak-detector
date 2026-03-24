import argparse
import sys
import os
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from collector.sniffer import start_sniffing


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ Guardian eBPF: Kernel Telemetry Daemon"
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=3600,  # Run for an hour by default, or change sniffer to run infinitely
        help="Seconds to expose system allocations to Prometheus (default: 3600)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("🛡️  GUARDIAN eBPF: DAEMON MODE")
    print(f"[*] Prometheus Exporter starting on port 8000...")
    print(f"[*] Duration: {args.duration}s")
    print("=" * 60)

    try:
        # Phase 1 - Only Sniff and Expose Metrics
        start_sniffing(args.duration)
    except KeyboardInterrupt:
        print("\n[*] Shutting down eBPF Sniffer...")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Critical Error in Sniffer: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
