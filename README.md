# AI-Powered eBPF Memory Leak Detector

This tool is designed for high-performance memory diagnostics in C++ applications. It identifies memory leaks in real-time by monitoring kernel allocation events via eBPF, analyzing the data using linear regression to find growth trends, and leveraging a local LLM to provide a root-cause diagnosis.

By moving the observation layer into the Linux kernel, the tool maintains less than 1% CPU overhead, making it a production-friendly alternative to heavy instrumentation tools like Valgrind.

---

## Core Features

- Low Overhead: eBPF-based monitoring avoids the 10x performance penalty of CPU emulation.
- Statistical Filtering: Linear regression distinguishes between legitimate initialization bursts and genuine resource exhaustion.
- Automated Diagnosis: Integrates with Ollama (Llama 3.2) to map kernel-level anomalies back to specific lines of C++ source code.
- Unified CLI: A single orchestrator manages the collection, analysis, and reporting phases.

---

## Requirements

- Linux Kernel 5.0+ with BCC (BPF Compiler Collection) installed.
- Python 3.10+
- Ollama running locally with the Llama 3.2 model.

---

## Installation

Because eBPF requires access to system-level libraries, create a virtual environment that can access system site packages:

```bash
python3 -m venv venv --system-site-packages
source venv/bin/activate
pip install -r requirements.txt

```

---

## Usage

1. Compile and run your target C++ application to get its PID.
2. Launch the detector with the unified CLI:

```bash
sudo ./venv/bin/python3 main.py [PID] --duration 60 --ai

```

The tool will sniff kernel events for the specified duration, run the ML detection engine on the resulting telemetry, and trigger the AI agent if any leaks are confirmed.

---

## Project Structure

- main.py: The central entry point for the tool.
- src/collector: Contains the eBPF C probes and Python sniffer logic.
- src/analysis: Contains the Scikit-learn detection model and AI diagnostic agent.
- targets: Includes sample C++ applications with intentional leaks for testing.

---
