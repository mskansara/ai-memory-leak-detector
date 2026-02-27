## AI-Powered eBPF Memory Leak Detector

This tool is designed for high-performance memory diagnostics in C++ applications. It identifies memory leaks in real-time by monitoring kernel allocation events via eBPF, analyzing the data using linear regression to find growth trends, and leveraging a local LLM to provide a root-cause diagnosis.

By moving the observation layer into the Linux kernel, the tool maintains less than 1% CPU overhead, making it a production-friendly alternative to heavy instrumentation tools like Valgrind.

---

## Core Features

* **Low Overhead:** eBPF-based monitoring avoids the 10x performance penalty of CPU emulation.
* **Statistical Filtering:** Linear regression distinguishes between legitimate initialization bursts and genuine resource exhaustion.
* **Automated Diagnosis:** Integrates with Ollama (Llama 3.2) to map kernel-level anomalies back to specific lines of C++ source code.
* **Containerized Engine:** Fully portable Docker environment with automated kernel header mapping and host-gateway bridging for AI services.
* **Unified Orchestration:** A single command-line interface manages the collection, analysis, and reporting phases.

---

## Requirements

* **Host:** Linux Kernel 5.0+ (or macOS via Lima VM).
* **Virtualization:** Docker and Docker Compose (V2).
* **AI Backend:** Ollama running on the host with the Llama 3.2 model.

---

## Installation & Setup

The tool is now containerized for portability, ensuring the BCC toolchain and LLVM dependencies are consistent across environments.

### 1. Configure the AI Host

To allow the container to communicate with the host's AI service, ensure Ollama is listening on all interfaces:

```bash
# On your host terminal
export OLLAMA_HOST=0.0.0.0
ollama serve

```

### 2. Build the Detector

```bash
docker compose build

```

---

## Usage

1. Compile and run your target C++ application (e.g., in `targets/`) to obtain its PID.
2. Launch the detector using Docker Compose:

```bash
sudo docker compose run --rm detector [PID] --duration 60 --ai

```

The tool will:

* **Sniff:** Hook into the kernel to track `malloc` events for the target PID.
* **Detect:** Apply Scikit-learn regression models to telemetry stored in shared volumes.
* **Diagnose:** Bridge to the host-based LLM to perform source-code level analysis of confirmed leaks.

---

## Project Structure

* `main.py`: The central orchestrator for the sniffing and analysis pipeline.
* `src/collector`: Contains eBPF C probes and Python sniffer logic.
* `src/analysis`: Contains the Scikit-learn detection model and the AI diagnostic agent.
* `targets/`: Includes sample C++ applications with intentional leaks for testing.
* `Dockerfile`: Defines the portable kernel-tracing environment.
* `docker-compose.yml`: Manages privileged permissions, PID namespace sharing, and networking bridges.

---
