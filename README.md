## AI-Powered Autonomous Memory Leak Detector

**AI-Powered Autonomous Memory Leak Detector** is a cloud-native observability tool designed for high-performance memory diagnostics in C++ applications. Unlike traditional debuggers, it operates as an autonomous pipeline: monitoring kernel allocation events via **eBPF**, detecting growth trends using **Prometheus-based linear regression**, and leveraging a **LangGraph AI Agent** to provide root-cause diagnosis and code fixes.

By moving the observation layer into the Linux kernel and the diagnostic layer into an asynchronous AI workflow, the tool maintains less than 1% CPU overhead while providing a fully automated "detect-to-fix" experience.

---

## Core Features

* **Kernel-Level Observability:** eBPF-based monitoring hooks into `malloc` and `new` calls directly in the kernel, avoiding the heavy performance penalties of Valgrind or CPU emulation.
* **Autonomous Detection Pipeline:** Integrated with **Prometheus and Alertmanager** to move beyond manual scans. The system continuously calculates allocation velocity and triggers the AI only when a genuine leak is confirmed.
* **Agentic AI Diagnosis:** Powered by **LangGraph** and **Llama 3.2**, the diagnostic agent doesn't just "chat"—it follows a stateful workflow to retrieve source code, analyze call stacks, and generate specific C++ code fixes.
* **Decoupled Architecture:** A microservices-based approach using Docker Compose, separating the **Sniffer** (Producer), the **AI Agent** (Processor), and the **Streamlit Dashboard** (Visualizer).
* **Statistical Precision:** Uses linear regression (via Prometheus `deriv()`) to distinguish between legitimate initialization bursts and genuine long-term resource exhaustion.

---

## Requirements

* **Host:** Linux Kernel 5.0+ (or macOS via Lima VM).
* **Virtualization:** Docker and Docker Compose (V2) with privileged access enabled.
* **AI Backend:** [Ollama](https://ollama.ai/) running on the host with the `llama3.2` model.

---

## Installation & Setup

The tool is fully containerized to ensure the BCC toolchain and LLVM dependencies remain consistent across environments.

### 1. Configure the AI Host
To allow the containers to communicate with your Mac's GPU, ensure Ollama is listening on all interfaces:

```bash
# On your macOS terminal
launchctl setenv OLLAMA_HOST "0.0.0.0"
ollama serve
```

### 2. Launch the Autonomous Stack
```bash
# Build and start the Sniffer, AI Agent, Dashboard, and Prometheus
docker compose up --build
```

---

## The Workflow

The system operates in a continuous, reactive loop:

1.  **Sniff:** The `sniffer` service hooks into the kernel to track allocations for target processes, exposing real-time metrics on port `8000`.
2.  **Monitor:** **Prometheus** scrapes these metrics every 5s and calculates the memory "slope."
3.  **Alert:** If a sustained linear growth is detected, **Alertmanager** fires a webhook to the AI Agent.
4.  **Diagnose:** The **LangGraph Agent** triggers:
    * **Retrieve:** Locates the relevant C++ source files in the `/targets` volume.
    * **Analyze:** Sends the code and stack trace to the local LLM.
    * **Report:** Generates a detailed Markdown report with a suggested code fix in `data/reports/`.
5.  **Visualize:** View live trends and historical AI reports via the **Streamlit Dashboard** at `http://localhost:8501`.

---

## Project Structure

* `src/collector/`: eBPF C probes and Python sniffer logic with Prometheus metric exporters.
* `src/agent/`: The `webhook_receiver` and **LangGraph** state machine logic.
* `src/analysis/`: The AI diagnostic prompts and source code retrieval logic.
* `monitoring/`: Configuration files for Prometheus alerting rules and Alertmanager routing.
* `targets/`: Sample C++ applications with intentional leaks for testing.
* `data/`: Shared volume for telemetry and generated AI diagnostic reports.

---

## Troubleshooting

### 1. Connection Refused (AI Agent)
If the agent cannot reach Ollama, verify the host IP. Inside Lima, the Mac host is typically `192.168.5.2`. Ensure this matches the `OLLAMA_HOST` variable in your `docker-compose.yml`.

### 2. Zero Metrics in Prometheus
Ensure the target application is compiled with debug symbols (`-g`). If the sniffer cannot find the process symbols, it will not be able to categorize allocation stacks.

### 3. BPF Header Errors
If the container fails to load the BPF program, ensure your Lima VM has kernel headers installed:
`sudo apt-get install linux-headers-$(uname -r)`
