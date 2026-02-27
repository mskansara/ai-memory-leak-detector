## AI-Powered eBPF Memory Leak Detector

This tool is designed for high-performance memory diagnostics in C++ applications. It identifies memory leaks in real-time by monitoring kernel allocation events via eBPF, analyzing the data using linear regression to find growth trends, and leveraging a local LLM to provide a root-cause diagnosis through an integrated web dashboard.

By moving the observation layer into the Linux kernel and the orchestration layer into a reactive UI, the tool maintains less than 1% CPU overhead while providing a user-friendly diagnostic experience.

---

## Core Features

* **Low Overhead:** eBPF-based monitoring avoids the performance penalties associated with traditional CPU emulation or heavy instrumentation.
* **Unified Dashboard:** A streamlined Streamlit interface manages the entire lifecycle—targeting, live capture, visualization, and AI diagnosis.
* **Statistical Filtering:** Scikit-learn linear regression models distinguish between legitimate initialization bursts and genuine resource exhaustion.
* **Automated Diagnosis:** Direct integration with Ollama (Llama 3.2) maps kernel-level anomalies back to specific lines of C++ source code.
* **Containerized Orchestration:** Fully portable Docker environment utilizing host PID namespace sharing and privileged kernel access for seamless observability.

---

## Requirements

* **Host:** Linux Kernel 5.0+ (or macOS via Lima VM).
* **Virtualization:** Docker and Docker Compose (V2) with privileged access enabled.
* **AI Backend:** Ollama running on the host with the Llama 3.2 model.

---

## Installation & Setup

The tool is containerized for portability, ensuring the BCC toolchain and LLVM dependencies are consistent across environments.

### 1. Configure the AI Host

To allow the container to communicate with the host AI service, ensure Ollama is listening on all interfaces:

```bash
# On your host terminal
export OLLAMA_HOST=0.0.0.0
ollama serve

```

### 2. Build and Launch the Platform

```bash
# Build the images
docker compose build

# Start the dashboard
sudo docker compose up

```

---

## Usage

1. Compile and run your target C++ application (e.g., in `targets/`) to obtain its PID.
2. Access the **Guardian eBPF Dashboard** at `http://localhost:8501`.
3. Enter the **Target PID** and **Source Code Path** in the configuration sidebar.
4. Click **Start Live Capture** to begin the eBPF sniffing phase.
5. Once capture is complete, review the **Allocation Velocity Trend** chart.
6. Click **Run AI Diagnosis** to perform a source-code level analysis of confirmed leaks.

The platform will:

* **Sniff:** Hook into the host kernel using `/proc/[PID]/root` to track `malloc` and `operator new` events for the target PID.
* **Detect:** Analyze telemetry via shared volumes to identify linear growth patterns.
* **Diagnose:** Bridge to the host-based LLM to provide a detailed root-cause report based on the identified leaking call-stacks.

---

## Project Structure

* `src/dashboard/app.py`: The central UI orchestrator managing background sniffing threads and data visualization.
* `src/collector`: Contains eBPF C probes and Python sniffer logic optimized for container-to-host library mapping.
* `src/analysis`: Contains the Scikit-learn detection models and the AI diagnostic agent.
* `targets/`: Includes sample C++ applications with intentional leaks for testing.
* `data/`: Shared volume for high-frequency telemetry storage.
* `docker-compose.yml`: Manages privileged permissions, host PID namespace sharing, and library volume mounts.

---

## Troubleshooting

Due to the specialized nature of eBPF and container-to-host interaction, you may encounter the following common issues:

### 1. Zero Stacks Captured (Empty Telemetry)

If the **Stacks in Map** count remains at 0 during a live capture:

* **Library Path Mismatch:** Ensure the target application is linked against the same `libc` version found in `/lib/aarch64-linux-gnu/` (or `/lib/x86_64-linux-gnu/`). If your host uses a different path, update the `volumes` section in `docker-compose.yml` to map your host's library path to `/host/lib`.
* **PID Visibility:** Verify the target PID is visible from within the container by running `docker exec -it [container_id] ps -p [PID]`. If not found, ensure `pid: "host"` is set in your compose file.
* **Symbol Stripping:** If the target binary is stripped of symbols, eBPF may fail to hook `malloc`. Compile your target with debug symbols (`-g`).

### 2. BPF Program Loading Failures

If the detector fails to initialize the BPF probe:

* **Locked Memory:** eBPF requires locked memory. If you see `RLIMIT_MEMLOCK` errors, ensure the container is running with `privileged: true`.
* **Kernel Headers:** The tool requires access to host kernel headers to compile the C probes at runtime. Ensure `/lib/modules` and `/usr/src` are correctly mounted as read-only volumes.
* **BTF Errors:** If you encounter `libbpf: failed to find valid kernel BTF`, ensure your host kernel was compiled with `CONFIG_DEBUG_INFO_BTF=y`.

### 3. AI Connection Refused

If the **AI Diagnosis** fails to connect to Ollama:

* **Host Gateway:** Ensure you are using `http://host.docker.internal:11434` as the `OLLAMA_HOST_URL`.
* **Ollama Interface:** By default, Ollama only listens on `127.0.0.1`. You **must** set `export OLLAMA_HOST=0.0.0.0` on your host machine before starting the Ollama service to allow cross-container communication.

### 4. Linear Regression "No Leaks Found"

If a leak is visually obvious on the chart but not detected:

* **Zigzag Data:** If multiple sniffer threads were running simultaneously, the data may be corrupted. Restart the dashboard to clear the background thread pool and perform a clean capture.
* **Duration Too Short:** Slow leaks require a longer observation window. Increase the **Scan Duration** in the sidebar to at least 120 seconds.
