import ollama
import os
from ollama import Client


def diagnosis_leak(leak_info):
    ollama_host = os.getenv("OLLAMA_HOST_URL", "http://127.0.0.1:11434")
    # ollama_host = "http://host.docker.internal:11434"
    client = Client(host=ollama_host)
    pid = leak_info.get("pid")
    proc_name = leak_info.get("process_name", "unknown_proc")
    symbol_path = leak_info.get("symbol_path", "")
    potential_source_paths = [
        os.getenv("TARGET_SOURCE_PATH"),
        f"./targets/{proc_name}.cpp",  # Local Host Path (Relative)
        f"/app/targets/{proc_name}.cpp",  # Docker Container Path
        # f"./targets/leaker.cpp",  # Explicit Fallback
    ]
    code_path = None

    for path in potential_source_paths:
        print(path)
        if path and os.path.exists(path):
            print(path)
            code_path = path
            break
    if not os.path.exists(code_path):
        print(
            f"\n AI DIAGNOSIS ERROR: Source code not found at {code_path} inside the container!"
        )
        return

    try:
        with open(code_path, "r") as f:
            source_code = f.read()
    except Exception as e:
        print(f"❌ Failed to read source file {code_path}: {e}")
        return None

    prompt = f"""
    You are a Senior Systems Engineer specializing in Linux Kernel and Memory Safety.
    
    INVESTIGATION CONTEXT:
    - Process Name: {proc_name}
    - PID: {pid}
    - Confidence Level: {leak_info.get('confidence', 0):.2%}
    - Leak Velocity: {leak_info.get('velocity', 0):.4f} units/sec
    - eBPF Stack Trace: {symbol_path}
    
    SOURCE CODE TO ANALYZE:
    {source_code}
    
    TASK:
    1. Pinpoint the exact function and line number responsible for the leak.
    2. Analyze the 'eBPF Stack Trace' provided and explain how it maps to the C++ logic.
    3. Explain the impact: based on the 'Leak Velocity', how quickly will this process crash the system?
    4. Provide the production-ready C++ fix for the identified function.
    """

    print(
        f"🤖 AI Agent is diagnosing '{proc_name}' (PID: {pid}) using source: {code_path}..."
    )

    try:
        response = client.generate(model="llama3.2", prompt=prompt)
        report = response["response"]
        report_dir = "./data/reports"
        os.makedirs(report_dir, exist_ok=True)
        report_file = f"{report_dir}/leak_report_{proc_name}_{pid}.txt"

        with open(report_file, "w") as f:
            f.write(report)
        return report

    except Exception as e:
        print(f"❌ Connection failed: {e}")
