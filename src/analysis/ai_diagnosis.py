import ollama
import os
from ollama import Client


def diagnosis_leak(symbol_path):
    ollama_host = os.getenv("OLLAMA_HOST_URL", "http://127.0.0.1:11434")
    client = Client(host=ollama_host)
    code_path = os.getenv("TARGET_SOURCE_PATH", "/app/targets/main.cpp")

    if not os.path.exists(code_path):
        print(
            f"\n AI DIAGNOSIS ERROR: Source code not found at {code_path} inside the container!"
        )
        return

    with open(code_path, "r") as f:
        source_code = f.read()

    prompt = f"""
    You are a Senior Systems Engineer. I have detected a memory leak using eBPF and Linear Regression.
    
    DETECTED LEAK PATH: {symbol_path}
    
    SOURCE CODE:
    {source_code}
    
    TASK:
    1. Identify the specific function in the source code causing the leak.
    2. Explain WHY it is leaking.
    3. Provide the corrected C++ code for that function.
    """

    print(f"🤖 AI Agent is analyzing the leak in: {symbol_path.split(';')[1]}...")

    try:
        response = client.generate(model="llama3.2", prompt=prompt)
        return response["response"]
    except Exception as e:
        print(f"❌ Connection failed: {e}")


if __name__ == "__main__":
    test_path = "malloc;steady_leak;main"
    diagnosis_leak(test_path)
