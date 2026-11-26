FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1 

# 1. Install System Dependencies (eBPF + Python)
RUN apt-get update && apt-get install -y \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc-dev \
    linux-headers-generic \
    python3-pip \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Install Python Stack (Consolidated)
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install --no-cache-dir \
    pandas scikit-learn numpy \
    prometheus_client flask \
    langgraph langchain-ollama httpx \
    streamlit plotly

# 3. Copy Codebase
COPY . .

# Ensure source code is discoverable
ENV PYTHONPATH="/app:/app/src"


ENTRYPOINT [ "python3" ]
CMD [ "main.py" ]