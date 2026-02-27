FROM ubuntu:22.04


ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1 

# 1. Install System Dependencies
RUN apt-get update && apt-get install -y \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc-dev \
    linux-headers-generic \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Install Python Stack directly to System
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install --no-cache-dir \
    pandas \
    scikit-learn \
    ollama \
    numpy \
    streamlit \
    plotly

# 3. EDGE CASE HANDLER: Verification Step
RUN python3 -c "import pandas; import sklearn; import bcc; print('Environment Verified Successfully')"

# 4. Copy Codebase
COPY . .

ENV PYTHONPATH="/app/src:${PYTHONPATH}"

ENTRYPOINT [ "python3", "main.py" ]