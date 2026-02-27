FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc-dev \
    linux-headers-generic \
    python3-pip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip3 install --no-cache-dir -r requirements.txt

COPY main.py .
COPY src/ ./src/
COPY data/ ./data/
COPY targets/ ./targets/

ENTRYPOINT [ "python3", "main.py" ]