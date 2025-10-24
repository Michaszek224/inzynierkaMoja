#Image
FROM python:3.11-slim

# some insatllation
RUN apt-get update && apt-get install -y \
    iptables \
    libnetfilter-conntrack3 \
    libnetfilter-queue1 \
    gcc \
    python3-dev \
    libxtables-dev \
    pkg-config \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/

RUN mkdir -p /app/data

# port na zewnatrz
EXPOSE 5000

# bez tego nei dziala nie wiem czemu
ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]
