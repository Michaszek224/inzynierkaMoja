# 1. Use an official Python runtime as a parent image
FROM python:3.9-slim

# 2. Install system dependencies (no privileged daemons)
RUN apt-get update && apt-get install -y \
    build-essential \
    libiptc-dev \
    iptables \
    libnetfilter-conntrack-dev \
    libnfnetlink-dev \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# 3. Use the legacy iptables version for compatibility
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy && \
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

# 4. Fix: correct XTABLES_LIBDIR path
ENV XTABLES_LIBDIR=/usr/lib/x86_64-linux-gnu/xtables/

# 5. Workdir setup
WORKDIR /app

# 6. Copy requirements and install deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 7. Copy your app code
COPY . .

# 8. Flask runs on port 5000
EXPOSE 5000

# 9. Run your app
CMD ["python", "app.py"]
