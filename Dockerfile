# 1. Use an official Python runtime as a parent image
FROM python:3.9-slim

# 2. Install necessary system dependencies
# `iptables` package provides BOTH legacy and nftables versions.
RUN apt-get update && apt-get install -y \
    build-essential \
    libiptc-dev \
    iptables \
    libnetfilter-conntrack-dev \
    libnfnetlink-dev \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# 3. *** THE CRITICAL FIX ***
# Force the system to use the legacy version of iptables.
# The python-iptables library knows how to parse the version string
# from the legacy tools, preventing the TypeError.
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy && \
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

# 4. Set the environment variable for module location
ENV XTABLES_LIBDIR=/usr/lib/x8-64-linux-gnu/xtables/

# 5. Set the working directory inside the container
WORKDIR /app

# 6. Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 7. Copy the rest of the application code into the container
COPY . .

# 8. Expose the port the Flask app runs on
EXPOSE 5000

# 9. Define the command to run the application
CMD ["python", "app.py"]

