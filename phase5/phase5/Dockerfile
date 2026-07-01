# Use Python 3.12 slim image based on Debian Bookworm
FROM python:3.12-slim-bookworm

# Set working directory for your app
WORKDIR /opt/ssl-tls-suite

# Copy app files into container
COPY . /opt/ssl-tls-suite

# Install system packages and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    sslscan \
    openssl \
    git \
    build-essential \
    libpcap-dev \
    net-tools \
    iputils-ping \
    curl \
    ca-certificates \
    wget \
    zlib1g-dev \
    libffi-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    xz-utils \
    liblzma-dev \
    gcc \
    g++ \
    libatlas-base-dev \
    libopenblas-dev \
    liblapack-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install legacy OpenSSL 1.0.2u
WORKDIR /tmp
RUN wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz && \
    tar xzf openssl-1.0.2u.tar.gz && \
    cd openssl-1.0.2u && \
    ./config --prefix=/opt/openssl-1.0.2u shared zlib && \
    make -j$(nproc) && make install && \
    rm -rf /tmp/openssl-1.0.2u /tmp/openssl-1.0.2u.tar.gz

# Set environment variables to prioritize legacy OpenSSL
ENV PATH="/opt/openssl-1.0.2u/bin:$PATH"
ENV LD_LIBRARY_PATH="/opt/openssl-1.0.2u/lib"

# Optional: verify legacy openssl version (for debugging)
RUN openssl version
WORKDIR /opt/ssl-tls-suite

# Upgrade pip and install Python dependencies
RUN python3 -m pip install --upgrade pip setuptools wheel

# Pre-install numpy to satisfy pandas requirement on Python 3.12
RUN python3 -m pip install numpy==1.26.4

# Install the remaining Python dependencies
RUN python3 -m pip install \
    Flask==3.0.3 \
    Flask-SocketIO==5.3.0 \
    python-engineio==4.9.1 \
    python-socketio==5.11.2 \
    eventlet==0.36.1 \
    requests==2.31.0 \
    pandas==2.2.2 \
    scikit-learn==1.5.1 \
    beautifulsoup4==4.12.3 \
    lxml==5.2.2 \
    scapy==2.5.0 \
    cryptography==42.0.8 \
    pyOpenSSL==24.0.0 \
    ndg-httpsclient==0.5.1 \
    pyasn1==0.6.0 \
    gunicorn==22.0.0

# Expose the Flask app port
EXPOSE 5000

# Set environment variable for Flask
ENV FLASK_APP=app.py

# Default command to run your Flask app
CMD ["python3", "app.py"]

