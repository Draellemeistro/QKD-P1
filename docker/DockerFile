# Start from Ubuntu 20.04 with Java 11
FROM eclipse-temurin:11-jdk-focal
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install Dependencies
RUN apt-get update && apt-get install -y \
    maven \
    git \
    libjson-c-dev \
    curl \
    jq \
    make \
    build-essential \
    libssl-dev \
    libcurl4-openssl-dev \
    screen \
    python3 \
    python3-pip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# 2. Install Python Libraries
RUN pip3 install requests python-dotenv cryptography

WORKDIR /app

# --- PATH FIX ---
# Since context is Project Root:
# 1. qkd-net is inside the 'docker' folder -> COPY docker/qkd-net ...
# 2. src is in the root -> COPY src ...
COPY ./docker/qkd-net /app/qkd-net
COPY ./src /app/src

# Set PYTHONPATH
ENV PYTHONPATH="${PYTHONPATH}:/app"

# 3. Build the Java microservices
WORKDIR /app/qkd-net/kms
RUN ./scripts/build

# 4. Pre-build the C-based demo applications
WORKDIR /app/qkd-net/applications/tls-kms-demo
RUN make

# 5. Set the default directory
WORKDIR /app/qkd-net/kms

# Default CMD: Start KMS and keep alive.
# It does NOT start the python sender/receiver automatically.
CMD ["/bin/bash", "-c", "./scripts/run && echo 'KMS Service started...' && tail -f /dev/null"]