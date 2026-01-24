FROM alpine:edge

RUN apk add --no-cache \
    dropbear dropbear-scp ruby ruby-bundler ruby-dev python3 py3-pip \
    curl bash iproute2 rng-tools \
    nodejs npm git \
    build-base libffi-dev yaml-dev zlib-dev openssl-dev \
    tzdata sqlite-dev libpq-dev \
    unzip

# Install Bun runtime
RUN curl -fsSL https://bun.sh/install | bash && \
    mv /root/.bun/bin/bun /usr/local/bin/bun && \
    ln -s /usr/local/bin/bun /usr/local/bin/bunx && \
    rm -rf /root/.bun

# Configure dropbear SSH and set root password
RUN mkdir -p /etc/dropbear && \
    dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key && \
    dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key && \
    dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key && \
    echo "root:root" | chpasswd

# Create app directory for Procfile deployments
RUN mkdir -p /app

# Copy init script to temp location first, then move it
COPY init /tmp/init
RUN chmod +x /tmp/init && mv /tmp/init /sbin/init

# Copy fcm-agent binary (PTY manager for console sessions)
COPY fcm-agent /usr/local/bin/fcm-agent
RUN chmod +x /usr/local/bin/fcm-agent

# Copy deployment scripts
COPY fcm-deploy /tmp/fcm-deploy
COPY fcm-runner /tmp/fcm-runner
RUN chmod +x /tmp/fcm-deploy /tmp/fcm-runner && \
    mv /tmp/fcm-deploy /usr/local/bin/fcm-deploy && \
    mv /tmp/fcm-runner /usr/local/bin/fcm-runner
