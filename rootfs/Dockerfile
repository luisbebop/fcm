FROM alpine:edge

RUN apk add --no-cache \
    dropbear dropbear-scp ruby ruby-bundler ruby-dev python3 py3-pip \
    curl bash iproute2 rng-tools agetty \
    nodejs npm git \
    build-base libffi-dev yaml-dev zlib-dev openssl-dev \
    tzdata sqlite-dev libpq-dev \
    unzip

# Install Bun runtime
RUN curl -fsSL https://bun.sh/install | bash && \
    mv /root/.bun/bin/bun /usr/local/bin/bun && \
    ln -s /usr/local/bin/bun /usr/local/bin/bunx && \
    rm -rf /root/.bun

# Install Claude Code CLI
RUN curl -fsSL https://claude.ai/install.sh | bash && \
    cp -L /root/.local/bin/claude /usr/local/bin/claude && \
    rm -rf /root/.local /root/.claude

# Add /usr/local/bin to PATH for all users
RUN echo 'export PATH="/usr/local/bin:$PATH"' >> /etc/profile

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

# Copy deployment scripts
COPY fcm-deploy /tmp/fcm-deploy
COPY fcm-runner /tmp/fcm-runner
RUN chmod +x /tmp/fcm-deploy /tmp/fcm-runner && \
    mv /tmp/fcm-deploy /usr/local/bin/fcm-deploy && \
    mv /tmp/fcm-runner /usr/local/bin/fcm-runner
