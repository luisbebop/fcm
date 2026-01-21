FROM alpine:edge

RUN apk add --no-cache \
    dropbear dropbear-scp ruby ruby-bundler python3 py3-pip \
    curl bash iproute2 rng-tools

# Configure dropbear SSH and set root password
RUN mkdir -p /etc/dropbear && \
    dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key && \
    dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key && \
    dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key && \
    echo "root:root" | chpasswd

# Copy init script to temp location first, then move it
COPY init /tmp/init
RUN chmod +x /tmp/init && mv /tmp/init /sbin/init
