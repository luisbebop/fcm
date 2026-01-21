FROM alpine:edge

RUN apk add --no-cache \
    openssh ruby ruby-bundler python3 py3-pip \
    curl bash iproute2

# Configure SSH
RUN ssh-keygen -A && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "root:root" | chpasswd

# Copy init script (configures network from cmdline, starts sshd)
COPY init /sbin/init
RUN chmod +x /sbin/init
