FROM alpine:3.19

# Install required packages
RUN apk add --no-cache \
    nftables \
    iperf3 \
    hping3 \
    iproute2 \
    bash \
    curl \
    tcpdump \
    iputils \
    net-tools \
    procps \
    jq

# Create necessary directories
RUN mkdir -p /etc/nftables.d

# Copy default nftables config if it exists (will be overridden by bind mount)
COPY --chown=root:root nftables.conf /etc/nftables.conf.default

# Set up sysctl for networking
RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# Ensure nftables service can start
RUN mkdir -p /run/nftables

# Default command
CMD ["/bin/bash"]
