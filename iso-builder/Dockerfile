FROM debian:bookworm

# Add amd64 architecture support
RUN dpkg --add-architecture amd64 && \
    apt-get update && \
    apt-get install -y \
    live-build \
    debootstrap \
    squashfs-tools \
    xorriso \
    grub-pc-bin:amd64 \
    grub-efi-amd64-bin:amd64 \
    mtools \
    dosfstools \
    && rm -rf /var/lib/apt/lists/*

COPY claudeos-source /claudeos-source
COPY build-iso.sh /build-iso.sh
RUN chmod +x /build-iso.sh

RUN mkdir -p /output

CMD ["/bin/bash", "/build-iso.sh"]
