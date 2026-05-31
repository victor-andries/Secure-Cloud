FROM --platform=linux/amd64 debian:bookworm-slim AS x86-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc gcc-multilib libc6-dev-i386 \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /decoys
RUN printf 'int main(void){return 0;}' > /tmp/decoy.c
RUN gcc    -o /decoys/decoy64_a /tmp/decoy.c
RUN gcc    -o /decoys/decoy64_b /tmp/decoy.c
RUN gcc    -o /decoys/decoy64_c /tmp/decoy.c
RUN gcc -m32 -o /decoys/decoy32_a /tmp/decoy.c
RUN gcc -m32 -o /decoys/decoy32_b /tmp/decoy.c
RUN gcc -m32 -o /decoys/decoy_1.elf32 /tmp/decoy.c
RUN gcc -m32 -o /decoys/decoy_2.elf32 /tmp/decoy.c

FROM --platform=linux/arm/v7 debian:bookworm-slim AS arm32-builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /decoys
RUN printf 'int main(void){return 0;}' > /tmp/decoy.c
RUN gcc -o /decoys/decoy_arm32_a /tmp/decoy.c
RUN gcc -o /decoys/decoy_arm32_b /tmp/decoy.c

FROM --platform=linux/arm64 debian:bookworm-slim AS arm64-builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /decoys
RUN printf 'int main(void){return 0;}' > /tmp/decoy.c
RUN gcc -o /decoys/decoy_arm64_a /tmp/decoy.c
RUN gcc -o /decoys/decoy_arm64_b /tmp/decoy.c

FROM --platform=linux/amd64 debian:bookworm-slim

RUN dpkg --add-architecture armhf && \
    dpkg --add-architecture arm64 && \
    apt-get update && apt-get install -y --no-install-recommends \
    strace bash python3 perl coreutils file \
    libc6-i386 qemu-user-static \
    libc6:armhf \
    libc6:arm64 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /decoys /malware /targets
COPY --from=x86-builder   /decoys/ /decoys/
COPY --from=arm32-builder /decoys/ /decoys/
COPY --from=arm64-builder /decoys/ /decoys/
WORKDIR /malware
