# Stage 1: compile minimal ELF32 and ELF64 decoy binaries
FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc gcc-multilib libc6-dev-i386 \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /decoys
RUN printf 'int main(void){return 0;}' > /tmp/decoy.c
# ELF64 decoys (x86-64)
RUN gcc -o /decoys/decoy64_a /tmp/decoy.c
RUN gcc -o /decoys/decoy64_b /tmp/decoy.c
RUN gcc -o /decoys/decoy64_c /tmp/decoy.c
# ELF32 decoys (i386) — targets for 32-bit file infectors
RUN gcc -m32 -o /decoys/decoy32_a /tmp/decoy.c
RUN gcc -m32 -o /decoys/decoy32_b /tmp/decoy.c

# Stage 2: runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace bash python3 perl coreutils file libc6-i386 \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /decoys /malware /targets
COPY --from=builder /decoys/ /decoys/
WORKDIR /malware
