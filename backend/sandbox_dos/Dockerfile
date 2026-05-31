FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    dosbox coreutils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /dosbox/c/decoys /dosbox/c/target_dir
RUN printf '\xcd\x20' > /dosbox/c/decoys/decoy_a.com
RUN printf '\xcd\x20' > /dosbox/c/decoys/decoy_b.com
RUN printf '\xcd\x20' > /dosbox/c/decoys/decoy_c.com
RUN printf '\xcd\x20' > /dosbox/c/decoys/decoy_d.com
RUN printf '\xcd\x20' > /dosbox/c/decoys/decoy_e.com

COPY dosbox.conf /dosbox/dosbox.conf
WORKDIR /dosbox
