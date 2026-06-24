FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    dosbox coreutils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /dosbox/c/decoys /dosbox/c/target_dir
RUN for d in a b c d e; do printf '\315\040' > /dosbox/c/decoys/decoy_$d.com; done

COPY dosbox.conf /dosbox/dosbox.conf
WORKDIR /dosbox
