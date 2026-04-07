FROM alpine:3.19

# Tools needed to execute and trace files
RUN apk add --no-cache \
    strace \
    bash \
    python3 \
    perl \
    coreutils \
    file \
    util-linux

WORKDIR /malware
