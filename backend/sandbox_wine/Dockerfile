FROM debian:bookworm-slim AS pe-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc mingw-w64 \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /decoys
RUN printf 'int main(void){return 0;}' > /tmp/decoy.c
RUN x86_64-w64-mingw32-gcc -o /decoys/decoy_x64_a.exe /tmp/decoy.c
RUN x86_64-w64-mingw32-gcc -o /decoys/decoy_x64_b.exe /tmp/decoy.c
RUN i686-w64-mingw32-gcc   -o /decoys/decoy_x86_a.exe /tmp/decoy.c
RUN i686-w64-mingw32-gcc   -o /decoys/decoy_x86_b.exe /tmp/decoy.c
RUN x86_64-w64-mingw32-gcc -o /decoys/decoy_x64_c.exe /tmp/decoy.c

FROM debian:bookworm-slim
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       strace wine wine32 coreutils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=pe-builder /decoys/ /decoys/
RUN mkdir -p /targets /malware /wine
ENV WINEPREFIX=/wine
ENV WINEDEBUG=-all
WORKDIR /malware
