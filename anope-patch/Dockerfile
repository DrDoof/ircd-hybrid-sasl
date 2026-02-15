FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY anope-src /tmp/anope
WORKDIR /tmp/anope

RUN cd build && \
    cmake -DINSTDIR=/opt/anope -DUSE_PCH=OFF .. && \
    make -j$(nproc) && \
    make install

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -s /usr/sbin/nologin anope

COPY --from=builder /opt/anope /opt/anope
WORKDIR /opt/anope

USER anope
ENTRYPOINT ["/opt/anope/bin/services"]
CMD ["--nofork"]
