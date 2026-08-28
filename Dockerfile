# Zaman — multi-stage build
# Stage 1: build the Makori core binary
# Stage 2: runtime with core + weft dashboard

FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates clang make && \
    rm -rf /var/lib/apt/lists/*

# Install Makori
ARG MAKORI_VERSION=0.6.1
RUN curl -fsSL https://mako-lang.dev/install.sh | bash || \
    (mkdir -p /root/.local/bin && \
     curl -fsSL -o /root/.local/bin/makori https://mako-lang.dev/dl/makori-linux-amd64 && \
     chmod +x /root/.local/bin/makori)
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /build
COPY mako.toml main.mko ./
COPY core/ core/

RUN makori build --release core/main.mko -o bin/zaman-core

# Stage 2: runtime
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Install Weft
RUN mkdir -p /usr/local/bin && \
    curl -fsSL https://weft.dev/install.sh | bash || \
    (curl -fsSL -o /usr/local/bin/weft https://weft.dev/dl/weft-linux-amd64 && \
     chmod +x /usr/local/bin/weft)
ENV PATH="/usr/local/bin:/root/.local/bin:${PATH}"

WORKDIR /app

COPY --from=builder /build/bin/zaman-core /app/bin/zaman-core
COPY web/ /app/web/
COPY scripts/ /app/scripts/

RUN mkdir -p /app/data

ENV ZAMAN_SIP_HOST=0.0.0.0 \
    ZAMAN_DB=/app/data/zaman.db \
    ZAMAN_DATA_DIR=/app/data \
    ZAMAN_CORE=http://127.0.0.1:9090

EXPOSE 5060/udp 9060/udp 9090 3000

VOLUME ["/app/data"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
    CMD curl -fs http://127.0.0.1:9090/api/health || exit 1

COPY docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

ENTRYPOINT ["/app/docker-entrypoint.sh"]
