# Zaman — multi-stage build
# Stage 1: build the Makori core binary
# Stage 2: build the Go web binary
# Stage 3: runtime

FROM ubuntu:24.04 AS core-builder

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

FROM golang:1.27 AS web-builder

WORKDIR /build/web
COPY web/go.mod web/main.go ./
RUN go build -o /build/bin/zaman-web .

# Stage 3: runtime
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=core-builder /build/bin/zaman-core /app/bin/zaman-core
COPY --from=web-builder /build/bin/zaman-web /app/bin/zaman-web
COPY web/static/ /app/web/static/
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
