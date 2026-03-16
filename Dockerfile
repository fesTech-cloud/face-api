# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.24-bookworm AS builder

# Install dlib and face recognition dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libdlib-dev \
    libatlas-base-dev \
    liblapack-dev \
    libjpeg-dev \
    build-essential \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache Go modules first (faster rebuilds)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary — CGO required for go-face/dlib
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-w -s" \
    -o /app/bin/server \
    .

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime
# ─────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Install only runtime libs (no dev headers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libdlib19.1 \
    libatlas3-base \
    liblapack3 \
    libjpeg62-turbo \
    ca-certificates \
    curl \
    bzip2 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/bin/server ./server

# Download dlib face recognition model files
RUN mkdir -p ./models && \
    curl -fsSL https://github.com/davisking/dlib-models/raw/master/dlib_face_recognition_resnet_model_v1.dat.bz2 \
        | bunzip2 > ./models/dlib_face_recognition_resnet_model_v1.dat && \
    curl -fsSL https://github.com/davisking/dlib-models/raw/master/shape_predictor_5_face_landmarks.dat.bz2 \
        | bunzip2 > ./models/shape_predictor_5_face_landmarks.dat && \
    chown -R appuser:appuser ./models

# Switch to non-root
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["./server"]