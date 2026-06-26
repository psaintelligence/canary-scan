# syntax=docker/dockerfile:1

# ==============================================================================
# STAGE 1: Builder (Python build environment with uv)
# ==============================================================================
FROM python:3.14-slim-bookworm AS builder

# Copy uv from official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

WORKDIR /app

# Copy package files and source
COPY src/ /app/src/
COPY pyproject.toml uv.lock README.md LICENSE /app/

# Create virtual environment and install dependencies + package physically
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv && \
    uv pip install --no-editable ".[specialized,imaging]"

# ==============================================================================
# STAGE 2: Runtime (final production image)
# ==============================================================================
FROM python:3.14-slim-bookworm AS runtime

# Enable non-free packages in sources list to install unrar
RUN sed -i 's/Components: main/Components: main contrib non-free/g' /etc/apt/sources.list.d/debian.sources

# Install system utilities required by canary-scan's file type parsers
RUN apt-get update && apt-get install -y --no-install-recommends \
    libimage-exiftool-perl \
    qpdf \
    poppler-utils \
    mupdf-tools \
    ripgrep \
    unzip \
    p7zip-full \
    unrar \
    imagemagick \
    steghide \
    pngcheck \
    libzbar0 \
    jq \
    wget \
    ca-certificates \
    && wget -O /tmp/stegseek.deb https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb \
    && apt-get install -y --no-install-recommends /tmp/stegseek.deb \
    && rm -rf /tmp/stegseek.deb \
    && apt-get purge -y --auto-remove wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-privileged system user for secure container execution
RUN groupadd -g 10001 canarygroup && \
    useradd -u 10001 -g canarygroup -m -s /bin/bash canaryuser

WORKDIR /data

# Copy the prepared production virtual environment from the builder stage
COPY --from=builder --chown=canaryuser:canarygroup /app/.venv /app/.venv

# Prepend virtual environment binaries to PATH
ENV PATH="/app/.venv/bin:$PATH"

# Run as non-root user
USER 10001:10001

# Entrypoint to execute canary-scan CLI directly
ENTRYPOINT ["canary-scan"]
CMD ["--help"]
