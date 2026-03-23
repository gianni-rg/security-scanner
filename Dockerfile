FROM python:3.12-slim

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG TRIVY_VERSION=0.69.3
ARG TRIVY_SHA256=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75
ARG SYFT_VERSION=1.42.3
ARG SYFT_SHA256=0d6be741479eddd2c8644a288990c04f3df0d609bbc1599a005532a9dff63509
ARG HADOLINT_VERSION=2.14.0
ARG HADOLINT_SHA256=6bf226944684f56c84dd014e8b979d27425c0148f61b3bd99bcc6f39e9dc5a47
ARG SEMGREP_VERSION=1.156.0
ARG PYYAML_VERSION=6.0.2

LABEL maintainer="Gianni Rosa Gallina"
LABEL description="Opinionated containerized security scanner toolset"
LABEL version="1.0.0"

# Environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV SCAN_DIR=/workspace
ENV OUTPUT_DIR=/output
ENV HOME=/tmp/scanner-home
ENV XDG_CACHE_HOME=/tmp/scanner-cache
ENV XDG_CONFIG_HOME=/tmp/scanner-config
ENV SEMGREP_CACHE_DIR=/tmp/scanner-cache/semgrep
ENV SYFT_CACHE_DIR=/output/.cache/syft
ENV TRIVY_CACHE_DIR=/var/lib/trivy

# Install dependencies, create runtime directories, and install scanner tooling.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        git \
        jq \
        ca-certificates \
        zip \
        unzip \
        tar \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 scanner \
    && useradd --system --uid 10001 --gid 10001 --home-dir /home/scanner --create-home scanner \
    && mkdir -p \
        ${SCAN_DIR} \
        ${OUTPUT_DIR} \
        /tools \
        /tmp/scanner-home \
        /tmp/scanner-cache \
        /tmp/scanner-config \
        /tmp/scanner-cache/semgrep \
        /var/lib/trivy \
    && chown -R scanner:scanner \
        ${SCAN_DIR} \
        ${OUTPUT_DIR} \
        /tools \
        /home/scanner \
        /tmp/scanner-home \
        /tmp/scanner-cache \
        /tmp/scanner-config \
        /var/lib/trivy \
    && echo "Installing Gitleaks ${GITLEAKS_VERSION}..." \
    && curl -fsSLo /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tar.gz -C /tmp \
    && mv /tmp/gitleaks /usr/local/bin/ \
    && chmod +x /usr/local/bin/gitleaks \
    && rm -f /tmp/gitleaks.tar.gz \
    && gitleaks version \
    && echo "Installing Semgrep ${SEMGREP_VERSION}..." \
    && pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" "PyYAML==${PYYAML_VERSION}" \
    && semgrep --version \
    && echo "Installing Trivy ${TRIVY_VERSION}..." \
    && curl -fsSLo /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/trivy.tar.gz -C /tmp trivy \
    && mv /tmp/trivy /usr/local/bin/ \
    && chmod +x /usr/local/bin/trivy \
    && rm -f /tmp/trivy.tar.gz \
    && trivy version \
    && echo "Installing Syft ${SYFT_VERSION}..." \
    && curl -fsSLo /tmp/syft.tar.gz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
    && echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/syft.tar.gz -C /tmp syft \
    && mv /tmp/syft /usr/local/bin/ \
    && chmod +x /usr/local/bin/syft \
    && rm -f /tmp/syft.tar.gz \
    && syft version \
    && echo "Installing Hadolint ${HADOLINT_VERSION}..." \
    && curl -fsSLo /usr/local/bin/hadolint "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-linux-x86_64" \
    && echo "${HADOLINT_SHA256}  /usr/local/bin/hadolint" | sha256sum -c - \
    && chmod +x /usr/local/bin/hadolint \
    && hadolint --version

WORKDIR /tools

# =============================================================================
# Copy scripts
# =============================================================================
WORKDIR /app

COPY --chown=scanner:scanner entrypoint.sh /app/entrypoint.sh
COPY --chown=scanner:scanner config.yml /app/config.yml

RUN chmod +x /app/*.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/bin/sh", "-c", "command -v gitleaks >/dev/null && command -v semgrep >/dev/null && command -v trivy >/dev/null && command -v syft >/dev/null && command -v hadolint >/dev/null"]

# Set working directory for scans
WORKDIR ${SCAN_DIR}

USER scanner:scanner

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["all"]
