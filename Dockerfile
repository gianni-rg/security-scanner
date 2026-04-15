FROM python:3.12-slim AS builder

ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG TRIVY_VERSION=0.69.3
ARG TRIVY_SHA256=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75
ARG SYFT_VERSION=1.42.4
ARG SYFT_SHA256=590650c2743b83f327d1bf9bec64f6f83b7fec504187bb84f500c862bf8f2a0f
ARG HADOLINT_VERSION=2.14.0
ARG HADOLINT_SHA256=6bf226944684f56c84dd014e8b979d27425c0148f61b3bd99bcc6f39e9dc5a47
ARG JQ_VERSION=1.8.1
ARG JQ_SHA256=020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d
ARG SEMGREP_VERSION=1.159.0
ARG PYYAML_VERSION=6.0.3
ARG YAMLLINT_VERSION=1.38.0

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tar \
    && rm -rf /var/lib/apt/lists/*

# Install Python tooling into an isolated virtual environment for runtime copy.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir \
        "semgrep==${SEMGREP_VERSION}" \
        "PyYAML==${PYYAML_VERSION}" \
        "yamllint==${YAMLLINT_VERSION}" \
    && /opt/venv/bin/semgrep --version \
    && /opt/venv/bin/yamllint --version

RUN echo "Installing Gitleaks ${GITLEAKS_VERSION}..." \
    && curl -fsSLo /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tar.gz -C /tmp \
    && mv /tmp/gitleaks /usr/local/bin/ \
    && chmod +x /usr/local/bin/gitleaks \
    && rm -f /tmp/gitleaks.tar.gz \
    && gitleaks version

RUN echo "Installing Trivy ${TRIVY_VERSION}..." \
    && curl -fsSLo /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/trivy.tar.gz -C /tmp trivy \
    && mv /tmp/trivy /usr/local/bin/ \
    && chmod +x /usr/local/bin/trivy \
    && rm -f /tmp/trivy.tar.gz \
    && trivy version

RUN echo "Installing Syft ${SYFT_VERSION}..." \
    && curl -fsSLo /tmp/syft.tar.gz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
    && echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/syft.tar.gz -C /tmp syft \
    && mv /tmp/syft /usr/local/bin/ \
    && chmod +x /usr/local/bin/syft \
    && rm -f /tmp/syft.tar.gz \
    && syft version

RUN echo "Installing Hadolint ${HADOLINT_VERSION}..." \
    && curl -fsSLo /usr/local/bin/hadolint "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-linux-x86_64" \
    && echo "${HADOLINT_SHA256}  /usr/local/bin/hadolint" | sha256sum -c - \
    && chmod +x /usr/local/bin/hadolint \
    && hadolint --version

RUN echo "Installing jq ${JQ_VERSION}..." \
    && curl -fsSLo /usr/local/bin/jq "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-amd64" \
    && echo "${JQ_SHA256}  /usr/local/bin/jq" | sha256sum -c - \
    && chmod +x /usr/local/bin/jq \
    && jq --version

RUN rm -f /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.12 \
    && find /opt/venv/lib -type d \( -name 'pip' -o -name 'pip-*.dist-info' \) -prune -exec rm -rf {} +

FROM python:3.12-slim

LABEL maintainer="Gianni Rosa Gallina"
LABEL description="Opinionated containerized security scanner toolset"
LABEL version="1.0.0"

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
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
        --only-upgrade openssl libssl3t64 openssl-provider-legacy \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        shellcheck \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 scanner \
    && useradd --system --uid 10001 --gid 10001 --home-dir /home/scanner --create-home scanner \
    && mkdir -p \
        ${SCAN_DIR} \
        ${OUTPUT_DIR} \
        /tmp/scanner-home \
        /tmp/scanner-cache \
        /tmp/scanner-config \
        /tmp/scanner-cache/semgrep \
        /var/lib/trivy \
    && chown -R scanner:scanner \
        ${SCAN_DIR} \
        ${OUTPUT_DIR} \
        /home/scanner \
        /tmp/scanner-home \
        /tmp/scanner-cache \
        /tmp/scanner-config \
        /var/lib/trivy

COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/syft /usr/local/bin/syft
COPY --from=builder /usr/local/bin/hadolint /usr/local/bin/hadolint
COPY --from=builder /usr/local/bin/jq /usr/local/bin/jq
COPY --from=builder /opt/venv /opt/venv

RUN rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 \
    && rm -rf /usr/local/lib/python3.12/site-packages/pip /usr/local/lib/python3.12/site-packages/pip-*.dist-info

WORKDIR /app

COPY --chown=scanner:scanner entrypoint.sh /app/entrypoint.sh
COPY --chown=scanner:scanner config.yml /app/config.yml

RUN chmod +x /app/*.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/bin/sh", "-c", "command -v gitleaks >/dev/null && command -v semgrep >/dev/null && command -v trivy >/dev/null && command -v syft >/dev/null && command -v hadolint >/dev/null && command -v shellcheck >/dev/null && command -v yamllint >/dev/null"]

WORKDIR ${SCAN_DIR}

USER scanner:scanner

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["all"]
