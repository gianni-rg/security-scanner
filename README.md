# Security Scanner

This is an opinionated repository that can be used to run security scans on your codebase. It provides tools and configurations for automated and local security scans, utilizing popular scanners like Trivy and Gitleaks. The repository is currently designed to work for *local development*, helping to identify and address security vulnerabilities early in the development process (especially when using AI-based coding agents).

## Included Tools

| Tool | Function | Description |
| ---- | -------- | ----------- |
| **Gitleaks** | Secret Detection | Detects secrets, API keys, passwords in code |
| **Semgrep** | SAST | Static Application Security Testing |
| **Trivy** | Vulnerability Scan | Dependency vulnerability scanning |
| **Trivy** | IaC Scan | Terraform, Docker, K8s configuration scanning |
| **Trivy** | License Scan | Dependency license analysis |
| **Trivy** | Image Scan | Optional container image vulnerability scanning |
| **Syft** | SBOM | Software Bill of Materials generation |
| **Hadolint** | Dockerfile Lint | Dockerfile best practices |
| **ShellCheck** | Shell Script Lint | Shell script static analysis |
| **yamllint** | YAML Lint | YAML syntax and quality validation |

## Quick Start

> All the development and usage instructions assume you are in Windows with PowerShell v7.x or later, and have either Docker or Podman installed on your machine. The examples below use `podman` as the runtime, but you can replace it with `docker` if you prefer.

### Build the image

```powershell
# Podman defaults to OCI image format, which ignores HEALTHCHECK.
# Build in Docker format so the image keeps the declared health check.
podman build --format docker -t localhost/security-scanner:latest .
```

### Run all scans

```powershell
# Scan the repository root
$env:OUTPUT_PATH='D:/path/to/security-scan-output'; podman compose run --rm security-scanner

# Scan a specific directory
$env:SCAN_PATH='D:/path/to/your/project'; $env:OUTPUT_PATH='D:/path/to/security-scan-output'; podman compose run --rm security-scanner
```

### Run specific scans

```shell
# Gitleaks only (secrets)
podman compose run --rm gitleaks

# Semgrep only (SAST)
podman compose run --rm semgrep

# Trivy only (all scans)
podman compose run --rm trivy

# Trivy vulnerabilities only
podman compose run --rm trivy-vuln

# Trivy IaC/config only
podman compose run --rm trivy-config

# Trivy licenses only
podman compose run --rm trivy-license

# Syft only (SBOM)
podman compose run --rm syft

# Hadolint only
podman compose run --rm hadolint

# ShellCheck only
podman compose run --rm shellcheck

# yamllint only
podman compose run --rm yamllint

# Trivy image scan only
$env:IMAGE_REF='ghcr.io/org/app:tag'; podman compose run --rm trivy-image
```

## Output

Results are saved in the `./output` directory by default (configurable via `OUTPUT_PATH`).

> Remember to create the output directory on the host if it doesn't exist, and ensure the container user has write permissions to it.

When you scan a project directory, prefer setting `OUTPUT_PATH` to a directory *outside* the scanned tree. Otherwise, generated reports can be picked up by later scans and create false positives.

> In both Compose and direct-run modes, avoid mounting `/output` to a directory inside the scanned source tree. Keep reports in a sibling or separate directory.

### Generated files

```text
output/
├── summary_YYYYMMDD_HHMMSS.json        # JSON summary
├── summary_YYYYMMDD_HHMMSS.md          # Markdown summary
├── gitleaks_YYYYMMDD_HHMMSS.json       # Gitleaks results
├── semgrep_YYYYMMDD_HHMMSS.json        # Semgrep results
├── semgrep_YYYYMMDD_HHMMSS.sarif       # Semgrep SARIF format
├── trivy-vuln_YYYYMMDD_HHMMSS.json     # Trivy vulnerabilities
├── trivy-vuln_YYYYMMDD_HHMMSS.sarif    # Trivy SARIF format
├── trivy-config_YYYYMMDD_HHMMSS.json   # Trivy IaC/config
├── trivy-license_YYYYMMDD_HHMMSS.json  # Trivy licenses
├── shellcheck_YYYYMMDD_HHMMSS.json     # ShellCheck results
├── shellcheck_YYYYMMDD_HHMMSS.sarif    # ShellCheck SARIF format
├── shellcheck_YYYYMMDD_HHMMSS.txt      # ShellCheck text output
├── yamllint_YYYYMMDD_HHMMSS.json       # yamllint results
├── yamllint_YYYYMMDD_HHMMSS.sarif      # yamllint SARIF format
├── yamllint_YYYYMMDD_HHMMSS.txt        # yamllint parsable output
├── sbom_YYYYMMDD_HHMMSS.spdx.json      # SBOM SPDX format
├── sbom_YYYYMMDD_HHMMSS.cyclonedx.json # SBOM CycloneDX format
└── hadolint_YYYYMMDD_HHMMSS.json       # Hadolint results
```

Optional `trivy-image` runs also produce `trivy-image_YYYYMMDD_HHMMSS.json`, `trivy-image_YYYYMMDD_HHMMSS.sarif`, and `trivy-image_YYYYMMDD_HHMMSS.txt`.

## Configuration

### Environment variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SCAN_PATH` | `.` | Directory to scan |
| `OUTPUT_PATH` | `./output` | Results directory |
| `SKIP_DIRS` | `node_modules,vendor,...` | Directories to exclude |
| `FAIL_ON_SEVERITY` | `CRITICAL,HIGH` | Severity levels that cause failure |
| `TRIVY_TIMEOUT` | `30m` | Timeout passed to each Trivy filesystem scan |
| `ALLOW_ROOT_FALLBACK` | `false` | Explicitly allow root execution if the runtime cannot drop privileges |
| `FORBIDDEN_LICENSES` | `GPL-3.0,AGPL-3.0` | License identifiers that fail the scan |
| `HADOLINT_FAIL_ON` | `error` | Hadolint levels that fail the scan |
| `HADOLINT_IGNORED_RULES` | empty | Comma-separated Hadolint rules to ignore |
| `SHELLCHECK_SEVERITY` | `warning` | Minimum ShellCheck severity included in findings |
| `YAMLLINT_FAIL_ON` | `error,warning` | yamllint levels that fail the scan |
| `IMAGE_REF` | empty | Container image reference used by the optional `trivy-image` command |

### Custom configuration example

```powershell
$env:SCAN_PATH='D:/path/to/your/project'
$env:OUTPUT_PATH='D:/path/to/your/reports'
$env:SKIP_DIRS='node_modules,dist,build,bin,obj'
$env:FAIL_ON_SEVERITY='CRITICAL'
$env:TRIVY_TIMEOUT='60m'
$env:ALLOW_ROOT_FALLBACK='true'
$env:FORBIDDEN_LICENSES='GPL-3.0,AGPL-3.0'
$env:SHELLCHECK_SEVERITY='warning'
$env:YAMLLINT_FAIL_ON='error,warning'
podman compose run --rm security-scanner
```

The scanner container runs with stricter defaults:

- non-root user inside the image
- read-only root filesystem in compose
- all Linux capabilities dropped
- `no-new-privileges` enabled
- writable state isolated to hardened tmpfs paths, the Trivy cache volume, and the explicit output bind mount

If Trivy times out on large repositories, exclude generated output first, especially `.NET` build folders like `bin` and `obj`. Increase `TRIVY_TIMEOUT` only when source-relevant paths still need more time to analyze.

On runtimes that do not permit in-container UID/GID switching (rootless containers), privilege drop fails closed by default. Set `$env:ALLOW_ROOT_FALLBACK=true` only when you explicitly accept root execution for that environment and start the container as root for that run, for example with `$env:ALLOW_ROOT_FALLBACK='true'; podman compose run --user 0:0 --rm security-scanner`.

### Compose vs. direct run

Use `podman compose` or `docker compose` as the default path when possible. In this repository, Compose is the safer and more convenient wrapper because it already applies the hardened runtime settings used by the scanner: read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, tmpfs mounts for writable transient paths, the output bind mount, and the persistent Trivy cache volume.

> Direct `podman run` or `docker run` is fully supported, but it is a lower-level interface. If you use it, *you are responsible for reproducing the same security controls and writable mounts yourself*.

## Direct Podman usage

```powershell
# Build
podman build --format docker -t localhost/security-scanner:latest .

# Create the persistent Trivy cache volume once
podman volume exists security-scanner-trivy-cache 2>$null
if ($LASTEXITCODE -ne 0) { podman volume create security-scanner-trivy-cache | Out-Null }

# Run all scans with the same hardening used by compose
$scanPath = 'D:/path/to/scan'
$outputPath = 'D:/path/to/output'
$workspaceMount = "type=bind,src=$scanPath,dst=/workspace,readonly"
$outputMount = "type=bind,src=$outputPath,dst=/output"
$cacheMount = 'type=volume,src=security-scanner-trivy-cache,dst=/var/lib/trivy'
podman run --rm --init --read-only `
  --cap-drop=ALL `
  --security-opt no-new-privileges:true `
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1g,mode=1777 `
  --tmpfs /run:rw,noexec,nosuid,nodev,size=16m,mode=755 `
  --mount $workspaceMount `
  --mount $outputMount `
  --mount $cacheMount `
  --env SCAN_DIR=/workspace `
  --env OUTPUT_DIR=/output `
  --env SKIP_DIRS=node_modules,vendor,bin,obj,.terraform,dist,build,target,.venv,venv,__pycache__,.gradle,Pods `
  --env FAIL_ON_SEVERITY=CRITICAL,HIGH `
  --env TRIVY_TIMEOUT=30m `
  --env ALLOW_ROOT_FALLBACK=false `
  --env SHELLCHECK_SEVERITY=warning `
  --env YAMLLINT_FAIL_ON=error,warning `
  --env CONFIG_FILE=/app/config.yml `
  localhost/security-scanner:latest all

# Run a specific scan
podman run --rm --init --read-only `
  --cap-drop=ALL `
  --security-opt no-new-privileges:true `
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1g,mode=1777 `
  --tmpfs /run:rw,noexec,nosuid,nodev,size=16m,mode=755 `
  --mount $workspaceMount `
  --mount $outputMount `
  --mount $cacheMount `
  --env SCAN_DIR=/workspace `
  --env OUTPUT_DIR=/output `
  --env SKIP_DIRS=node_modules,vendor,bin,obj,.terraform,dist,build,target,.venv,venv,__pycache__,.gradle,Pods `
  --env FAIL_ON_SEVERITY=CRITICAL,HIGH `
  --env TRIVY_TIMEOUT=30m `
  --env ALLOW_ROOT_FALLBACK=false `
  --env SHELLCHECK_SEVERITY=warning `
  --env YAMLLINT_FAIL_ON=error,warning `
  --env CONFIG_FILE=/app/config.yml `
  localhost/security-scanner:latest gitleaks

# Run an optional container image scan
$imageRef = 'ghcr.io/org/app:tag'
podman run --rm --init --read-only `
  --cap-drop=ALL `
  --security-opt no-new-privileges:true `
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1g,mode=1777 `
  --tmpfs /run:rw,noexec,nosuid,nodev,size=16m,mode=755 `
  --mount $outputMount `
  --mount $cacheMount `
  --env OUTPUT_DIR=/output `
  --env TRIVY_TIMEOUT=30m `
  --env IMAGE_REF=$imageRef `
  --env ALLOW_ROOT_FALLBACK=false `
  --env CONFIG_FILE=/app/config.yml `
  localhost/security-scanner:latest trivy-image
```

## Direct Docker usage

```powershell
# Build
docker build -t localhost/security-scanner:latest .

# Create the persistent Trivy cache volume once
docker volume inspect security-scanner-trivy-cache *> $null
if ($LASTEXITCODE -ne 0) { docker volume create security-scanner-trivy-cache | Out-Null }

$scanPath = 'D:/path/to/scan'
$outputPath = 'D:/path/to/output'
$workspaceMount = "type=bind,src=$scanPath,dst=/workspace,readonly"
$outputMount = "type=bind,src=$outputPath,dst=/output"
$cacheMount = 'type=volume,src=security-scanner-trivy-cache,dst=/var/lib/trivy'
docker run --rm --init --read-only `
  --cap-drop=ALL `
  --security-opt no-new-privileges:true `
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1g,mode=1777 `
  --tmpfs /run:rw,noexec,nosuid,nodev,size=16m,mode=755 `
  --mount $workspaceMount `
  --mount $outputMount `
  --mount $cacheMount `
  --env SCAN_DIR=/workspace `
  --env OUTPUT_DIR=/output `
  --env SKIP_DIRS=node_modules,vendor,bin,obj,.terraform,dist,build,target,.venv,venv,__pycache__,.gradle,Pods `
  --env FAIL_ON_SEVERITY=CRITICAL,HIGH `
  --env TRIVY_TIMEOUT=30m `
  --env ALLOW_ROOT_FALLBACK=false `
  --env SHELLCHECK_SEVERITY=warning `
  --env YAMLLINT_FAIL_ON=error,warning `
  --env CONFIG_FILE=/app/config.yml `
  localhost/security-scanner:latest all
```

When using direct container invocations, keep the output directory outside the scanned source tree. In PowerShell, passing the mount specification through variables avoids quoting issues with `--mount`. If you explicitly need root execution because your runtime cannot drop privileges inside the container, add `--user 0:0` and set `ALLOW_ROOT_FALLBACK=true` for that run.

## Output Format

### Summary JSON

```json
{
    "scan_id": "scan_20260323_183000",
    "timestamp": "2026-03-23T18:30:00+00:00",
    "scan_directory": "/workspace",
    "overall_status": "PASSED",
    "results": {
        "Gitleaks": "PASSED",
        "Semgrep": "PASSED",
        "Trivy-Vuln": "FAILED",
        "Trivy-Config": "PASSED",
        "Trivy-License": "PASSED",
        "Syft": "PASSED",
        "Hadolint": "SKIPPED"
    }
}
```

### Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0` | All scans passed |
| `1` | At least one scan failed |

## Contribution

The project is constantly evolving and contributions are warmly welcomed.

I'm more than happy to receive any kind of contribution to this project: from helpful feedbacks to bug reports, documentation, usage examples, feature requests, or directly contributions for bug fixes and new and/or improved features.

Feel free to file issues and pull requests on the repository and I'll address them as much as I can, *with a best effort approach during my spare time*. DO NOT expect a super fast turnaround, but I'll do my best to keep the project active and responsive.

> Given that development is mainly done on Windows/WSL, other platforms are not directly developed, tested, or supported. Help is kindly appreciated in making the tool work on other platforms as well.

## License

This project is licensed under the [Apache License 2.0](./LICENSE).

Copyright © 2026 Gianni Rosa Gallina.
