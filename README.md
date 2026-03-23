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
| **Syft** | SBOM | Software Bill of Materials generation |
| **Hadolint** | Dockerfile Lint | Dockerfile best practices |

## Quick Start

> All the development and usage instructions assume you are in Windows with PowerShell v7.x or later, and have either Docker or Podman installed on your machine. The examples below use `podman` as the runtime, but you can replace it with `docker` if you prefer.

### Build the image

```powershell
podman compose build
```

### Run all scans

```powershell
# Scan current directory
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
```

## Output

Results are saved in the `./output` directory by default (configurable via `OUTPUT_PATH`).

When you scan a project directory, prefer setting `OUTPUT_PATH` to a directory *outside* the scanned tree. Otherwise, generated reports can be picked up by later scans and create false positives.

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
├── sbom_YYYYMMDD_HHMMSS.spdx.json      # SBOM SPDX format
├── sbom_YYYYMMDD_HHMMSS.cyclonedx.json # SBOM CycloneDX format
└── hadolint_YYYYMMDD_HHMMSS.json       # Hadolint results
```

## Configuration

### Environment variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SCAN_PATH` | `../..` | Directory to scan |
| `OUTPUT_PATH` | `./output` | Results directory |
| `SKIP_DIRS` | `node_modules,vendor,...` | Directories to exclude |
| `FAIL_ON_SEVERITY` | `CRITICAL,HIGH` | Severity levels that cause failure |
| `ALLOW_ROOT_FALLBACK` | `false` | Explicitly allow root execution if the runtime cannot drop privileges |
| `FORBIDDEN_LICENSES` | `GPL-3.0,AGPL-3.0` | License identifiers that fail the scan |
| `HADOLINT_FAIL_ON` | `error` | Hadolint levels that fail the scan |
| `HADOLINT_IGNORED_RULES` | empty | Comma-separated Hadolint rules to ignore |

### Custom configuration example

```powershell
$env:SCAN_PATH='D:/path/to/your/project'
$env:OUTPUT_PATH='D:/path/to/your/reports'
$env:SKIP_DIRS='node_modules,dist,build'
$env:FAIL_ON_SEVERITY='CRITICAL'
$env:ALLOW_ROOT_FALLBACK='true'
$env:FORBIDDEN_LICENSES='GPL-3.0,AGPL-3.0'
podman compose run --rm security-scanner
```

The scanner container runs with stricter defaults:

- non-root user inside the image
- read-only root filesystem in compose
- all Linux capabilities dropped
- `no-new-privileges` enabled
- writable state isolated to hardened tmpfs paths, the Trivy cache volume, and the explicit output bind mount

On runtimes that do not permit in-container UID/GID switching (rootless containers), privilege drop fails closed by default. Set `$env:ALLOW_ROOT_FALLBACK=true` only when you explicitly accept root execution for that environment and start the container as root for that run, for example with `$env:ALLOW_ROOT_FALLBACK='true'; podman compose run --user 0:0 --rm security-scanner`.

### Compose vs. direct run

Use `podman compose` or `docker compose` as the default path when possible. In this repository, Compose is the safer and more convenient wrapper because it already applies the hardened runtime settings used by the scanner: read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, tmpfs mounts for writable transient paths, the output bind mount, and the persistent Trivy cache volume.

> Direct `podman run` or `docker run` is fully supported, but it is a lower-level interface. If you use it, *you are responsible for reproducing the same security controls and writable mounts yourself*.
>
> In both Compose and direct-run modes, avoid mounting `/output` to a directory inside the scanned source tree. Keep reports in a sibling or separate directory.

## Direct Podman usage

```powershell
# Build
podman build -t localhost/security-scanner .

# Run all scans
podman run --rm `
  -v "D:/path/to/scan:/workspace:ro" `
  -v "D:/path/to/output:/output" `
  localhost/security-scanner all

# Run specific scan
podman run --rm `
  -v "D:/path/to/scan:/workspace:ro" `
  -v "D:/path/to/output:/output" `
  localhost/security-scanner gitleaks
```

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
