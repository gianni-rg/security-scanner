# Security Scanner

Security Scanner is an opinionated, hardened, containerized scanner for source repositories and container images. It packages Gitleaks, Semgrep, Trivy, Syft, Hadolint, ShellCheck, and yamllint behind a single runtime contract so you can scan code without granting the container broad host access.

## Included Tools

| Tool | Function | Description |
| ---- | -------- | ----------- |
| **[Gitleaks](https://github.com/gitleaks/gitleaks)** | Secret Detection | Detects secrets, API keys, passwords in code |
| **[Semgrep](https://semgrep.dev/)** | SAST | Static Application Security Testing |
| **[Trivy](https://github.com/aquasecurity/trivy)** | Vulnerability Scan | Dependency vulnerability scanning |
| **Trivy** | IaC Scan | Terraform, Docker, K8s configuration scanning |
| **Trivy** | License Scan | Dependency license analysis |
| **Trivy** | Image Scan | Optional container image vulnerability scanning |
| **[Syft](https://github.com/anchore/syft)** | SBOM | Software Bill of Materials generation |
| **[Hadolint](https://github.com/hadolint/hadolint)** | Dockerfile Lint | Dockerfile best practices |
| **[ShellCheck](https://github.com/koalaman/shellcheck)** | Shell Script Lint | Shell script static analysis |
| **[yamllint](https://github.com/adrienverge/yamllint)** | YAML Lint | YAML syntax and quality validation |

## What This Project Is For

This repository serves two audiences:

1. Consumers who want to run the scanner image from any repository through an opinionated wrapper.
2. Maintainers who want to build, test, and evolve the scanner itself.

The supported consumer entrypoints are the wrapper scripts in the repository root:

1. `run-security-scanner.ps1` for PowerShell
2. `run-security-scanner.sh` for Bash

The supported maintainer entrypoint is `podman compose` or `docker compose` using `docker-compose.yml`.

## Use this scanner from any repository

The wrapper scripts are the primary interface for running the scanner outside this repository. They pick Podman or Docker automatically, create the output directory, ensure the Trivy cache volume exists, and apply the hardened container settings used by this project.

If you publish the image to a registry, pass that image reference with `-Image` or `--image`. The wrappers default to `localhost/security-scanner:latest`, which is convenient for local development after building the image from this repository.

## Requirements

1. [Podman](https://podman.io/) or [Docker](https://www.docker.com/) installed locally
2. [PowerShell](https://learn.microsoft.com/powershell/scripting/install/install-powershell-on-windows) 7 or later for `run-security-scanner.ps1`, or Bash for `run-security-scanner.sh`
3. Permission to create an output directory and a local container volume for Trivy cache data

## Quick Start

### PowerShell

```powershell
./run-security-scanner.ps1 -ScanPath . -Command all
./run-security-scanner.ps1 -ScanPath . -Command gitleaks
./run-security-scanner.ps1 -Command trivy-image -ImageRef ghcr.io/org/app:tag
```

### Bash

```bash
./run-security-scanner.sh --scan-path . --command all
./run-security-scanner.sh --scan-path . --command gitleaks
./run-security-scanner.sh --command trivy-image --image-ref ghcr.io/org/app:tag
```

### Override The Image

```powershell
./run-security-scanner.ps1 -ScanPath . -Image ghcr.io/your-org/security-scanner:1.0.0 -Pull
```

```bash
./run-security-scanner.sh --scan-path . --image ghcr.io/your-org/security-scanner:1.0.0 --pull
```

## Wrapper Options

| Option | Meaning |
| ------ | ------- |
| `-ScanPath` / `--scan-path` | Host directory to scan. Defaults to the current directory. |
| `-OutputPath` / `--output-path` | Host directory for reports. Defaults to a sibling directory outside the scanned tree. |
| `-ConfigPath` / `--config-path` | Optional path to an external scanner config file. When set, the file is mounted read-only and used instead of the image default config. |
| `-Command` / `--command` | Scan command to run. Defaults to `all`. |
| `-Runtime` / `--runtime` | Runtime to use: `auto`, `podman`, or `docker`. Defaults to `auto`. |
| `-Image` / `--image` | Scanner image reference. Defaults to `localhost/security-scanner:latest`. |
| `-ImageRef` / `--image-ref` | Image reference to scan when the command is `trivy-image`. |
| `-SkipDirs` / `--skip-dirs` | Optional comma-separated override for `SKIP_DIRS`. These exclusions are applied to Semgrep, Trivy, Syft, and in-container file discovery. |
| `-FailOnSeverity` / `--fail-on-severity` | Optional comma-separated override for `FAIL_ON_SEVERITY`. |
| `-TrivyTimeout` / `--trivy-timeout` | Optional override for the Trivy timeout. |
| `-AllowRootFallback` / `--allow-root-fallback` | Explicitly opt in to running the container as root with `ALLOW_ROOT_FALLBACK=true`. |
| `-Pull` / `--pull` | Pull the image before running. |
| `-VolumeName` / `--volume-name` | Override the persistent Trivy cache volume name. |
| `-ShowResolvedCommand` / `--show-resolved-command` | Print the generated container runtime command before executing it. |

## Commands

| Command | Description |
| ------- | ----------- |
| `all` | Run the full scan suite |
| `gitleaks` | Run secret detection only |
| `semgrep` | Run Semgrep only |
| `trivy` | Run all Trivy filesystem scans |
| `trivy-vuln` | Run dependency vulnerability scanning only |
| `trivy-config` | Run IaC and configuration scanning only |
| `trivy-license` | Run license checks only |
| `syft` | Generate SBOM output only |
| `hadolint` | Run Hadolint only |
| `shellcheck` | Run ShellCheck only |
| `yamllint` | Run yamllint only |
| `trivy-image` | Scan a container image referenced by `-ImageRef` or `--image-ref` |

## Security Defaults

The wrappers apply the hardened runtime settings on every run:

1. The source directory is mounted read-only at `/workspace`.
2. The container root filesystem is read-only.
3. All Linux capabilities are dropped.
4. `no-new-privileges` is enabled.
5. Writable runtime state is limited to tmpfs mounts, the output bind mount, and the Trivy cache volume.
6. Host networking is not enabled.
7. Host credentials, sockets, and other sensitive mounts are not passed through.
8. Root fallback is disabled unless explicitly requested.

## Output And Exit Codes

Reports are written to a sibling directory outside the scanned tree by default. This avoids generated findings being picked up by later scans.

### Generated Files

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

### Summary JSON Example

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

## Advanced Configuration

The wrappers expose the most common overrides as CLI parameters. The image still supports environment-variable-based configuration, which is useful if you invoke the container directly.

You can also point either wrapper at a config file outside this repository with `-ConfigPath` or `--config-path`. This is the supported way to reuse the scanner image from another source repository while keeping repo-specific scan policy in that external repository.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SCAN_PATH` | `.` | Directory to scan |
| `OUTPUT_PATH` | `./output` | Results directory |
| `SKIP_DIRS` | `node_modules,vendor,...` | Directories to exclude from Semgrep, Trivy, Syft, and entrypoint file discovery. Use `./path` to anchor a rule at the repo root; patterns without `./` are treated as basename or suffix matches. For direct Syft compatibility, prefer patterns starting with `./`, `*/`, or `**/`. |
| `FAIL_ON_SEVERITY` | `CRITICAL,HIGH` | Severity levels that cause failure |
| `TRIVY_TIMEOUT` | `30m` | Timeout passed to each Trivy filesystem scan |
| `ALLOW_ROOT_FALLBACK` | `false` | Explicitly allow root execution if the runtime cannot drop privileges |
| `FORBIDDEN_LICENSES` | `GPL-3.0,AGPL-3.0` | License identifiers that fail the scan |
| `HADOLINT_FAIL_ON` | `error` | Hadolint levels that fail the scan |
| `HADOLINT_IGNORED_RULES` | empty | Comma-separated Hadolint rules to ignore |
| `SHELLCHECK_SEVERITY` | `warning` | Minimum ShellCheck severity included in findings |
| `YAMLLINT_FAIL_ON` | `error,warning` | yamllint levels that fail the scan |
| `IMAGE_REF` | empty | Container image reference used by the optional `trivy-image` command |

If Trivy times out on large repositories, exclude generated output first, especially `.NET` build folders like `bin` and `obj`. Increase `TRIVY_TIMEOUT` only when source-relevant paths still need more time to analyze.

On runtimes that do not permit in-container UID and GID switching, privilege drop fails closed by default. Only enable root fallback when you explicitly accept root execution for that environment.

## Develop This Scanner

Use Compose when working inside this repository. Compose is the canonical maintainer workflow because it captures the hardened runtime settings used by the scanner: read-only root filesystem, dropped capabilities, `no-new-privileges`, tmpfs mounts, output bind mount, and persistent Trivy cache volume.

### Build The Image

```powershell
podman build --format docker -t localhost/security-scanner:latest .
docker build -t localhost/security-scanner:latest .
```

### Run With Compose

```powershell
$env:OUTPUT_PATH='D:/path/to/security-scan-output'; podman compose run --rm security-scanner
$env:SCAN_PATH='D:/path/to/your/project'; $env:OUTPUT_PATH='D:/path/to/security-scan-output'; podman compose run --rm security-scanner
$env:IMAGE_REF='ghcr.io/org/app:tag'; podman compose run --rm trivy-image
```

Compose is defined in `docker-compose.yml` and should remain the source of truth for the hardened runtime in this repository.

### Direct Runtime Equivalents

If you need to debug the wrapper behavior or run the image without Compose, use direct `podman run` or `docker run` and reproduce the same hardening flags explicitly.

```powershell
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
  --env CONFIG_FILE=/app/config.yml `
  localhost/security-scanner:latest all
```

## Repository Layout

| Path | Purpose |
| ---- | ------- |
| `Dockerfile` | Builds the scanner image |
| `entrypoint.sh` | Implements scan orchestration inside the container |
| `config.yml` | Default scanner configuration |
| `docker-compose.yml` | Maintainer-oriented hardened runtime definition |
| `run-security-scanner.ps1` | PowerShell consumer wrapper |
| `run-security-scanner.sh` | Bash consumer wrapper |

## Contribution

The project is constantly evolving and contributions are warmly welcomed.

I'm more than happy to receive any kind of contribution to this project: from helpful feedbacks to bug reports, documentation, usage examples, feature requests, or directly contributions for bug fixes and new and/or improved features.

Feel free to file issues and pull requests on the repository and I'll address them as much as I can, *with a best effort approach during my spare time*. DO NOT expect a super fast turnaround, but I'll do my best to keep the project active and responsive.

> Given that development is mainly done on Windows/WSL, other platforms are not directly developed, tested, or supported. Help is kindly appreciated in making the tool work on other platforms as well.

## License

This project is licensed under the [Apache License 2.0](./LICENSE).

Copyright © 2026 Gianni Rosa Gallina.
