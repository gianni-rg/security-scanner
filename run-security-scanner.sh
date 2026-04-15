#!/usr/bin/env bash
# Copyright (c) 2026 Gianni Rosa Gallina.
# This script is licensed under the APACHE-2.0 License. See LICENSE file in the project root for full license information.
# It is part of Security Scanner project. See https://github.com/gianni-rg/security-scanner for more details.

set -euo pipefail

usage() {
    local script_name
    script_name=$(basename "$0")
    cat <<EOF
NAME
  $script_name

SYNOPSIS
  Run the hardened security-scanner container against a source directory or container image.

USAGE
    ./$script_name [--scan-path <path>] [--output-path <path>] [--config-path <file>] [--command <name>] [--runtime auto|podman|docker]
                 [--image <ref>] [--image-ref <ref>] [--skip-dirs <csv>] [--fail-on-severity <csv>]
                 [--trivy-timeout <duration>] [--allow-root-fallback] [--pull] [--volume-name <name>]
                 [--allow-localhost-image-from-daemon]
                 [--show-resolved-command] [--help]

    Optional registry auth for private images:
        Set TRIVY_REGISTRY_USERNAME and TRIVY_REGISTRY_PASSWORD in your shell before running trivy-image.

COMMANDS
  all, gitleaks, semgrep, trivy, trivy-vuln, trivy-config, trivy-license,
  syft, hadolint, shellcheck, yamllint, trivy-image

EXAMPLES
  ./$script_name --scan-path . --command all
  ./$script_name --scan-path . --command semgrep
  ./$script_name --scan-path /src/app --output-path /tmp/app-security-scan-output
    ./$script_name --scan-path /src/app --config-path /configs/security-scanner.yml
  ./$script_name --command trivy-image --image-ref ghcr.io/org/app:tag

NOTES
  The source directory is mounted read-only.
  Reports are written outside the scanned tree by default.
  Root fallback is disabled unless explicitly enabled.
    Localhost image scanning from the host daemon is disabled by default and requires --allow-localhost-image-from-daemon.
EOF
}

die() {
    printf '%s\n' "$1" >&2
    exit 1
}

is_windows_drive_path() {
    local path=$1
    [[ "$path" =~ ^[A-Za-z]:[\\/] ]]
}

is_posix_path() {
    local path=$1
    [[ "$path" == /* ]]
}

to_host_path() {
    local path=$1

    if is_windows_drive_path "$path"; then
        printf '%s\n' "$path"
        return
    fi

    if is_posix_path "$path"; then
        if command -v cygpath >/dev/null 2>&1; then
            cygpath -am "$path"
            return
        fi

        if command -v wslpath >/dev/null 2>&1; then
            wslpath -m "$path"
            return
        fi
    fi

    printf '%s\n' "$path"
}

to_filesystem_path() {
    local path=$1

    if is_posix_path "$path"; then
        printf '%s\n' "$path"
        return
    fi

    if is_windows_drive_path "$path"; then
        if command -v cygpath >/dev/null 2>&1; then
            cygpath -u "$path"
            return
        fi

        if command -v wslpath >/dev/null 2>&1; then
            wslpath -u "$path"
            return
        fi
    fi

    printf '%s\n' "$path"
}

to_runtime_mount_path() {
    local runtime_name=$1
    local path=$2

    if [[ "$runtime_name" == *.exe ]]; then
        to_host_path "$path"
        return
    fi

    printf '%s\n' "$path"
}

resolve_runtime() {
    local requested=$1
    if [[ "$requested" != "auto" ]]; then
        command -v "$requested" >/dev/null 2>&1 || die "Container runtime not found: $requested"
        printf '%s\n' "$requested"
        return
    fi

    if command -v wslpath >/dev/null 2>&1; then
        if command -v podman.exe >/dev/null 2>&1; then
            printf '%s\n' 'podman.exe'
            return
        fi

        if command -v docker.exe >/dev/null 2>&1; then
            printf '%s\n' 'docker.exe'
            return
        fi
    fi

    if command -v podman >/dev/null 2>&1; then
        printf '%s\n' 'podman'
        return
    fi

    if command -v docker >/dev/null 2>&1; then
        printf '%s\n' 'docker'
        return
    fi

    die 'Neither podman nor docker was found in PATH.'
}

resolve_existing_dir() {
    local path=$1
    local fs_path

    fs_path=$(to_filesystem_path "$path")
    [[ -d "$fs_path" ]] || die "Scan path must be an existing directory: $path"

    if command -v realpath >/dev/null 2>&1; then
        realpath "$fs_path"
        return
    fi

    (cd "$fs_path" && pwd -P)
}

resolve_candidate_path() {
    local path=$1
    local fs_path
    local dir_name base_name

    fs_path=$(to_filesystem_path "$path")

    if command -v realpath >/dev/null 2>&1; then
        realpath -m "$fs_path"
        return
    fi

    if [[ -e "$fs_path" ]]; then
        if [[ -d "$fs_path" ]]; then
            (cd "$fs_path" && pwd -P)
            return
        fi

        dir_name=$(dirname "$fs_path")
        base_name=$(basename "$fs_path")
        printf '%s/%s\n' "$(cd "$dir_name" && pwd -P)" "$base_name"
        return
    fi

    dir_name=$(dirname "$fs_path")
    base_name=$(basename "$fs_path")

    if [[ -d "$dir_name" ]]; then
        printf '%s/%s\n' "$(cd "$dir_name" && pwd -P)" "$base_name"
        return
    fi

    if [[ "$fs_path" = /* ]]; then
        printf '%s\n' "$fs_path"
        return
    fi

    printf '%s/%s\n' "$(pwd -P)" "$fs_path"
}

default_output_path() {
    local scan_path=$1
    local parent leaf
    parent=$(dirname "$scan_path")
    leaf=$(basename "$scan_path")
    [[ -n "$leaf" ]] || leaf='scan-target'
    printf '%s/%s-security-scan-output\n' "$parent" "$leaf"
}

is_subpath() {
    local parent child
    parent=${1%/}
    child=${2%/}
    [[ "$child" == "$parent" || "$child" == "$parent"/* ]]
}

scan_path='.'
output_path=''
config_path=''
command_name='all'
runtime='auto'
image='localhost/security-scanner:latest'
image_ref=''
skip_dirs=''
fail_on_severity=''
trivy_timeout=''
allow_root_fallback='false'
pull='false'
volume_name='security-scanner-trivy-cache'
show_resolved_command='false'
allow_localhost_image_from_daemon='false'

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scan-path)
            [[ $# -ge 2 ]] || die 'Missing value for --scan-path'
            scan_path=$2
            shift 2
            ;;
        --output-path)
            [[ $# -ge 2 ]] || die 'Missing value for --output-path'
            output_path=$2
            shift 2
            ;;
        --config-path)
            [[ $# -ge 2 ]] || die 'Missing value for --config-path'
            config_path=$2
            shift 2
            ;;
        --command)
            [[ $# -ge 2 ]] || die 'Missing value for --command'
            command_name=$2
            shift 2
            ;;
        --runtime)
            [[ $# -ge 2 ]] || die 'Missing value for --runtime'
            runtime=$2
            shift 2
            ;;
        --image)
            [[ $# -ge 2 ]] || die 'Missing value for --image'
            image=$2
            shift 2
            ;;
        --image-ref)
            [[ $# -ge 2 ]] || die 'Missing value for --image-ref'
            image_ref=$2
            shift 2
            ;;
        --skip-dirs)
            [[ $# -ge 2 ]] || die 'Missing value for --skip-dirs'
            skip_dirs=$2
            shift 2
            ;;
        --fail-on-severity)
            [[ $# -ge 2 ]] || die 'Missing value for --fail-on-severity'
            fail_on_severity=$2
            shift 2
            ;;
        --trivy-timeout)
            [[ $# -ge 2 ]] || die 'Missing value for --trivy-timeout'
            trivy_timeout=$2
            shift 2
            ;;
        --allow-root-fallback)
            allow_root_fallback='true'
            shift
            ;;
        --pull)
            pull='true'
            shift
            ;;
        --volume-name)
            [[ $# -ge 2 ]] || die 'Missing value for --volume-name'
            volume_name=$2
            shift 2
            ;;
        --show-resolved-command)
            show_resolved_command='true'
            shift
            ;;
        --allow-localhost-image-from-daemon)
            allow_localhost_image_from_daemon='true'
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "Unknown argument: $1"
            ;;
    esac
done

case "$command_name" in
    all|gitleaks|semgrep|trivy|trivy-vuln|trivy-config|trivy-license|syft|hadolint|shellcheck|yamllint|trivy-image)
        ;;
    *)
        die "Unsupported command: $command_name"
        ;;
esac

case "$runtime" in
    auto|podman|docker)
        ;;
    *)
        die "Unsupported runtime: $runtime"
        ;;
esac

resolved_scan_path=$(resolve_existing_dir "$scan_path")
if [[ -z "$output_path" ]]; then
    output_path=$(default_output_path "$resolved_scan_path")
fi
resolved_output_path=$(resolve_candidate_path "$output_path")

resolved_config_path=''
if [[ -n "$config_path" ]]; then
    [[ -f "$(to_filesystem_path "$config_path")" ]] || die "Config path must be an existing file: $config_path"
    resolved_config_path=$(resolve_candidate_path "$config_path")
fi

if [[ "$command_name" != 'trivy-image' ]] && is_subpath "$resolved_scan_path" "$resolved_output_path"; then
    die "Output path must be outside the scan path to avoid re-scanning generated reports: $resolved_output_path"
fi

if [[ "$command_name" == 'trivy-image' && -z "$image_ref" ]]; then
    die 'Image reference is required when --command trivy-image is used.'
fi

is_localhost_image_ref='false'
if [[ "$command_name" == 'trivy-image' && "$image_ref" =~ ^[Ll][Oo][Cc][Aa][Ll][Hh][Oo][Ss][Tt]/ ]]; then
    is_localhost_image_ref='true'
fi

if [[ "$is_localhost_image_ref" == 'true' && "$allow_localhost_image_from_daemon" != 'true' ]]; then
    die 'Image reference uses localhost/. To scan host-daemon localhost images, explicitly set --allow-localhost-image-from-daemon.'
fi

if [[ "$allow_localhost_image_from_daemon" == 'true' && "$is_localhost_image_ref" != 'true' ]]; then
    die '--allow-localhost-image-from-daemon is only valid when --command trivy-image and --image-ref starts with localhost/.'
fi

if [[ -n "${TRIVY_REGISTRY_USERNAME:-}" && -z "${TRIVY_REGISTRY_PASSWORD:-}" ]] || [[ -z "${TRIVY_REGISTRY_USERNAME:-}" && -n "${TRIVY_REGISTRY_PASSWORD:-}" ]]; then
    die 'Set both TRIVY_REGISTRY_USERNAME and TRIVY_REGISTRY_PASSWORD (or neither).'
fi

if [[ "$show_resolved_command" == 'true' && -n "${TRIVY_REGISTRY_PASSWORD:-}" ]]; then
    printf 'Warning: --show-resolved-command may expose TRIVY_REGISTRY_PASSWORD in terminal output.\n' >&2
fi

mkdir -p "$resolved_output_path"

resolved_runtime=$(resolve_runtime "$runtime")
runtime_scan_path=$(to_runtime_mount_path "$resolved_runtime" "$resolved_scan_path")
runtime_output_path=$(to_runtime_mount_path "$resolved_runtime" "$resolved_output_path")
runtime_config_path=''
if [[ -n "$resolved_config_path" ]]; then
    runtime_config_path=$(to_runtime_mount_path "$resolved_runtime" "$resolved_config_path")
fi

if [[ "$pull" == 'true' ]]; then
    "$resolved_runtime" pull "$image"
fi

if ! "$resolved_runtime" volume inspect "$volume_name" >/dev/null 2>&1; then
    "$resolved_runtime" volume create "$volume_name" >/dev/null
fi

output_mount="type=bind,src=$runtime_output_path,dst=/output"
cache_mount="type=volume,src=$volume_name,dst=/var/lib/trivy"
scan_mount="type=bind,src=$runtime_scan_path,dst=/workspace,readonly"
config_mount=''
local_image_archive_host_path=''
local_image_mount=''

run_args=(
    run
    --rm
    --init
    --read-only
    --cap-drop=ALL
    --security-opt no-new-privileges:true
    --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=1g,mode=1777"
    --tmpfs "/run:rw,noexec,nosuid,nodev,size=16m,mode=755"
    --mount "$output_mount"
    --mount "$cache_mount"
    --env OUTPUT_DIR=/output
    --env "ALLOW_ROOT_FALLBACK=$allow_root_fallback"
)

if [[ -n "$resolved_config_path" ]]; then
    config_mount="type=bind,src=$runtime_config_path,dst=/run/scanner/config.yml,readonly"
    run_args+=(--mount "$config_mount" --env CONFIG_FILE=/run/scanner/config.yml)
else
    run_args+=(--env CONFIG_FILE=/app/config.yml)
fi

if [[ "$is_localhost_image_ref" == 'true' ]]; then
    local_image_archive_host_path="$resolved_output_path/localhost-image-input.tar"
    rm -f "$local_image_archive_host_path"

    if [[ "$resolved_runtime" == podman* ]]; then
        "$resolved_runtime" image save --format docker-archive --output "$local_image_archive_host_path" "$image_ref"
    else
        "$resolved_runtime" image save --output "$local_image_archive_host_path" "$image_ref"
    fi

    [[ -f "$local_image_archive_host_path" ]] || die "Failed to export localhost image from daemon: $image_ref"
    runtime_local_image_archive_path=$(to_runtime_mount_path "$resolved_runtime" "$local_image_archive_host_path")
    local_image_mount="type=bind,src=$runtime_local_image_archive_path,dst=/run/scanner/localhost-image-input.tar,readonly"
    run_args+=(--mount "$local_image_mount" --env IMAGE_INPUT=/run/scanner/localhost-image-input.tar)
fi

if [[ "$allow_root_fallback" == 'true' ]]; then
    run_args+=(--user 0:0)
fi

if [[ "$command_name" != 'trivy-image' ]]; then
    run_args+=(--mount "$scan_mount" --env SCAN_DIR=/workspace)
fi

if [[ -n "$skip_dirs" ]]; then
    run_args+=(--env "SKIP_DIRS=$skip_dirs")
fi

if [[ -n "$fail_on_severity" ]]; then
    run_args+=(--env "FAIL_ON_SEVERITY=$fail_on_severity")
fi

if [[ -n "$trivy_timeout" ]]; then
    run_args+=(--env "TRIVY_TIMEOUT=$trivy_timeout")
fi

if [[ -n "$image_ref" ]]; then
    run_args+=(--env "IMAGE_REF=$image_ref")
fi

if [[ -n "${TRIVY_REGISTRY_USERNAME:-}" ]]; then
    run_args+=(--env "TRIVY_REGISTRY_USERNAME=$TRIVY_REGISTRY_USERNAME")
fi

if [[ -n "${TRIVY_REGISTRY_PASSWORD:-}" ]]; then
    run_args+=(--env "TRIVY_REGISTRY_PASSWORD=$TRIVY_REGISTRY_PASSWORD")
fi

run_args+=("$image" "$command_name")

printf 'Execution plan\n'
printf '  Runtime: %s\n' "$resolved_runtime"
printf '  Image: %s\n' "$image"
printf '  Command: %s\n' "$command_name"
if [[ "$command_name" == 'trivy-image' ]]; then
    printf '  ImageRef: %s\n' "$image_ref"
    printf '  ScanPath: not used\n'
else
    printf '  ScanPath: %s\n' "$resolved_scan_path"
fi
printf '  OutputPath: %s\n' "$resolved_output_path"
if [[ -n "$resolved_config_path" ]]; then
    printf '  ConfigPath: %s\n' "$resolved_config_path"
else
    printf '  ConfigPath: %s\n' '/app/config.yml (image default)'
fi
printf '  CacheVolume: %s\n' "$volume_name"
printf '  AllowRootFallback: %s\n' "$allow_root_fallback"
printf '  AllowLocalhostImageFromDaemon: %s\n' "$allow_localhost_image_from_daemon"
if [[ "$is_localhost_image_ref" == 'true' ]]; then
    printf '  LocalhostImageArchive: %s\n' "$local_image_archive_host_path"
fi

if [[ "$show_resolved_command" == 'true' ]]; then
    printf 'Resolved command\n'
    printf '%q ' "$resolved_runtime" "${run_args[@]}"
    printf '\n'
fi

"$resolved_runtime" "${run_args[@]}"