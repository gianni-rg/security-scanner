#!/usr/bin/env bash

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
  ./$script_name [--scan-path <path>] [--output-path <path>] [--command <name>] [--runtime auto|podman|docker]
                 [--image <ref>] [--image-ref <ref>] [--skip-dirs <csv>] [--fail-on-severity <csv>]
                 [--trivy-timeout <duration>] [--allow-root-fallback] [--pull] [--volume-name <name>]
                 [--show-resolved-command] [--help]

COMMANDS
  all, gitleaks, semgrep, trivy, trivy-vuln, trivy-config, trivy-license,
  syft, hadolint, shellcheck, yamllint, trivy-image

EXAMPLES
  ./$script_name --scan-path . --command all
  ./$script_name --scan-path . --command semgrep
  ./$script_name --scan-path /src/app --output-path /tmp/app-security-scan-output
  ./$script_name --command trivy-image --image-ref ghcr.io/org/app:tag

NOTES
  The source directory is mounted read-only.
  Reports are written outside the scanned tree by default.
  Root fallback is disabled unless explicitly enabled.
EOF
}

die() {
    printf '%s\n' "$1" >&2
    exit 1
}

resolve_runtime() {
    local requested=$1
    if [[ "$requested" != "auto" ]]; then
        command -v "$requested" >/dev/null 2>&1 || die "Container runtime not found: $requested"
        printf '%s\n' "$requested"
        return
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
    [[ -d "$path" ]] || die "Scan path must be an existing directory: $path"
    (cd "$path" && pwd -P)
}

resolve_candidate_path() {
    local path=$1
    if command -v realpath >/dev/null 2>&1; then
        realpath -m "$path"
        return
    fi

    if [[ -e "$path" ]]; then
        (cd "$path" && pwd -P)
        return
    fi

    local dir_name base_name
    dir_name=$(dirname "$path")
    base_name=$(basename "$path")

    if [[ -d "$dir_name" ]]; then
        printf '%s/%s\n' "$(cd "$dir_name" && pwd -P)" "$base_name"
        return
    fi

    printf '%s/%s\n' "$(pwd -P)" "$path"
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

if [[ "$command_name" != 'trivy-image' ]] && is_subpath "$resolved_scan_path" "$resolved_output_path"; then
    die "Output path must be outside the scan path to avoid re-scanning generated reports: $resolved_output_path"
fi

if [[ "$command_name" == 'trivy-image' && -z "$image_ref" ]]; then
    die 'Image reference is required when --command trivy-image is used.'
fi

mkdir -p "$resolved_output_path"

resolved_runtime=$(resolve_runtime "$runtime")
if [[ "$pull" == 'true' ]]; then
    "$resolved_runtime" pull "$image"
fi

if ! "$resolved_runtime" volume inspect "$volume_name" >/dev/null 2>&1; then
    "$resolved_runtime" volume create "$volume_name" >/dev/null
fi

output_mount="type=bind,src=$resolved_output_path,dst=/output"
cache_mount="type=volume,src=$volume_name,dst=/var/lib/trivy"
scan_mount="type=bind,src=$resolved_scan_path,dst=/workspace,readonly"

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
    --env CONFIG_FILE=/app/config.yml
    --env "ALLOW_ROOT_FALLBACK=$allow_root_fallback"
)

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
printf '  CacheVolume: %s\n' "$volume_name"
printf '  AllowRootFallback: %s\n' "$allow_root_fallback"

if [[ "$show_resolved_command" == 'true' ]]; then
    printf 'Resolved command\n'
    printf '%q ' "$resolved_runtime" "${run_args[@]}"
    printf '\n'
fi

"$resolved_runtime" "${run_args[@]}"