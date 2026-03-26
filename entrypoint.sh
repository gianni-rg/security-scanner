#!/bin/bash
# =============================================================================
# Security Scanner Entrypoint
# =============================================================================
# Usage:
#   podman run --rm localhost/security-scanner all           # Run all scans
#   podman run --rm localhost/security-scanner gitleaks      # Run only Gitleaks
#   podman run --rm localhost/security-scanner semgrep       # Run only Semgrep
#   podman run --rm localhost/security-scanner trivy         # Run all Trivy scans
#   podman run --rm localhost/security-scanner trivy-vuln    # Run Trivy vulnerability scan
#   podman run --rm localhost/security-scanner trivy-config  # Run Trivy IaC/config scan
#   podman run --rm localhost/security-scanner trivy-license # Run Trivy license scan
#   podman run --rm localhost/security-scanner syft          # Run Syft SBOM generation
#   podman run --rm localhost/security-scanner hadolint      # Run Hadolint
#   podman run --rm localhost/security-scanner shellcheck    # Run ShellCheck
#   podman run --rm localhost/security-scanner yamllint      # Run yamllint
# Run optional Trivy image scan
#   podman run --rm -e IMAGE_REF=ghcr.io/org/app:tag localhost/security-scanner trivy-image
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCAN_DIR="${SCAN_DIR:-/workspace}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
CONFIG_FILE="${CONFIG_FILE:-/app/config.yml}"

ensure_valid_json_report() {
    local report_file=$1
    [ -s "$report_file" ] && jq empty "$report_file" >/dev/null 2>&1
}

get_config_value() {
    local key_path=$1
    python - "$CONFIG_FILE" "$key_path" <<'PY' 2>/dev/null || true
import sys
import yaml

config_path, key_path = sys.argv[1], sys.argv[2]

try:
    with open(config_path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
except FileNotFoundError:
    sys.exit(0)

value = data
for part in key_path.split('.'):
    if not isinstance(value, dict) or part not in value:
        sys.exit(0)
    value = value[part]

if isinstance(value, list):
    print(','.join(str(item) for item in value))
elif isinstance(value, bool):
    print('true' if value else 'false')
elif value is None:
    print('')
else:
    print(value)
PY
}

threshold_to_fail_list() {
    case "${1^^}" in
        CRITICAL) echo "CRITICAL" ;;
        HIGH) echo "CRITICAL,HIGH" ;;
        MEDIUM) echo "CRITICAL,HIGH,MEDIUM" ;;
        LOW|INFO) echo "CRITICAL,HIGH,MEDIUM,LOW" ;;
        *) echo "CRITICAL,HIGH" ;;
    esac
}

split_csv() {
    local input=$1
    local array_name=$2
    local -n target_array="$array_name"
    local item
    IFS=',' read -r -a target_array <<< "$input"
    for item in "${!target_array[@]}"; do
        target_array[$item]="$(echo "${target_array[$item]}" | xargs)"
    done
}

csv_contains() {
    local needle="${2^^}"
    local -n values=$1
    local value
    for value in "${values[@]}"; do
        if [ "${value^^}" = "$needle" ]; then
            return 0
        fi
    done
    return 1
}

build_skip_args() {
    local flag=$1
    local array_name=$2
    # shellcheck disable=SC2178
    local -n target_array="$array_name"
    local -a skip_args=()
    local item
    for item in "${SKIP_DIR_ARRAY[@]}"; do
        [ -n "$item" ] && skip_args+=("$flag" "$item")
    done
    target_array=("${skip_args[@]}")
}

append_find_skip_group() {
    local array_name=$1
    local pattern=$2
    # shellcheck disable=SC2178
    local -n target_array="$array_name"

    [ -z "$pattern" ] && return

    if [ "${#target_array[@]}" -gt 0 ]; then
        target_array+=(-o)
    fi

    target_array+=(
        -path "./${pattern}"
        -o -path "./${pattern}/*"
        -o -path "${pattern}"
        -o -path "${pattern}/*"
        -o -path "*/${pattern}"
        -o -path "*/${pattern}/*"
    )
}

build_find_prune_args() {
    local array_name=$1
    # shellcheck disable=SC2178
    local -n target_array="$array_name"
    local item
    local normalized
    local without_globstar

    target_array=()

    for item in "${SKIP_DIR_ARRAY[@]}"; do
        [ -z "$item" ] && continue
        append_find_skip_group "$array_name" "$item"

        normalized="${item#./}"
        if [ "$normalized" != "$item" ]; then
            append_find_skip_group "$array_name" "$normalized"
        fi

        without_globstar="${normalized#\*\*/}"
        if [ "$without_globstar" != "$normalized" ]; then
            append_find_skip_group "$array_name" "$without_globstar"
        fi
    done
}

build_syft_exclude_args() {
    local array_name=$1
    # shellcheck disable=SC2178
    local -n target_array="$array_name"
    local item
    local normalized

    target_array=()

    for item in "${SKIP_DIR_ARRAY[@]}"; do
        [ -z "$item" ] && continue
        normalized="${item#./}"

        case "$normalized" in
            ./*|\*/*|\*\*/*)
                ;;
            *)
                normalized="**/${normalized}"
                ;;
        esac

        target_array+=(--exclude "$normalized")
    done
}

find_files_with_prune() {
    local array_name=$1
    shift
    # shellcheck disable=SC2178
    local -n target_array="$array_name"
    local -a prune_args=()
    local path

    target_array=()
    build_find_prune_args prune_args

    if [ "${#prune_args[@]}" -gt 0 ]; then
        while IFS= read -r -d '' path; do
            target_array+=("$path")
        done < <(find . \( "${prune_args[@]}" \) -prune -o "$@" -print0)
        return
    fi

    while IFS= read -r -d '' path; do
        target_array+=("$path")
    done < <(find . "$@" -print0)
}

convert_trivy_report() {
    local input_file=$1
    local format=$2
    local output_file=$3

    run_as_scanner trivy convert \
        --format "$format" \
        --output "$output_file" \
        "$input_file"
}

path_is_skipped() {
    local path=$1
    local item
    for item in "${SKIP_DIR_ARRAY[@]}"; do
        [ -z "$item" ] && continue
        case "$path" in
            "./${item}"|"./${item}/"*|*/"${item}"|*/"${item}/"*)
                return 0
                ;;
        esac
    done
    return 1
}

semgrep_severity_fails() {
    local error_count=$1
    local warning_count=$2
    if [ "$error_count" -gt 0 ] && (csv_contains FAIL_ON_SEVERITY_ARRAY HIGH || csv_contains FAIL_ON_SEVERITY_ARRAY CRITICAL); then
        return 0
    fi
    if [ "$warning_count" -gt 0 ] && csv_contains FAIL_ON_SEVERITY_ARRAY MEDIUM; then
        return 0
    fi
    return 1
}

trivy_severity_fails() {
    local critical=$1
    local high=$2
    local medium=$3
    local low=$4
    if [ "$critical" -gt 0 ] && csv_contains FAIL_ON_SEVERITY_ARRAY CRITICAL; then
        return 0
    fi
    if [ "$high" -gt 0 ] && csv_contains FAIL_ON_SEVERITY_ARRAY HIGH; then
        return 0
    fi
    if [ "$medium" -gt 0 ] && csv_contains FAIL_ON_SEVERITY_ARRAY MEDIUM; then
        return 0
    fi
    if [ "$low" -gt 0 ] && csv_contains FAIL_ON_SEVERITY_ARRAY LOW; then
        return 0
    fi
    return 1
}

yamllint_severity_fails() {
    local errors=$1
    local warnings=$2
    if [ "$errors" -gt 0 ] && csv_contains YAMLLINT_FAIL_ON_ARRAY ERROR; then
        return 0
    fi
    if [ "$warnings" -gt 0 ] && csv_contains YAMLLINT_FAIL_ON_ARRAY WARNING; then
        return 0
    fi
    return 1
}

DEFAULT_SKIP_DIRS="$(get_config_value general.skip_dirs)"
DEFAULT_SEMGREP_RULESETS="$(get_config_value semgrep.rulesets)"
DEFAULT_FAIL_THRESHOLD="$(get_config_value semgrep.fail_on_severity)"
DEFAULT_FORBIDDEN_LICENSES="$(get_config_value trivy.license.forbidden_licenses)"
DEFAULT_TRIVY_TIMEOUT="$(get_config_value trivy.timeout)"
DEFAULT_HADOLINT_FAIL_ON="$(get_config_value hadolint.fail_on)"
DEFAULT_HADOLINT_IGNORED_RULES="$(get_config_value hadolint.ignored_rules)"
DEFAULT_SHELLCHECK_SEVERITY="$(get_config_value shellcheck.severity)"
DEFAULT_YAMLLINT_FAIL_ON="$(get_config_value yamllint.fail_on)"

SKIP_DIRS="${SKIP_DIRS:-${DEFAULT_SKIP_DIRS:-node_modules,vendor,.terraform,dist,build,target,.venv,venv,__pycache__,.gradle,Pods}}"
FAIL_ON_SEVERITY="${FAIL_ON_SEVERITY:-$(threshold_to_fail_list "${DEFAULT_FAIL_THRESHOLD:-HIGH}")}"
SEMGREP_RULESETS="${SEMGREP_RULESETS:-${DEFAULT_SEMGREP_RULESETS:-auto,p/security-audit,p/secrets}}"
FORBIDDEN_LICENSES="${FORBIDDEN_LICENSES:-${DEFAULT_FORBIDDEN_LICENSES:-GPL-3.0,AGPL-3.0}}"
TRIVY_TIMEOUT="${TRIVY_TIMEOUT:-${DEFAULT_TRIVY_TIMEOUT:-30m}}"
HADOLINT_FAIL_ON="${HADOLINT_FAIL_ON:-${DEFAULT_HADOLINT_FAIL_ON:-error}}"
HADOLINT_IGNORED_RULES="${HADOLINT_IGNORED_RULES:-${DEFAULT_HADOLINT_IGNORED_RULES:-}}"
SHELLCHECK_SEVERITY="${SHELLCHECK_SEVERITY:-${DEFAULT_SHELLCHECK_SEVERITY:-warning}}"
YAMLLINT_FAIL_ON="${YAMLLINT_FAIL_ON:-${DEFAULT_YAMLLINT_FAIL_ON:-error,warning}}"
YAMLLINT_CONFIG_DATA="${YAMLLINT_CONFIG_DATA:-{extends: default, rules: {line-length: disable, comments: disable, comments-indentation: disable, document-start: disable}}}"
IMAGE_REF="${IMAGE_REF:-}"
ALLOW_ROOT_FALLBACK="${ALLOW_ROOT_FALLBACK:-false}"

# shellcheck disable=SC2034
declare -a SKIP_DIR_ARRAY FAIL_ON_SEVERITY_ARRAY SEMGREP_RULESET_ARRAY FORBIDDEN_LICENSE_ARRAY HADOLINT_FAIL_ON_ARRAY HADOLINT_IGNORED_RULES_ARRAY YAMLLINT_FAIL_ON_ARRAY
split_csv "$SKIP_DIRS" SKIP_DIR_ARRAY
split_csv "$FAIL_ON_SEVERITY" FAIL_ON_SEVERITY_ARRAY
split_csv "$SEMGREP_RULESETS" SEMGREP_RULESET_ARRAY
split_csv "$FORBIDDEN_LICENSES" FORBIDDEN_LICENSE_ARRAY
split_csv "$HADOLINT_FAIL_ON" HADOLINT_FAIL_ON_ARRAY
split_csv "$HADOLINT_IGNORED_RULES" HADOLINT_IGNORED_RULES_ARRAY
split_csv "$YAMLLINT_FAIL_ON" YAMLLINT_FAIL_ON_ARRAY

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

CAN_DROP_PRIVILEGES="false"
if [ "$(id -u)" -eq 0 ] && setpriv --reuid 10001 --regid 10001 --clear-groups true sh -c 'exit 0' 2>/dev/null; then
    CAN_DROP_PRIVILEGES="true"
fi

prepare_runtime_path() {
    local path=$1
    mkdir -p "${path}"
    if [ "${CAN_DROP_PRIVILEGES}" = "true" ]; then
        chown -R 10001:10001 "${path}" >/dev/null 2>&1 || true
    fi
}

assert_writable_path() {
    local path=$1
    local description=$2
    if [ "${CAN_DROP_PRIVILEGES}" = "true" ]; then
        if ! setpriv --reuid 10001 --regid 10001 --clear-groups true test -w "${path}" 2>/dev/null; then
            echo "${description} is not writable: ${path}" >&2
            exit 126
        fi
        return
    fi

    if [ ! -w "${path}" ]; then
        echo "${description} is not writable: ${path}" >&2
        exit 126
    fi
}

# Ensure scanner state paths exist on writable mounts before dropping privileges.
export HOME="${HOME:-/tmp/scanner-home}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-/tmp/scanner-cache}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-/tmp/scanner-config}"
export SEMGREP_CACHE_DIR="${SEMGREP_CACHE_DIR:-${XDG_CACHE_HOME}/semgrep}"
export SEMGREP_SETTINGS_FILE="${SEMGREP_SETTINGS_FILE:-${XDG_CONFIG_HOME}/semgrep-settings.yml}"
export SEMGREP_LOG_FILE="${SEMGREP_LOG_FILE:-${XDG_CONFIG_HOME}/semgrep.log}"
export SYFT_CACHE_DIR="${SYFT_CACHE_DIR:-${OUTPUT_DIR}/.cache/syft}"
export TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/var/lib/trivy}"

prepare_runtime_path "${HOME}"
prepare_runtime_path "${XDG_CACHE_HOME}"
prepare_runtime_path "${XDG_CONFIG_HOME}"
prepare_runtime_path "${SEMGREP_CACHE_DIR}"
prepare_runtime_path "${SYFT_CACHE_DIR}"
prepare_runtime_path "${TRIVY_CACHE_DIR}"
prepare_runtime_path "${TRIVY_CACHE_DIR}/db"

touch "${SEMGREP_LOG_FILE}"
if [ "${CAN_DROP_PRIVILEGES}" = "true" ]; then
    chown 10001:10001 "${SEMGREP_LOG_FILE}" >/dev/null 2>&1 || true
fi

assert_writable_path "${HOME}" "HOME"
assert_writable_path "${XDG_CACHE_HOME}" "XDG cache directory"
assert_writable_path "${XDG_CONFIG_HOME}" "XDG config directory"
assert_writable_path "${SEMGREP_CACHE_DIR}" "Semgrep cache directory"
assert_writable_path "${SYFT_CACHE_DIR}" "Syft cache directory"
assert_writable_path "${TRIVY_CACHE_DIR}" "Trivy cache directory"

run_as_scanner() {
    if [ "$(id -u)" -ne 0 ]; then
        env \
            HOME="$HOME" \
            XDG_CACHE_HOME="$XDG_CACHE_HOME" \
            XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
            SEMGREP_CACHE_DIR="$SEMGREP_CACHE_DIR" \
            SYFT_CACHE_DIR="$SYFT_CACHE_DIR" \
            TRIVY_CACHE_DIR="$TRIVY_CACHE_DIR" \
            PATH="$PATH" \
            "$@"
        return
    fi

    if [ "${CAN_DROP_PRIVILEGES}" = "true" ]; then
        setpriv --reuid 10001 --regid 10001 --clear-groups \
            env \
            HOME="$HOME" \
            XDG_CACHE_HOME="$XDG_CACHE_HOME" \
            XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
            SEMGREP_CACHE_DIR="$SEMGREP_CACHE_DIR" \
            SYFT_CACHE_DIR="$SYFT_CACHE_DIR" \
            TRIVY_CACHE_DIR="$TRIVY_CACHE_DIR" \
            PATH="$PATH" \
            "$@"
        return
    fi

    if [ "${ALLOW_ROOT_FALLBACK,,}" = "true" ]; then
        env \
            HOME="$HOME" \
            XDG_CACHE_HOME="$XDG_CACHE_HOME" \
            XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
            SEMGREP_CACHE_DIR="$SEMGREP_CACHE_DIR" \
            SYFT_CACHE_DIR="$SYFT_CACHE_DIR" \
            TRIVY_CACHE_DIR="$TRIVY_CACHE_DIR" \
            PATH="$PATH" \
            "$@"
        return
    fi

    echo "Privilege drop unavailable and ALLOW_ROOT_FALLBACK is not enabled" >&2
    return 126
}

run_as_scanner git config --global --add safe.directory "${SCAN_DIR}" >/dev/null 2>&1 || true

# Timestamp for this scan run
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCAN_ID="scan_${TIMESTAMP}"

echo -e "${BLUE}============================${NC}"
echo -e "${BLUE}  Security Scan${NC}"
echo -e "${BLUE}============================${NC}"
echo -e "${YELLOW}Scan ID:${NC} ${SCAN_ID}"
echo -e "${YELLOW}Target:${NC} ${SCAN_DIR}"
echo -e "${YELLOW}Output:${NC} ${OUTPUT_DIR}"
echo -e "${BLUE}============================${NC}"
echo ""

# Initialize results tracking
declare -A SCAN_RESULTS
OVERALL_STATUS="PASSED"

# Function to log scan start
log_start() {
    local scan_name=$1
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}🔍 Running: ${scan_name}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Function to log scan result
log_result() {
    local scan_name=$1
    local status=$2
    local details=$3

    SCAN_RESULTS["$scan_name"]="$status"

    if [ "$status" = "PASSED" ]; then
        echo -e "${GREEN}✅ ${scan_name}: PASSED${NC} - ${details}"
    elif [ "$status" = "FAILED" ]; then
        echo -e "${RED}❌ ${scan_name}: FAILED${NC} - ${details}"
        OVERALL_STATUS="FAILED"
    elif [ "$status" = "SKIPPED" ]; then
        echo -e "${YELLOW}⏭️ ${scan_name}: SKIPPED${NC} - ${details}"
    else
        echo -e "${YELLOW}⚠️ ${scan_name}: ${status}${NC} - ${details}"
    fi
}

# =============================================================================
# GITLEAKS - Secret Detection
# =============================================================================
run_gitleaks() {
    log_start "Gitleaks (Secret Detection)"

    local output_file="${OUTPUT_DIR}/gitleaks_${TIMESTAMP}.json"
    local report_file="${OUTPUT_DIR}/gitleaks_${TIMESTAMP}.txt"
    local ignore_arg=()

    cd "${SCAN_DIR}"

    if [ -f ".gitleaksignore" ]; then
        ignore_arg=(--gitleaks-ignore-path .gitleaksignore)
    fi

    # Check if it's a git repository
    if [ -d ".git" ]; then
        run_as_scanner gitleaks detect \
            --source . \
            "${ignore_arg[@]}" \
            --report-format json \
            --report-path "${output_file}" \
            --exit-code 0 \
            --verbose 2>&1 | tee "${report_file}" || true
    else
        run_as_scanner gitleaks detect \
            --source . \
            --no-git \
            "${ignore_arg[@]}" \
            --report-format json \
            --report-path "${output_file}" \
            --exit-code 0 \
            --verbose 2>&1 | tee "${report_file}" || true
    fi

    # Count secrets
    if [ -f "${output_file}" ]; then
        local secrets_count
        secrets_count=$(jq 'length' "${output_file}" 2>/dev/null || echo 0)

        if [ "${secrets_count}" -gt 0 ]; then
            log_result "Gitleaks" "FAILED" "${secrets_count} secrets found"
        else
            log_result "Gitleaks" "PASSED" "No secrets found"
        fi
    else
        log_result "Gitleaks" "PASSED" "No secrets found"
    fi
}

# =============================================================================
# SEMGREP - SAST
# =============================================================================
run_semgrep() {
    log_start "Semgrep (SAST)"

    local output_file="${OUTPUT_DIR}/semgrep_${TIMESTAMP}.json"
    local sarif_file="${OUTPUT_DIR}/semgrep_${TIMESTAMP}.sarif"
    local -a semgrep_args=()
    local -a skip_args=()
    local semgrep_exit=0

    cd "${SCAN_DIR}"

    build_skip_args --exclude skip_args
    for ruleset in "${SEMGREP_RULESET_ARRAY[@]}"; do
        [ -n "$ruleset" ] && semgrep_args+=(--config "$ruleset")
    done

    run_as_scanner semgrep scan \
        "${semgrep_args[@]}" \
        --json \
        --output "${output_file}" \
        --sarif-output "${sarif_file}" \
        "${skip_args[@]}" \
        --metrics off \
        --quiet \
        . 2>&1 || semgrep_exit=$?

    if ! ensure_valid_json_report "${output_file}"; then
        log_result "Semgrep" "FAILED" "Execution failed with exit code ${semgrep_exit}"
        return
    fi

    # Count findings by severity
    if [ -f "${output_file}" ]; then
        local total
        local errors
        local warnings
        total=$(jq '.results | length' "${output_file}" 2>/dev/null || echo 0)
        errors=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' "${output_file}" 2>/dev/null || echo 0)
        warnings=$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' "${output_file}" 2>/dev/null || echo 0)

        if semgrep_severity_fails "$errors" "$warnings"; then
            log_result "Semgrep" "FAILED" "Total: ${total}, Errors: ${errors}, Warnings: ${warnings}"
        else
            log_result "Semgrep" "PASSED" "Total: ${total}, Errors: ${errors}, Warnings: ${warnings}"
        fi
    else
        log_result "Semgrep" "PASSED" "No findings"
    fi
}

# =============================================================================
# TRIVY - Vulnerability Scanning
# =============================================================================
run_trivy_vuln() {
    log_start "Trivy (Vulnerability Scanning)"

    local output_file="${OUTPUT_DIR}/trivy-vuln_${TIMESTAMP}.json"
    local sarif_file="${OUTPUT_DIR}/trivy-vuln_${TIMESTAMP}.sarif"
    local table_file="${OUTPUT_DIR}/trivy-vuln_${TIMESTAMP}.txt"
    local -a skip_args=()
    local trivy_json_exit=0
    local trivy_sarif_exit=0
    local trivy_table_exit=0

    cd "${SCAN_DIR}"

    build_skip_args --skip-dirs skip_args

    # JSON output
    run_as_scanner trivy fs \
        --scanners vuln \
        --format json \
        --output "${output_file}" \
        "${skip_args[@]}" \
        --timeout "${TRIVY_TIMEOUT}" \
        --severity CRITICAL,HIGH,MEDIUM,LOW \
        . 2>&1 || trivy_json_exit=$?

    if ! ensure_valid_json_report "${output_file}"; then
        log_result "Trivy-Vuln" "FAILED" "Execution failed (json=${trivy_json_exit}, sarif=${trivy_sarif_exit}, table=${trivy_table_exit})"
        return
    fi

    convert_trivy_report "${output_file}" sarif "${sarif_file}" 2>&1 || trivy_sarif_exit=$?
    convert_trivy_report "${output_file}" table "${table_file}" 2>&1 || trivy_table_exit=$?

    # Count vulnerabilities
    if [ -f "${output_file}" ]; then
        local critical
        local high
        local medium
        local low
        critical=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "${output_file}" 2>/dev/null || echo 0)
        high=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "${output_file}" 2>/dev/null || echo 0)
        medium=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "${output_file}" 2>/dev/null || echo 0)
        low=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length' "${output_file}" 2>/dev/null || echo 0)

        if trivy_severity_fails "$critical" "$high" "$medium" "$low"; then
            log_result "Trivy-Vuln" "FAILED" "Critical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}"
        else
            log_result "Trivy-Vuln" "PASSED" "Critical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}"
        fi
    else
        log_result "Trivy-Vuln" "PASSED" "No vulnerabilities found"
    fi
}

# =============================================================================
# TRIVY - IaC/Config Scanning
# =============================================================================
run_trivy_config() {
    log_start "Trivy (IaC/Config Scanning)"

    local output_file="${OUTPUT_DIR}/trivy-config_${TIMESTAMP}.json"
    local table_file="${OUTPUT_DIR}/trivy-config_${TIMESTAMP}.txt"
    local -a skip_args=()
    local -a terraform_files=()
    local -a docker_related_files=()
    local -a yaml_files=()
    local trivy_json_exit=0
    local trivy_table_exit=0
    local yaml_file

    cd "${SCAN_DIR}"

    build_skip_args --skip-dirs skip_args

    # Check if IaC files exist
    local has_iac="false"
    find_files_with_prune terraform_files -type f -name "*.tf"
    if [ "${#terraform_files[@]}" -gt 0 ]; then has_iac="true"; fi

    if [ "${has_iac}" = "false" ]; then
        find_files_with_prune docker_related_files -type f \( -name "Dockerfile*" -o -name "*.dockerfile" -o -name "docker-compose*.yml" -o -name "docker-compose*.yaml" \)
        if [ "${#docker_related_files[@]}" -gt 0 ]; then has_iac="true"; fi
    fi

    if [ "${has_iac}" = "false" ]; then
        find_files_with_prune yaml_files -type f \( -name "*.yaml" -o -name "*.yml" \)
        for yaml_file in "${yaml_files[@]}"; do
            if grep -q -m 1 "apiVersion:" "${yaml_file}" 2>/dev/null; then
                has_iac="true"
                break
            fi
        done
    fi

    if [ "${has_iac}" = "false" ]; then
        log_result "Trivy-Config" "SKIPPED" "No IaC files found"
        return
    fi

    # JSON output
    run_as_scanner trivy fs \
        --scanners misconfig \
        --format json \
        --output "${output_file}" \
        "${skip_args[@]}" \
        --timeout "${TRIVY_TIMEOUT}" \
        --severity CRITICAL,HIGH,MEDIUM,LOW \
        . 2>&1 || trivy_json_exit=$?

    if ! ensure_valid_json_report "${output_file}"; then
        log_result "Trivy-Config" "FAILED" "Execution failed (json=${trivy_json_exit}, table=${trivy_table_exit})"
        return
    fi

    convert_trivy_report "${output_file}" table "${table_file}" 2>&1 || trivy_table_exit=$?

    # Count misconfigurations
    if [ -f "${output_file}" ]; then
        local misconfig_count
        local critical
        local high
        local medium
        local low
        misconfig_count=$(jq '[.Results[]?.Misconfigurations[]?] | length' "${output_file}" 2>/dev/null || echo 0)
        critical=$(jq '[.Results[]?.Misconfigurations[]? | select(.Severity=="CRITICAL")] | length' "${output_file}" 2>/dev/null || echo 0)
        high=$(jq '[.Results[]?.Misconfigurations[]? | select(.Severity=="HIGH")] | length' "${output_file}" 2>/dev/null || echo 0)
        medium=$(jq '[.Results[]?.Misconfigurations[]? | select(.Severity=="MEDIUM")] | length' "${output_file}" 2>/dev/null || echo 0)
        low=$(jq '[.Results[]?.Misconfigurations[]? | select(.Severity=="LOW")] | length' "${output_file}" 2>/dev/null || echo 0)

        if trivy_severity_fails "$critical" "$high" "$medium" "$low"; then
            log_result "Trivy-Config" "FAILED" "Total: ${misconfig_count}, Critical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}"
        else
            log_result "Trivy-Config" "PASSED" "Total: ${misconfig_count}, Critical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}"
        fi
    else
        log_result "Trivy-Config" "PASSED" "No misconfigurations found"
    fi
}

# =============================================================================
# TRIVY - License Scanning
# =============================================================================
run_trivy_license() {
    log_start "Trivy (License Scanning)"

    local output_file="${OUTPUT_DIR}/trivy-license_${TIMESTAMP}.json"
    local table_file="${OUTPUT_DIR}/trivy-license_${TIMESTAMP}.txt"
    local -a skip_args=()
    local -a forbidden_matches=()
    local license_name
    local forbidden_license
    local trivy_json_exit=0
    local trivy_table_exit=0

    cd "${SCAN_DIR}"

    build_skip_args --skip-dirs skip_args

    # JSON output
    run_as_scanner trivy fs \
        --scanners license \
        --format json \
        --output "${output_file}" \
        "${skip_args[@]}" \
        --timeout "${TRIVY_TIMEOUT}" \
        . 2>&1 || trivy_json_exit=$?

    if ! ensure_valid_json_report "${output_file}"; then
        log_result "Trivy-License" "FAILED" "Execution failed (json=${trivy_json_exit}, table=${trivy_table_exit})"
        return
    fi

    convert_trivy_report "${output_file}" table "${table_file}" 2>&1 || trivy_table_exit=$?

    # Count licenses
    if [ -f "${output_file}" ]; then
        local license_count
        license_count=$(jq '[.Results[]?.Licenses[]?] | length' "${output_file}" 2>/dev/null || echo 0)
        while IFS= read -r license_name; do
            for forbidden_license in "${FORBIDDEN_LICENSE_ARRAY[@]}"; do
                if [ -n "$forbidden_license" ] && [[ "$license_name" == "$forbidden_license"* ]]; then
                    forbidden_matches+=("$license_name")
                    break
                fi
            done
        done < <(jq -r '.Results[]?.Licenses[]?.Name // empty' "${output_file}" 2>/dev/null | sort -u)

        if [ "${#forbidden_matches[@]}" -gt 0 ]; then
            local matched_list
            matched_list=$(printf '%s, ' "${forbidden_matches[@]}")
            matched_list=${matched_list%, }
            log_result "Trivy-License" "FAILED" "${license_count} licenses detected, forbidden: ${matched_list}"
        else
            log_result "Trivy-License" "PASSED" "${license_count} licenses detected"
        fi
    else
        log_result "Trivy-License" "PASSED" "License scan completed"
    fi
}

write_yamllint_json_report() {
    local input_file=$1
    local output_file=$2
    python - "$input_file" "$output_file" <<'PY'
import json
import re
import sys

input_path, output_path = sys.argv[1], sys.argv[2]
pattern = re.compile(r'^(.*?):(\d+):(\d+): \[(error|warning)\] (.*)$')
results = []

with open(input_path, 'r', encoding='utf-8') as handle:
    for raw_line in handle:
        line = raw_line.rstrip('\n')
        match = pattern.match(line)
        if not match:
            continue
        file_path, line_no, column_no, level, message = match.groups()
        results.append(
            {
                'file': file_path,
                'line': int(line_no),
                'column': int(column_no),
                'level': level,
                'message': message,
            }
        )

with open(output_path, 'w', encoding='utf-8') as handle:
    json.dump(results, handle, indent=2)
PY
}

write_shellcheck_sarif_report() {
    local input_file=$1
    local output_file=$2
    python - "$input_file" "$output_file" <<'PY'
import json
import sys

input_path, output_path = sys.argv[1], sys.argv[2]

with open(input_path, 'r', encoding='utf-8') as handle:
    findings = json.load(handle)

rules = {}
results = []
for finding in findings:
    rule_id = f"SC{finding.get('code', 'unknown')}"
    level = finding.get('level', 'warning').lower()
    rules[rule_id] = {
        'id': rule_id,
        'name': rule_id,
        'shortDescription': {'text': rule_id},
        'helpUri': f"https://www.shellcheck.net/wiki/{rule_id}",
    }
    results.append(
        {
            'ruleId': rule_id,
            'level': 'error' if level == 'error' else 'warning',
            'message': {'text': finding.get('message', '')},
            'locations': [
                {
                    'physicalLocation': {
                        'artifactLocation': {'uri': finding.get('file', '')},
                        'region': {
                            'startLine': finding.get('line', 1),
                            'startColumn': finding.get('column', 1),
                            'endLine': finding.get('endLine', finding.get('line', 1)),
                            'endColumn': finding.get('endColumn', finding.get('column', 1)),
                        },
                    }
                }
            ],
        }
    )

sarif = {
    '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
    'version': '2.1.0',
    'runs': [
        {
            'tool': {
                'driver': {
                    'name': 'ShellCheck',
                    'informationUri': 'https://www.shellcheck.net/',
                    'rules': list(rules.values()),
                }
            },
            'results': results,
        }
    ],
}

with open(output_path, 'w', encoding='utf-8') as handle:
    json.dump(sarif, handle, indent=2)
PY
}

write_yamllint_sarif_report() {
    local input_file=$1
    local output_file=$2
    python - "$input_file" "$output_file" <<'PY'
import json
import sys

input_path, output_path = sys.argv[1], sys.argv[2]

with open(input_path, 'r', encoding='utf-8') as handle:
    findings = json.load(handle)

rules = {
    'yamllint-error': {
        'id': 'yamllint-error',
        'name': 'yamllint-error',
        'shortDescription': {'text': 'yamllint error'},
        'helpUri': 'https://yamllint.readthedocs.io/',
    },
    'yamllint-warning': {
        'id': 'yamllint-warning',
        'name': 'yamllint-warning',
        'shortDescription': {'text': 'yamllint warning'},
        'helpUri': 'https://yamllint.readthedocs.io/',
    },
}

results = []
for finding in findings:
    level = finding.get('level', 'warning').lower()
    rule_id = f"yamllint-{level}"
    results.append(
        {
            'ruleId': rule_id,
            'level': 'error' if level == 'error' else 'warning',
            'message': {'text': finding.get('message', '')},
            'locations': [
                {
                    'physicalLocation': {
                        'artifactLocation': {'uri': finding.get('file', '')},
                        'region': {
                            'startLine': finding.get('line', 1),
                            'startColumn': finding.get('column', 1),
                        },
                    }
                }
            ],
        }
    )

sarif = {
    '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
    'version': '2.1.0',
    'runs': [
        {
            'tool': {
                'driver': {
                    'name': 'yamllint',
                    'informationUri': 'https://yamllint.readthedocs.io/',
                    'rules': list(rules.values()),
                }
            },
            'results': results,
        }
    ],
}

with open(output_path, 'w', encoding='utf-8') as handle:
    json.dump(sarif, handle, indent=2)
PY
}

# =============================================================================
# TRIVY - Container Image Scanning
# =============================================================================
run_trivy_image() {
    log_start "Trivy (Container Image Scanning)"

    local output_file="${OUTPUT_DIR}/trivy-image_${TIMESTAMP}.json"
    local sarif_file="${OUTPUT_DIR}/trivy-image_${TIMESTAMP}.sarif"
    local table_file="${OUTPUT_DIR}/trivy-image_${TIMESTAMP}.txt"
    local trivy_json_exit=0
    local trivy_sarif_exit=0
    local trivy_table_exit=0

    if [ -z "${IMAGE_REF}" ]; then
        log_result "Trivy-Image" "SKIPPED" "IMAGE_REF is not set"
        return
    fi

    run_as_scanner trivy image \
        --format json \
        --output "${output_file}" \
        --timeout "${TRIVY_TIMEOUT}" \
        --severity CRITICAL,HIGH,MEDIUM,LOW \
        "${IMAGE_REF}" 2>&1 || trivy_json_exit=$?

    if ! ensure_valid_json_report "${output_file}"; then
        log_result "Trivy-Image" "FAILED" "Execution failed for ${IMAGE_REF} (json=${trivy_json_exit}, sarif=${trivy_sarif_exit}, table=${trivy_table_exit})"
        return
    fi

    convert_trivy_report "${output_file}" sarif "${sarif_file}" 2>&1 || trivy_sarif_exit=$?
    convert_trivy_report "${output_file}" table "${table_file}" 2>&1 || trivy_table_exit=$?

    local critical
    local high
    local medium
    local low
    critical=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "${output_file}" 2>/dev/null || echo 0)
    high=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "${output_file}" 2>/dev/null || echo 0)
    medium=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' "${output_file}" 2>/dev/null || echo 0)
    low=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length' "${output_file}" 2>/dev/null || echo 0)

    if trivy_severity_fails "$critical" "$high" "$medium" "$low"; then
        log_result "Trivy-Image" "FAILED" "Image: ${IMAGE_REF}, Critical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}"
    else
        log_result "Trivy-Image" "PASSED" "Image: ${IMAGE_REF}, Critical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}"
    fi
}

# =============================================================================
# SYFT - SBOM Generation
# =============================================================================
run_syft() {
    log_start "Syft (SBOM Generation)"

    local spdx_file="${OUTPUT_DIR}/sbom_${TIMESTAMP}.spdx.json"
    local cyclonedx_file="${OUTPUT_DIR}/sbom_${TIMESTAMP}.cyclonedx.json"
    local table_file="${OUTPUT_DIR}/sbom_${TIMESTAMP}.txt"
    local -a exclude_args=()
    local source_name
    local syft_exit=0

    cd "${SCAN_DIR}"
    source_name="$(basename "$(pwd)")"
    build_syft_exclude_args exclude_args

    run_as_scanner syft scan . \
        --source-name "${source_name}" \
        --output spdx-json="${spdx_file}" \
        --output cyclonedx-json="${cyclonedx_file}" \
        --output syft-table="${table_file}" \
        "${exclude_args[@]}" \
        2>&1 || syft_exit=$?

    if [ "${syft_exit}" -ne 0 ]; then
        log_result "Syft" "FAILED" "Execution failed with exit code ${syft_exit}"
        return
    fi

    if ! ensure_valid_json_report "${spdx_file}" || ! ensure_valid_json_report "${cyclonedx_file}"; then
        log_result "Syft" "FAILED" "Execution completed without valid SBOM JSON output"
        return
    fi

    # Count packages
    if [ -f "${spdx_file}" ]; then
        local package_count
        package_count=$(jq '.packages | length' "${spdx_file}" 2>/dev/null || echo 0)
        log_result "Syft" "PASSED" "${package_count} packages cataloged"
    else
        log_result "Syft" "PASSED" "SBOM generated"
    fi
}

# =============================================================================
# HADOLINT - Dockerfile Linting
# =============================================================================
run_hadolint() {
    log_start "Hadolint (Dockerfile Linting)"

    local output_file="${OUTPUT_DIR}/hadolint_${TIMESTAMP}.json"
    local sarif_file="${OUTPUT_DIR}/hadolint_${TIMESTAMP}.sarif"
    local -a ignore_args=()
    local -a dockerfiles=()
    local -a failing_levels=()
    local ignored_rule
    local issue_level
    local dockerfile

    cd "${SCAN_DIR}"

    for ignored_rule in "${HADOLINT_IGNORED_RULES_ARRAY[@]}"; do
        [ -n "$ignored_rule" ] && ignore_args+=(--ignore "$ignored_rule")
    done

    # Find Dockerfiles
    find_files_with_prune dockerfiles -type f \( -name "Dockerfile*" -o -name "*.dockerfile" \)

    if [ "${#dockerfiles[@]}" -eq 0 ]; then
        log_result "Hadolint" "SKIPPED" "No Dockerfiles found"
        return
    fi

    local total_issues=0
    local all_results="[]"

    for dockerfile in "${dockerfiles[@]}"; do
        echo "  Scanning: ${dockerfile}"
        local result
        local count
        result=$(run_as_scanner hadolint --format json "${ignore_args[@]}" "${dockerfile}" 2>/dev/null || echo "[]")
        all_results=$(echo "${all_results}" "${result}" | jq -s 'add')
        count=$(echo "${result}" | jq 'length' 2>/dev/null | tr -d '[:space:]' || echo 0)
        count=${count:-0}
        total_issues=$((total_issues + count))
    done

    echo "${all_results}" > "${output_file}"

    # Count by severity
    local errors
    local warnings
    local styles
    errors=$(echo "${all_results}" | jq '[.[] | select(.level == "error")] | length' 2>/dev/null | tr -d '[:space:]' || echo 0)
    warnings=$(echo "${all_results}" | jq '[.[] | select(.level == "warning")] | length' 2>/dev/null | tr -d '[:space:]' || echo 0)
    styles=$(echo "${all_results}" | jq '[.[] | select(.level == "style" or .level == "info")] | length' 2>/dev/null | tr -d '[:space:]' || echo 0)
    errors=${errors:-0}
    warnings=${warnings:-0}
    styles=${styles:-0}

    for issue_level in "${HADOLINT_FAIL_ON_ARRAY[@]}"; do
        case "${issue_level,,}" in
            error)
                [ "$errors" -gt 0 ] && failing_levels+=(error)
                ;;
            warning)
                [ "$warnings" -gt 0 ] && failing_levels+=(warning)
                ;;
            style|info)
                [ "$styles" -gt 0 ] && failing_levels+=("${issue_level,,}")
                ;;
        esac
    done

    if [ "${#failing_levels[@]}" -gt 0 ]; then
        log_result "Hadolint" "FAILED" "Errors: ${errors}, Warnings: ${warnings}, Style: ${styles}"
    else
        log_result "Hadolint" "PASSED" "Errors: ${errors}, Warnings: ${warnings}, Style: ${styles}"
    fi
}

# =============================================================================
# SHELLCHECK - Shell Script Static Analysis
# =============================================================================
run_shellcheck() {
    log_start "ShellCheck (Shell Script Linting)"

    local output_file="${OUTPUT_DIR}/shellcheck_${TIMESTAMP}.json"
    local report_file="${OUTPUT_DIR}/shellcheck_${TIMESTAMP}.txt"
    local sarif_file="${OUTPUT_DIR}/shellcheck_${TIMESTAMP}.sarif"
    local -a shell_files=()
    local all_results='[]'
    local shell_file

    cd "${SCAN_DIR}"

    find_files_with_prune shell_files -type f \( -name '*.sh' -o -name '*.bash' \)

    if [ "${#shell_files[@]}" -eq 0 ]; then
        log_result "ShellCheck" "SKIPPED" "No shell scripts found"
        return
    fi

    : > "${report_file}"
    for shell_file in "${shell_files[@]}"; do
        local raw_result
        local result
        raw_result=$(run_as_scanner shellcheck --format=json1 --severity="${SHELLCHECK_SEVERITY}" "${shell_file}" 2>/dev/null || echo '{"comments": []}')
        result=$(echo "${raw_result}" | jq '.comments // []')
        all_results=$(echo "${all_results}" "${result}" | jq -s 'add')
        run_as_scanner shellcheck --format=gcc --severity="${SHELLCHECK_SEVERITY}" "${shell_file}" 2>/dev/null >> "${report_file}" || true
    done

    echo "${all_results}" > "${output_file}"
    write_shellcheck_sarif_report "${output_file}" "${sarif_file}"

    local total
    local errors
    local warnings
    local infos
    total=$(jq 'length' "${output_file}" 2>/dev/null | tr -d '[:space:]' || echo 0)
    errors=$(jq '[.[] | select(.level == "error")] | length' "${output_file}" 2>/dev/null | tr -d '[:space:]' || echo 0)
    warnings=$(jq '[.[] | select(.level == "warning")] | length' "${output_file}" 2>/dev/null | tr -d '[:space:]' || echo 0)
    infos=$(jq '[.[] | select(.level == "info" or .level == "style")] | length' "${output_file}" 2>/dev/null | tr -d '[:space:]' || echo 0)
    total=${total:-0}
    errors=${errors:-0}
    warnings=${warnings:-0}
    infos=${infos:-0}

    if [ "$total" -gt 0 ]; then
        log_result "ShellCheck" "FAILED" "Total: ${total}, Errors: ${errors}, Warnings: ${warnings}, Info/Style: ${infos}"
    else
        log_result "ShellCheck" "PASSED" "No shell issues found"
    fi
}

# =============================================================================
# YAMLLINT - YAML Linting
# =============================================================================
run_yamllint() {
    log_start "yamllint (YAML Validation)"

    local output_file="${OUTPUT_DIR}/yamllint_${TIMESTAMP}.json"
    local report_file="${OUTPUT_DIR}/yamllint_${TIMESTAMP}.txt"
    local sarif_file="${OUTPUT_DIR}/yamllint_${TIMESTAMP}.sarif"
    local -a yaml_files=()
    local yaml_file
    local yamllint_exit=0

    cd "${SCAN_DIR}"

    find_files_with_prune yaml_files -type f \( -name '*.yml' -o -name '*.yaml' \)

    if [ "${#yaml_files[@]}" -eq 0 ]; then
        log_result "yamllint" "SKIPPED" "No YAML files found"
        return
    fi

    run_as_scanner yamllint -f parsable -d "${YAMLLINT_CONFIG_DATA}" "${yaml_files[@]}" 2>&1 | tee "${report_file}" || yamllint_exit=$?
    write_yamllint_json_report "${report_file}" "${output_file}"
    write_yamllint_sarif_report "${output_file}" "${sarif_file}"

    if ! ensure_valid_json_report "${output_file}"; then
        log_result "yamllint" "FAILED" "Execution failed with exit code ${yamllint_exit}"
        return
    fi

    local total
    local errors
    local warnings
    total=$(jq 'length' "${output_file}" 2>/dev/null | tr -d '[:space:]' || echo 0)
    errors=$(jq '[.[] | select(.level == "error")] | length' "${output_file}" 2>/dev/null | tr -d '[:space:]' || echo 0)
    warnings=$(jq '[.[] | select(.level == "warning")] | length' "${output_file}" 2>/dev/null | tr -d '[:space:]' || echo 0)
    total=${total:-0}
    errors=${errors:-0}
    warnings=${warnings:-0}

    if yamllint_severity_fails "$errors" "$warnings"; then
        log_result "yamllint" "FAILED" "Total: ${total}, Errors: ${errors}, Warnings: ${warnings}"
    else
        log_result "yamllint" "PASSED" "Total: ${total}, Errors: ${errors}, Warnings: ${warnings}"
    fi
}

# =============================================================================
# Extract Failure Details
# =============================================================================
extract_gitleaks_details() {
    local output_file="${OUTPUT_DIR}/gitleaks_${TIMESTAMP}.json"
    if [ -f "${output_file}" ] && [ "$(jq 'length' "${output_file}" 2>/dev/null || echo 0)" -gt 0 ]; then
        jq -r '.[] | "- **\(.RuleID)** in `\(.File)`:\(.StartLine) - \(.Description // .Match | .[0:80])"' "${output_file}" 2>/dev/null | head -20
    fi
}

extract_trivy_vuln_details() {
    local output_file="${OUTPUT_DIR}/trivy-vuln_${TIMESTAMP}.json"
    if [ -f "${output_file}" ]; then
        jq -r '
            [.Results[]? | .Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH")] |
            sort_by(.Severity) |
            reverse |
            .[:20][] |
            "- **[\(.Severity)]** \(.VulnerabilityID): \(.PkgName)@\(.InstalledVersion) → \(.FixedVersion // "no fix") - \(.Title // .Description | .[0:60])"
        ' "${output_file}" 2>/dev/null
    fi
}

extract_trivy_config_details() {
    local output_file="${OUTPUT_DIR}/trivy-config_${TIMESTAMP}.json"
    if [ -f "${output_file}" ]; then
        jq -r '
            [.Results[]? | .Misconfigurations[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH")] |
            .[:20][] |
            "- **[\(.Severity)]** \(.ID) in `\(.CauseMetadata.Resource // "config")` - \(.Title)"
        ' "${output_file}" 2>/dev/null
    fi
}

extract_semgrep_details() {
    local output_file="${OUTPUT_DIR}/semgrep_${TIMESTAMP}.json"
    if [ -f "${output_file}" ]; then
        jq -r '
            [.results[] | select(.extra.severity == "ERROR" or .extra.severity == "WARNING")] |
            .[:20][] |
            "- **[\(.extra.severity)]** \(.check_id | split(".")[-1]) in `\(.path)`:\(.start.line) - \(.extra.message | .[0:60])"
        ' "${output_file}" 2>/dev/null
    fi
}

extract_hadolint_details() {
    local output_file="${OUTPUT_DIR}/hadolint_${TIMESTAMP}.json"
    if [ -f "${output_file}" ]; then
        jq -r '
            [.[] | select(.level == "error" or .level == "warning")] |
            .[:20][] |
            "- **[\(.level | ascii_upcase)]** \(.code) at line \(.line) in `\(.file)` - \(.message | .[0:60])"
        ' "${output_file}" 2>/dev/null
    fi
}

extract_shellcheck_details() {
    local output_file="${OUTPUT_DIR}/shellcheck_${TIMESTAMP}.json"
    if [ -f "${output_file}" ]; then
        jq -r '
            [.[] | select(.level == "error" or .level == "warning")] |
            .[:20][] |
            "- **[\(.level | ascii_upcase)]** SC\(.code) in `\(.file)`:\(.line) - \(.message | .[0:80])"
        ' "${output_file}" 2>/dev/null
    fi
}

extract_yamllint_details() {
    local output_file="${OUTPUT_DIR}/yamllint_${TIMESTAMP}.json"
    if [ -f "${output_file}" ]; then
        jq -r '
            [.[] | select(.level == "error" or .level == "warning")] |
            .[:20][] |
            "- **[\(.level | ascii_upcase)]** in `\(.file)`:\(.line):\(.column) - \(.message | .[0:80])"
        ' "${output_file}" 2>/dev/null
    fi
}

# =============================================================================
# Generate Summary Report
# =============================================================================
generate_summary() {
    local summary_file="${OUTPUT_DIR}/summary_${TIMESTAMP}.json"
    local summary_md="${OUTPUT_DIR}/summary_${TIMESTAMP}.md"

    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}📊 Generating Summary Report${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Build failure details JSON
    local failure_details="{}"

    if [ "${SCAN_RESULTS[Gitleaks]}" = "FAILED" ]; then
        local gitleaks_file="${OUTPUT_DIR}/gitleaks_${TIMESTAMP}.json"
        if [ -f "${gitleaks_file}" ]; then
            failure_details=$(echo "${failure_details}" | jq --slurpfile secrets "${gitleaks_file}" '.gitleaks = ($secrets[0] | map({rule: .RuleID, file: .File, line: .StartLine, match: (.Match | .[0:50])}) | .[0:20])')
        fi
    fi

    if [ "${SCAN_RESULTS[Trivy-Vuln]}" = "FAILED" ]; then
        local trivy_file="${OUTPUT_DIR}/trivy-vuln_${TIMESTAMP}.json"
        if [ -f "${trivy_file}" ]; then
            local trivy_details
            trivy_details=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH")] | sort_by(.Severity) | reverse | .[0:20] | map({id: .VulnerabilityID, severity: .Severity, package: .PkgName, installed: .InstalledVersion, fixed: .FixedVersion, title: (.Title // .Description | .[0:80])})' "${trivy_file}" 2>/dev/null)
            failure_details=$(echo "${failure_details}" | jq --argjson vulns "${trivy_details:-[]}" '.trivy_vulnerabilities = $vulns')
        fi
    fi

    if [ "${SCAN_RESULTS[Trivy-Config]}" = "FAILED" ]; then
        local trivy_config_file="${OUTPUT_DIR}/trivy-config_${TIMESTAMP}.json"
        if [ -f "${trivy_config_file}" ]; then
            local config_details
            config_details=$(jq '[.Results[]?.Misconfigurations[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH")] | .[0:20] | map({id: .ID, severity: .Severity, title: .Title, resource: .CauseMetadata.Resource})' "${trivy_config_file}" 2>/dev/null)
            failure_details=$(echo "${failure_details}" | jq --argjson misconfig "${config_details:-[]}" '.trivy_misconfigurations = $misconfig')
        fi
    fi

    if [ "${SCAN_RESULTS[Semgrep]}" = "FAILED" ]; then
        local semgrep_file="${OUTPUT_DIR}/semgrep_${TIMESTAMP}.json"
        if [ -f "${semgrep_file}" ]; then
            local semgrep_details
            semgrep_details=$(jq '[.results[] | select(.extra.severity == "ERROR" or .extra.severity == "WARNING")] | .[0:20] | map({rule: .check_id, severity: .extra.severity, file: .path, line: .start.line, message: (.extra.message | .[0:80])})' "${semgrep_file}" 2>/dev/null)
            failure_details=$(echo "${failure_details}" | jq --argjson sast "${semgrep_details:-[]}" '.semgrep = $sast')
        fi
    fi

    if [ "${SCAN_RESULTS[Hadolint]}" = "FAILED" ]; then
        local hadolint_file="${OUTPUT_DIR}/hadolint_${TIMESTAMP}.json"
        if [ -f "${hadolint_file}" ]; then
            local hadolint_details
            hadolint_details=$(jq '[.[] | select(.level == "error" or .level == "warning")] | .[0:20] | map({code: .code, level: .level, file: .file, line: .line, message: (.message | .[0:80])})' "${hadolint_file}" 2>/dev/null)
            failure_details=$(echo "${failure_details}" | jq --argjson docker "${hadolint_details:-[]}" '.hadolint = $docker')
        fi
    fi

    if [ "${SCAN_RESULTS[ShellCheck]}" = "FAILED" ]; then
        local shellcheck_file="${OUTPUT_DIR}/shellcheck_${TIMESTAMP}.json"
        if [ -f "${shellcheck_file}" ]; then
            local shellcheck_details
            shellcheck_details=$(jq '[.[] | select(.level == "error" or .level == "warning")] | .[0:20] | map({code: .code, level: .level, file: .file, line: .line, message: (.message | .[0:80])})' "${shellcheck_file}" 2>/dev/null)
            failure_details=$(echo "${failure_details}" | jq --argjson shell "${shellcheck_details:-[]}" '.shellcheck = $shell')
        fi
    fi

    if [ "${SCAN_RESULTS[yamllint]}" = "FAILED" ]; then
        local yamllint_file="${OUTPUT_DIR}/yamllint_${TIMESTAMP}.json"
        if [ -f "${yamllint_file}" ]; then
            local yamllint_details
            yamllint_details=$(jq '[.[] | select(.level == "error" or .level == "warning")] | .[0:20] | map({level: .level, file: .file, line: .line, column: .column, message: (.message | .[0:80])})' "${yamllint_file}" 2>/dev/null)
            failure_details=$(echo "${failure_details}" | jq --argjson yaml "${yamllint_details:-[]}" '.yamllint = $yaml')
        fi
    fi

    # JSON Summary
    cat > "${summary_file}" << EOF
{
    "scan_id": "${SCAN_ID}",
    "timestamp": "$(date -Iseconds)",
    "scan_directory": "${SCAN_DIR}",
    "overall_status": "${OVERALL_STATUS}",
    "results": {
EOF

    local first=true
    for scan in "${!SCAN_RESULTS[@]}"; do
        if [ "${first}" = true ]; then
            first=false
        else
            echo "," >> "${summary_file}"
        fi
        echo -n "        \"${scan}\": \"${SCAN_RESULTS[$scan]}\"" >> "${summary_file}"
    done

    # Add failure details to JSON if there are failures
    if [ "${OVERALL_STATUS}" = "FAILED" ]; then
        cat >> "${summary_file}" << EOF

    },
    "failure_details": ${failure_details}
}
EOF
    else
        cat >> "${summary_file}" << EOF

    }
}
EOF
    fi

    # Markdown Summary
    cat > "${summary_md}" << EOF
# Security Scan Report

**Scan ID:** ${SCAN_ID}  
**Timestamp:** $(date)  
**Target Directory:** ${SCAN_DIR}  
**Overall Status:** ${OVERALL_STATUS}

## Scan Results

| Scanner | Status |
|---------|--------|
EOF

    for scan in "${!SCAN_RESULTS[@]}"; do
        local status="${SCAN_RESULTS[$scan]}"
        local icon="⚠️"
        case "${status}" in
            "PASSED") icon="✅" ;;
            "FAILED") icon="❌" ;;
            "SKIPPED") icon="⏭️" ;;
        esac
        echo "| ${scan} | ${icon} ${status} |" >> "${summary_md}"
    done

    # Add failure details section if there are any failures
    if [ "${OVERALL_STATUS}" = "FAILED" ]; then
        cat >> "${summary_md}" << EOF

## ❌ Failure Details

The following issues must be resolved before the scan can pass.

EOF

        # Gitleaks failures
        if [ "${SCAN_RESULTS[Gitleaks]}" = "FAILED" ]; then
            cat >> "${summary_md}" << EOF
### 🔐 Gitleaks - Secrets Detected

EOF
            extract_gitleaks_details >> "${summary_md}"
            echo "" >> "${summary_md}"
        fi

        # Trivy-Vuln failures
        if [ "${SCAN_RESULTS[Trivy-Vuln]}" = "FAILED" ]; then
            cat >> "${summary_md}" << EOF
### 🛡️ Trivy - Vulnerabilities Found

EOF
            extract_trivy_vuln_details >> "${summary_md}"
            echo "" >> "${summary_md}"
        fi

        # Trivy-Config failures
        if [ "${SCAN_RESULTS[Trivy-Config]}" = "FAILED" ]; then
            cat >> "${summary_md}" << EOF
### ⚙️ Trivy - IaC Misconfigurations

EOF
            extract_trivy_config_details >> "${summary_md}"
            echo "" >> "${summary_md}"
        fi

        # Semgrep failures
        if [ "${SCAN_RESULTS[Semgrep]}" = "FAILED" ]; then
            cat >> "${summary_md}" << EOF
### 🔍 Semgrep - SAST Findings

EOF
            extract_semgrep_details >> "${summary_md}"
            echo "" >> "${summary_md}"
        fi

        # Hadolint failures
        if [ "${SCAN_RESULTS[Hadolint]}" = "FAILED" ]; then
            cat >> "${summary_md}" << EOF
### 🐳 Hadolint - Dockerfile Issues

EOF
            extract_hadolint_details >> "${summary_md}"
            echo "" >> "${summary_md}"
        fi

        if [ "${SCAN_RESULTS[ShellCheck]}" = "FAILED" ]; then
            cat >> "${summary_md}" << EOF
### 🐚 ShellCheck - Shell Script Issues

EOF
            extract_shellcheck_details >> "${summary_md}"
            echo "" >> "${summary_md}"
        fi

        if [ "${SCAN_RESULTS[yamllint]}" = "FAILED" ]; then
            cat >> "${summary_md}" << EOF
### 📄 yamllint - YAML Issues

EOF
            extract_yamllint_details >> "${summary_md}"
            echo "" >> "${summary_md}"
        fi

        echo "> **Note:** Only issues that can fail the active policy are listed above (max 20 per scanner). Check individual JSON reports for complete details." >> "${summary_md}"
        echo "" >> "${summary_md}"
    fi

    cat >> "${summary_md}" << EOF

## Output Files

All scan results are available in the output directory:

- \`summary_${TIMESTAMP}.json\` - JSON summary
- \`gitleaks_${TIMESTAMP}.json\` - Gitleaks results
- \`semgrep_${TIMESTAMP}.json\` - Semgrep results
- \`trivy-vuln_${TIMESTAMP}.json\` - Trivy vulnerability results
- \`trivy-config_${TIMESTAMP}.json\` - Trivy IaC results
- \`trivy-license_${TIMESTAMP}.json\` - Trivy license results
- \`shellcheck_${TIMESTAMP}.json\` - ShellCheck results
- \`shellcheck_${TIMESTAMP}.sarif\` - ShellCheck SARIF results
- \`yamllint_${TIMESTAMP}.json\` - yamllint results
- \`yamllint_${TIMESTAMP}.sarif\` - yamllint SARIF results
- \`yamllint_${TIMESTAMP}.txt\` - yamllint parsable output
- \`sbom_${TIMESTAMP}.spdx.json\` - SBOM (SPDX format)
- \`sbom_${TIMESTAMP}.cyclonedx.json\` - SBOM (CycloneDX format)
- \`hadolint_${TIMESTAMP}.json\` - Hadolint results
EOF

    if [ -f "${OUTPUT_DIR}/trivy-image_${TIMESTAMP}.json" ]; then
        cat >> "${summary_md}" << EOF
- \`trivy-image_${TIMESTAMP}.json\` - Optional Trivy image scan results
EOF
    fi

    if [ -f "${OUTPUT_DIR}/trivy-image_${TIMESTAMP}.sarif" ]; then
        cat >> "${summary_md}" << EOF
- \`trivy-image_${TIMESTAMP}.sarif\` - Optional Trivy image scan SARIF results
EOF
    fi

    if [ -f "${OUTPUT_DIR}/trivy-image_${TIMESTAMP}.txt" ]; then
        cat >> "${summary_md}" << EOF
- \`trivy-image_${TIMESTAMP}.txt\` - Optional Trivy image scan text output
EOF
    fi

    cat >> "${summary_md}" << EOF

---
EOF

    echo -e "${GREEN}📄 Summary saved to:${NC}"
    echo "   - ${summary_file}"
    echo "   - ${summary_md}"
}

# =============================================================================
# Print Final Status
# =============================================================================
print_final_status() {
    # Write simple status file for CI/CD integration
    local status_file="${OUTPUT_DIR}/STATUS"
    echo "${OVERALL_STATUS}" > "${status_file}"

    # Write exit code file
    local exitcode_file="${OUTPUT_DIR}/EXIT_CODE"
    if [ "${OVERALL_STATUS}" = "PASSED" ]; then
        echo "0" > "${exitcode_file}"
    else
        echo "1" > "${exitcode_file}"
    fi

    echo -e "\n${BLUE}=============================================${NC}"
    echo -e "${BLUE}  SCAN COMPLETE${NC}"
    echo -e "${BLUE}=============================================${NC}"

    if [ "${OVERALL_STATUS}" = "PASSED" ]; then
        echo -e "${GREEN}✅ Overall Status: PASSED${NC}"
    else
        echo -e "${RED}❌ Overall Status: FAILED${NC}"
    fi

    echo -e "\n${YELLOW}Results Summary:${NC}"
    for scan in "${!SCAN_RESULTS[@]}"; do
        local status="${SCAN_RESULTS[$scan]}"
        local icon="⚠️"
        case "${status}" in
            "PASSED") icon="✅" ;;
            "FAILED") icon="❌" ;;
            "SKIPPED") icon="⏭️" ;;
        esac
        echo -e "  ${icon} ${scan}: ${status}"
    done

    echo -e "\n${YELLOW}Output Directory:${NC} ${OUTPUT_DIR}"
    echo -e "${YELLOW}Status File:${NC} ${status_file} (${OVERALL_STATUS})"
    echo -e "${BLUE}=============================================${NC}\n"

    if [ "${OVERALL_STATUS}" = "FAILED" ]; then
        exit 1
    fi
}

# =============================================================================
# Main Execution
# =============================================================================
case "${1:-all}" in
    all)
        run_gitleaks
        run_semgrep
        run_trivy_vuln
        run_trivy_config
        run_trivy_license
        run_syft
        run_hadolint
        run_shellcheck
        run_yamllint
        generate_summary
        print_final_status
        ;;
    gitleaks)
        run_gitleaks
        print_final_status
        ;;
    semgrep)
        run_semgrep
        print_final_status
        ;;
    trivy)
        run_trivy_vuln
        run_trivy_config
        run_trivy_license
        print_final_status
        ;;
    trivy-vuln)
        run_trivy_vuln
        print_final_status
        ;;
    trivy-config)
        run_trivy_config
        print_final_status
        ;;
    trivy-license)
        run_trivy_license
        print_final_status
        ;;
    trivy-image)
        run_trivy_image
        print_final_status
        ;;
    syft|sbom)
        run_syft
        print_final_status
        ;;
    hadolint)
        run_hadolint
        print_final_status
        ;;
    shellcheck)
        run_shellcheck
        print_final_status
        ;;
    yamllint)
        run_yamllint
        print_final_status
        ;;
    *)
        echo "Usage: $0 {all|gitleaks|semgrep|trivy|trivy-vuln|trivy-config|trivy-license|trivy-image|syft|hadolint|shellcheck|yamllint}"
        echo ""
        echo "Commands:"
        echo "  all           Run all security scans (default)"
        echo "  gitleaks      Run Gitleaks secret detection"
        echo "  semgrep       Run Semgrep SAST analysis"
        echo "  trivy         Run all Trivy scans"
        echo "  trivy-vuln    Run Trivy vulnerability scan"
        echo "  trivy-config  Run Trivy IaC/config scan"
        echo "  trivy-license Run Trivy license scan"
        echo "  trivy-image   Run optional Trivy container image scan (requires IMAGE_REF)"
        echo "  syft          Generate SBOM with Syft"
        echo "  hadolint      Run Hadolint Dockerfile linting"
        echo "  shellcheck    Run ShellCheck shell script analysis"
        echo "  yamllint      Run yamllint YAML validation"
        exit 1
        ;;
esac
