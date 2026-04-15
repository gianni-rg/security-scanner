# Copyright (c) 2026 Gianni Rosa Gallina.
# This script is licensed under the APACHE-2.0 License. See LICENSE file in the project root for full license information.
# It is part of Security Scanner project. See https://github.com/gianni-rg/security-scanner for more details.

param(
    [string]$ScanPath = '.',
    [string]$OutputPath,
    [string]$ConfigPath,
    [ValidateSet('all', 'gitleaks', 'semgrep', 'trivy', 'trivy-vuln', 'trivy-config', 'trivy-license', 'syft', 'hadolint', 'shellcheck', 'yamllint', 'trivy-image')]
    [string]$Command = 'all',
    [ValidateSet('auto', 'podman', 'docker')]
    [string]$Runtime = 'auto',
    [string]$Image = 'localhost/security-scanner:latest',
    [string]$ImageRef,
    [string]$SkipDirs,
    [string]$FailOnSeverity,
    [string]$TrivyTimeout,
    [switch]$AllowRootFallback,
    [switch]$Pull,
    [string]$VolumeName = 'security-scanner-trivy-cache',
    [switch]$AllowLocalhostImageFromDaemon,
    [switch]$ShowResolvedCommand,
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-Usage {
    $scriptName = Split-Path -Leaf $PSCommandPath
    @"
NAME
  $scriptName

SYNOPSIS
  Run the hardened security-scanner container against a source directory or container image.

USAGE
    ./$scriptName [-ScanPath <path>] [-OutputPath <path>] [-ConfigPath <file>] [-Command <name>] [-Runtime auto|podman|docker]
                [-Image <ref>] [-ImageRef <ref>] [-SkipDirs <csv>] [-FailOnSeverity <csv>]
                [-TrivyTimeout <duration>] [-AllowRootFallback] [-Pull] [-VolumeName <name>]
                [-AllowLocalhostImageFromDaemon]
                [-ShowResolvedCommand] [-Help]

    Optional registry auth for private images:
        Set TRIVY_REGISTRY_USERNAME and TRIVY_REGISTRY_PASSWORD in your shell before running trivy-image.

COMMANDS
  all, gitleaks, semgrep, trivy, trivy-vuln, trivy-config, trivy-license,
  syft, hadolint, shellcheck, yamllint, trivy-image

EXAMPLES
  ./$scriptName -ScanPath . -Command all
  ./$scriptName -ScanPath . -Command semgrep
  ./$scriptName -ScanPath D:/src/app -OutputPath D:/scan-results/app
    ./$scriptName -ScanPath D:/src/app -ConfigPath D:/configs/security-scanner.yml
  ./$scriptName -Command trivy-image -ImageRef ghcr.io/org/app:tag

NOTES
  The source directory is mounted read-only.
  Reports are written outside the scanned tree by default.
  Root fallback is disabled unless explicitly enabled.
    Localhost image scanning from the host daemon is disabled by default and requires -AllowLocalhostImageFromDaemon.
"@
}

function Resolve-PathStrict {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$AllowMissing
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Path cannot be empty.'
    }

    if (Test-Path -LiteralPath $Path) {
        return [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path)
    }

    if (-not $AllowMissing) {
        throw "Path does not exist: $Path"
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path -Path (Get-Location) -ChildPath $Path))
}

function Get-DefaultOutputPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResolvedScanPath
    )

    $parent = Split-Path -Path $ResolvedScanPath -Parent
    $leaf = Split-Path -Path $ResolvedScanPath -Leaf

    if ([string]::IsNullOrWhiteSpace($parent)) {
        $parent = (Get-Location).Path
    }

    if ([string]::IsNullOrWhiteSpace($leaf)) {
        $leaf = 'scan-target'
    }

    return [System.IO.Path]::GetFullPath((Join-Path -Path $parent -ChildPath ("{0}-security-scan-output" -f $leaf)))
}

function Test-IsSubPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ParentPath,
        [Parameter(Mandatory = $true)]
        [string]$ChildPath
    )

    $parent = [System.IO.Path]::GetFullPath($ParentPath).TrimEnd('\', '/')
    $child = [System.IO.Path]::GetFullPath($ChildPath).TrimEnd('\', '/')

    if ($child.Equals($parent, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    $separator = [System.IO.Path]::DirectorySeparatorChar
    return ($child + $separator).StartsWith($parent + $separator, [System.StringComparison]::OrdinalIgnoreCase)
}

function Resolve-RuntimeName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RequestedRuntime
    )

    if ($RequestedRuntime -ne 'auto') {
        if (-not (Get-Command -Name $RequestedRuntime -ErrorAction SilentlyContinue)) {
            throw "Container runtime not found: $RequestedRuntime"
        }
        return $RequestedRuntime
    }

    foreach ($candidate in @('podman', 'docker')) {
        if (Get-Command -Name $candidate -ErrorAction SilentlyContinue) {
            return $candidate
        }
    }

    throw 'Neither podman nor docker was found in PATH.'
}

function Ensure-Volume {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuntimeName,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    & $RuntimeName volume inspect $Name *> $null
    if ($LASTEXITCODE -ne 0) {
        & $RuntimeName volume create $Name | Out-Null
    }
}

function Convert-ToMountPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return ([System.IO.Path]::GetFullPath($Path) -replace '\\', '/')
}

function Format-ResolvedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    return ($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"{0}"' -f ($_ -replace '"', '\"')
        }
        else {
            $_
        }
    }) -join ' '
}

if ($Help) {
    Show-Usage
    exit 0
}

$resolvedScanPath = Resolve-PathStrict -Path $ScanPath
if (-not (Test-Path -LiteralPath $resolvedScanPath -PathType Container)) {
    throw "ScanPath must be an existing directory: $resolvedScanPath"
}

$resolvedOutputPath = if ($PSBoundParameters.ContainsKey('OutputPath')) {
    Resolve-PathStrict -Path $OutputPath -AllowMissing
}
else {
    Get-DefaultOutputPath -ResolvedScanPath $resolvedScanPath
}

$resolvedConfigPath = $null
if ($PSBoundParameters.ContainsKey('ConfigPath')) {
    $resolvedConfigPath = Resolve-PathStrict -Path $ConfigPath -AllowMissing
    if (-not (Test-Path -LiteralPath $resolvedConfigPath -PathType Leaf)) {
        throw "ConfigPath must be an existing file: $ConfigPath"
    }
}

if ($Command -ne 'trivy-image' -and (Test-IsSubPath -ParentPath $resolvedScanPath -ChildPath $resolvedOutputPath)) {
    throw "OutputPath must be outside ScanPath to avoid re-scanning generated reports: $resolvedOutputPath"
}

if ($Command -eq 'trivy-image' -and [string]::IsNullOrWhiteSpace($ImageRef)) {
    throw 'ImageRef is required when Command is trivy-image.'
}

$isLocalhostImageRef = ($Command -eq 'trivy-image' -and -not [string]::IsNullOrWhiteSpace($ImageRef) -and $ImageRef -match '^(?i)localhost/')
if ($isLocalhostImageRef -and -not $AllowLocalhostImageFromDaemon) {
    throw 'ImageRef uses localhost/. To scan host-daemon localhost images, explicitly set -AllowLocalhostImageFromDaemon.'
}

if ($AllowLocalhostImageFromDaemon -and -not $isLocalhostImageRef) {
    throw '-AllowLocalhostImageFromDaemon is only valid when Command is trivy-image and ImageRef starts with localhost/.'
}

if ($PSBoundParameters.ContainsKey('ShowResolvedCommand') -and -not [string]::IsNullOrWhiteSpace($env:TRIVY_REGISTRY_PASSWORD)) {
    Write-Warning 'ShowResolvedCommand may expose TRIVY_REGISTRY_PASSWORD in terminal output.'
}

if ([string]::IsNullOrWhiteSpace($env:TRIVY_REGISTRY_USERNAME) -xor [string]::IsNullOrWhiteSpace($env:TRIVY_REGISTRY_PASSWORD)) {
    throw 'Set both TRIVY_REGISTRY_USERNAME and TRIVY_REGISTRY_PASSWORD (or neither).'
}

New-Item -ItemType Directory -Path $resolvedOutputPath -Force | Out-Null

$resolvedRuntime = Resolve-RuntimeName -RequestedRuntime $Runtime
if ($Pull) {
    & $resolvedRuntime pull $Image
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to pull image: $Image"
    }
}

Ensure-Volume -RuntimeName $resolvedRuntime -Name $VolumeName

$scanMount = "type=bind,src=$(Convert-ToMountPath -Path $resolvedScanPath),dst=/workspace,readonly"
$outputMount = "type=bind,src=$(Convert-ToMountPath -Path $resolvedOutputPath),dst=/output"
$cacheMount = "type=volume,src=$VolumeName,dst=/var/lib/trivy"
$configMount = $null
$allowRootFallbackValue = if ($AllowRootFallback) { 'true' } else { 'false' }
$localImageMount = $null
$localImageArchiveHostPath = $null

$runArguments = @(
    'run',
    '--rm',
    '--init',
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt', 'no-new-privileges:true',
    '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=1g,mode=1777',
    '--tmpfs', '/run:rw,noexec,nosuid,nodev,size=16m,mode=755',
    '--mount', $outputMount,
    '--mount', $cacheMount,
    '--env', 'OUTPUT_DIR=/output',
    '--env', "ALLOW_ROOT_FALLBACK=$allowRootFallbackValue"
)

if ($null -ne $resolvedConfigPath) {
    $configMount = "type=bind,src=$(Convert-ToMountPath -Path $resolvedConfigPath),dst=/run/scanner/config.yml,readonly"
    $runArguments += @('--mount', $configMount, '--env', 'CONFIG_FILE=/run/scanner/config.yml')
}
else {
    $runArguments += @('--env', 'CONFIG_FILE=/app/config.yml')
}

if ($isLocalhostImageRef) {
    $localImageArchiveHostPath = Join-Path -Path $resolvedOutputPath -ChildPath 'localhost-image-input.tar'
    if (Test-Path -LiteralPath $localImageArchiveHostPath) {
        Remove-Item -LiteralPath $localImageArchiveHostPath -Force
    }

    if ($resolvedRuntime -like 'podman*') {
        & $resolvedRuntime image save --format docker-archive --output $localImageArchiveHostPath $ImageRef
    }
    else {
        & $resolvedRuntime image save --output $localImageArchiveHostPath $ImageRef
    }

    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $localImageArchiveHostPath -PathType Leaf)) {
        throw "Failed to export localhost image from daemon: $ImageRef"
    }

    $localImageMount = "type=bind,src=$(Convert-ToMountPath -Path $localImageArchiveHostPath),dst=/run/scanner/localhost-image-input.tar,readonly"
    $runArguments += @('--mount', $localImageMount, '--env', 'IMAGE_INPUT=/run/scanner/localhost-image-input.tar')
}

if ($AllowRootFallback) {
    $runArguments += @('--user', '0:0')
}

if ($Command -ne 'trivy-image') {
    $runArguments += @('--mount', $scanMount, '--env', 'SCAN_DIR=/workspace')
}

if (-not [string]::IsNullOrWhiteSpace($SkipDirs)) {
    $runArguments += @('--env', "SKIP_DIRS=$SkipDirs")
}

if (-not [string]::IsNullOrWhiteSpace($FailOnSeverity)) {
    $runArguments += @('--env', "FAIL_ON_SEVERITY=$FailOnSeverity")
}

if (-not [string]::IsNullOrWhiteSpace($TrivyTimeout)) {
    $runArguments += @('--env', "TRIVY_TIMEOUT=$TrivyTimeout")
}

if (-not [string]::IsNullOrWhiteSpace($ImageRef)) {
    $runArguments += @('--env', "IMAGE_REF=$ImageRef")
}

if (-not [string]::IsNullOrWhiteSpace($env:TRIVY_REGISTRY_USERNAME)) {
    $runArguments += @('--env', "TRIVY_REGISTRY_USERNAME=$($env:TRIVY_REGISTRY_USERNAME)")
}

if (-not [string]::IsNullOrWhiteSpace($env:TRIVY_REGISTRY_PASSWORD)) {
    $runArguments += @('--env', "TRIVY_REGISTRY_PASSWORD=$($env:TRIVY_REGISTRY_PASSWORD)")
}

$runArguments += @($Image, $Command)

Write-Host 'Execution plan'
Write-Host ("  Runtime: {0}" -f $resolvedRuntime)
Write-Host ("  Image: {0}" -f $Image)
Write-Host ("  Command: {0}" -f $Command)
if ($Command -eq 'trivy-image') {
    Write-Host ("  ImageRef: {0}" -f $ImageRef)
    Write-Host '  ScanPath: not used'
}
else {
    Write-Host ("  ScanPath: {0}" -f $resolvedScanPath)
}
Write-Host ("  OutputPath: {0}" -f $resolvedOutputPath)
Write-Host ("  ConfigPath: {0}" -f $(if ($null -ne $resolvedConfigPath) { $resolvedConfigPath } else { '/app/config.yml (image default)' }))
Write-Host ("  CacheVolume: {0}" -f $VolumeName)
Write-Host ("  AllowRootFallback: {0}" -f $allowRootFallbackValue)
Write-Host ("  AllowLocalhostImageFromDaemon: {0}" -f $(if ($AllowLocalhostImageFromDaemon) { 'true' } else { 'false' }))
if ($isLocalhostImageRef) {
    Write-Host ("  LocalhostImageArchive: {0}" -f $localImageArchiveHostPath)
}

if ($ShowResolvedCommand) {
    Write-Host 'Resolved command'
    $resolvedCommand = @($resolvedRuntime) + $runArguments
    Write-Host (Format-ResolvedCommand -Arguments $resolvedCommand)
}

& $resolvedRuntime @runArguments
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    exit $exitCode
}