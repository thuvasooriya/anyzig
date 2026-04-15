<#
.SYNOPSIS
    Installs anyzig - a universal Zig version manager for Windows.

.DESCRIPTION
    Downloads the latest (or specified) release of anyzig from GitHub and installs
    it to a local bin directory, optionally adding it to the user PATH.
    The installed zig.exe binary intercepts all zig invocations and dispatches to
    the correct Zig version based on build.zig.zon or explicit version arguments.

.PARAMETER Version
    A specific release version to install (e.g. "v0.1.0"). Defaults to latest.

.PARAMETER InstallDir
    Directory to install zig.exe into. Defaults to $HOME\.local\bin or
    the value of the ANYZIG_INSTALL_DIR environment variable.

.PARAMETER NoModifyPath
    Skip adding the install directory to the user PATH.

.PARAMETER Force
    Reinstall even if the same version is already present.

.PARAMETER Help
    Show this help message and exit.

.EXAMPLE
    powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/thuvasooriya/anyzig/main/install.ps1 | iex"

.EXAMPLE
    .\install.ps1 -Version v0.2.0 -InstallDir C:\tools\bin
#>

[CmdletBinding()]
param(
    [string]$Version        = "",
    [string]$InstallDir     = "",
    [switch]$NoModifyPath,
    [switch]$Force,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

$REPO = "thuvasooriya/anyzig"
$GITHUB_API = "https://api.github.com"
$GITHUB_BASE = "https://github.com"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Step { param([string]$msg) Write-Information "  $msg" }
function Write-Done  { param([string]$msg) Write-Information "  [ok] $msg" }
function Abort { param([string]$msg) Write-Error "error: $msg" -ErrorAction Stop }

function Get-Architecture {
    # RuntimeInformation is available on .NET Core / PS 6+ automatically.
    # On PS 5.1 (.NET Framework 4.x) fall back to Environment.Is64BitOperatingSystem.
    try {
        $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        switch ($arch) {
            "X64"   { return "x86_64" }
            "X86"   { return "x86" }
            "Arm64" { return "aarch64" }
            default { Abort "unsupported architecture: $arch" }
        }
    } catch {
        if ([System.Environment]::Is64BitOperatingSystem) { return "x86_64" }
        return "x86"
    }
}

function Get-WebClient {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "anyzig-installer/1.0 PowerShell/$($PSVersionTable.PSVersion)")

    $proxy_env = $env:HTTPS_PROXY
    if (-not $proxy_env) { $proxy_env = $env:ALL_PROXY }
    if ($proxy_env) {
        $proxy = New-Object System.Net.WebProxy($proxy_env, $true)
        $proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        $wc.Proxy = $proxy
    }

    $token = $env:ANYZIG_GITHUB_TOKEN
    if ($token) { $wc.Headers.Add("Authorization", "Bearer $token") }

    return $wc
}

function Resolve-LatestVersion {
    Write-Step "querying GitHub for latest release..."
    $url = "$GITHUB_API/repos/$REPO/releases/latest"
    $wc = Get-WebClient
    try {
        $json = $wc.DownloadString($url)
        $tag  = ($json | ConvertFrom-Json).tag_name
        if (-not $tag) { Abort "could not parse latest release tag from GitHub API" }
        return $tag
    } catch {
        Abort "failed to query GitHub API: $_"
    } finally {
        $wc.Dispose()
    }
}

function Broadcast-PathChange {
    # Notify running processes that the environment changed
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
        uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
}
"@ -ErrorAction SilentlyContinue
        $result = [UIntPtr]::Zero
        [Win32]::SendMessageTimeout(
            [IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, "Environment",
            0x0002, 5000, [ref]$result) | Out-Null
    } catch { <# non-fatal #> }
}

function Add-ToUserPath {
    param([string]$dir)

    $current = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $parts   = $current -split ";" | Where-Object { $_ -ne "" }

    if ($parts -contains $dir) {
        Write-Step "install dir already in user PATH"
        return
    }

    $new = ($parts + $dir) -join ";"
    [System.Environment]::SetEnvironmentVariable("Path", $new, "User")
    Broadcast-PathChange
    Write-Done "added $dir to user PATH"
    Write-Information ""
    Write-Information "  To use anyzig in this terminal session run:"
    Write-Information "    `$env:PATH = `"$dir;`$env:PATH`""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Definition -Full
    exit 0
}

# PowerShell version gate
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Abort "PowerShell 5 or later is required (found $($PSVersionTable.PSVersion))"
}

# TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = `
    [System.Net.ServicePointManager]::SecurityProtocol -bor `
    [System.Net.SecurityProtocolType]::Tls12

# Execution policy advisory (non-fatal - script may be piped/invoked via ByPass)
$policy = Get-ExecutionPolicy -Scope CurrentUser
if ($policy -eq "Restricted") {
    Write-Warning "ExecutionPolicy is Restricted. If you encounter issues run:`n  Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"
}

Write-Information ""
Write-Information "anyzig installer"
Write-Information "----------------"

# Resolve version
$tag = $env:ANYZIG_VERSION
if (-not $tag -and $Version) { $tag = $Version }
if (-not $tag) { $tag = Resolve-LatestVersion }
# Normalise: ensure tag starts with "v"
if (-not $tag.StartsWith("v")) { $tag = "v$tag" }
Write-Done "version: $tag"

# Resolve architecture
$arch = Get-Architecture
Write-Done "architecture: $arch"

# Resolve install directory
if (-not $InstallDir -and $env:ANYZIG_INSTALL_DIR) { $InstallDir = $env:ANYZIG_INSTALL_DIR }
if (-not $InstallDir) { $InstallDir = Join-Path $HOME ".local\bin" }
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
Write-Done "install dir: $InstallDir"

# Check for existing install
$target_exe = Join-Path $InstallDir "zig.exe"
if ((Test-Path $target_exe) -and -not $Force) {
    $existing = & "$target_exe" any version 2>$null
    if ($existing -and $existing -match [regex]::Escape($tag.TrimStart("v"))) {
        Write-Information ""
        Write-Information "  anyzig $tag is already installed. Use -Force to reinstall."
        exit 0
    }
}

# Build download URL
$asset = "anyzig-$arch-windows.zip"
$url   = "$GITHUB_BASE/$REPO/releases/download/$tag/$asset"
Write-Step "download URL: $url"

# Create temp directory
$tmp = Join-Path $env:TEMP "anyzig-install-$(Get-Random)"
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    # Download
    $zip_path = Join-Path $tmp $asset
    Write-Step "downloading $asset..."
    $wc = Get-WebClient
    try {
        $wc.DownloadFile($url, $zip_path)
    } catch {
        Abort "download failed: $_`n  URL: $url"
    } finally {
        $wc.Dispose()
    }
    Write-Done "downloaded"

    # Extract
    $extract_dir = Join-Path $tmp "extracted"
    Write-Step "extracting archive..."
    Expand-Archive -Path $zip_path -DestinationPath $extract_dir -Force
    Write-Done "extracted"

    # Locate zig.exe in extracted archive (may be in a subdirectory)
    $src_exe = Get-ChildItem -Path $extract_dir -Filter "zig.exe" -Recurse | Select-Object -First 1
    if (-not $src_exe) { Abort "zig.exe not found in archive" }
    $src_dir = $src_exe.DirectoryName

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Write-Done "created $InstallDir"
    }

    # Backup existing files
    foreach ($name in @("zig.exe", "zig.pdb")) {
        $dest = Join-Path $InstallDir $name
        if (Test-Path $dest) {
            $backup = "$dest.bak"
            Copy-Item $dest $backup -Force
            Write-Step "backed up existing $name to $name.bak"
        }
    }

    # Copy files
    Copy-Item (Join-Path $src_dir "zig.exe") $InstallDir -Force
    Write-Done "installed zig.exe"

    $pdb_src = Join-Path $src_dir "zig.pdb"
    if (Test-Path $pdb_src) {
        Copy-Item $pdb_src $InstallDir -Force
        Write-Done "installed zig.pdb"
    }

    # PATH management
    if (-not $NoModifyPath) {
        Add-ToUserPath $InstallDir
    }

    # Verify
    Write-Step "verifying installation..."
    $exe = Join-Path $InstallDir "zig.exe"
    try {
        $ver_out = & "$exe" any version 2>&1
        Write-Done "verified: $ver_out"
    } catch {
        Write-Warning "installed but could not verify: $_"
    }

} finally {
    # Cleanup temp dir
    if (Test-Path $tmp) {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

Write-Information ""
Write-Information "  anyzig $tag installed successfully."
Write-Information "  Run 'zig any help' to get started."
Write-Information ""
