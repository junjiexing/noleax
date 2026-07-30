[CmdletBinding()]
param(
    [string]$VisualStudioPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$requestedVcpkgRoot = $env:VCPKG_ROOT
if ([string]::IsNullOrWhiteSpace($requestedVcpkgRoot)) {
    $repositoryRoot = Split-Path -Parent $PSScriptRoot
    $localVcpkg = Join-Path $repositoryRoot "_temp\vcpkg"
    if (-not (Test-Path -LiteralPath (Join-Path $localVcpkg "vcpkg.exe"))) {
        throw "VCPKG_ROOT is not set and _temp\vcpkg\vcpkg.exe was not found."
    }
    $requestedVcpkgRoot = (Resolve-Path -LiteralPath $localVcpkg).Path
}

if ([string]::IsNullOrWhiteSpace($VisualStudioPath)) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw "vswhere.exe was not found."
    }

    $VisualStudioPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
}

if ([string]::IsNullOrWhiteSpace($VisualStudioPath)) {
    throw "Visual Studio with the x64 C++ toolchain was not found."
}

$toolsetRoot = Join-Path $VisualStudioPath "VC\Tools\MSVC"
$toolset = Get-ChildItem -LiteralPath $toolsetRoot -Directory |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1

if ($null -eq $toolset) {
    throw "No MSVC toolset was found under $toolsetRoot."
}

$devShellModule = Join-Path $VisualStudioPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
$shellSignature = "$VisualStudioPath|$($toolset.Name)|x64|x64"
if ($env:NOLEAX_DEV_SHELL_SIGNATURE -ne $shellSignature) {
    Import-Module $devShellModule
    Enter-VsDevShell -VsInstallPath $VisualStudioPath -SkipAutomaticLocation `
        -DevCmdArguments "-arch=x64 -host_arch=x64 -vcvars_ver=$($toolset.Name)"
    $env:NOLEAX_DEV_SHELL_SIGNATURE = $shellSignature
}
$env:VCPKG_ROOT = $requestedVcpkgRoot

Write-Host "Noleax developer environment:"
Write-Host "  Visual Studio: $VisualStudioPath"
Write-Host "  MSVC toolset:  $($toolset.Name)"
Write-Host "  VCPKG_ROOT:    $env:VCPKG_ROOT"
