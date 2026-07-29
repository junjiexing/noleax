[CmdletBinding()]
param(
    [string]$ClangFormat = "clang-format"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$clangFormatCommand = Get-Command $ClangFormat -ErrorAction Stop
$sourceFiles = @(
    & git -C $repositoryRoot ls-files --cached --others --exclude-standard -- `
        "*.c" "*.cc" "*.cpp" "*.cxx" "*.h" "*.hh" "*.hpp" "*.hxx"
)

if ($LASTEXITCODE -ne 0) {
    throw "git ls-files failed with exit code $LASTEXITCODE."
}

if ($sourceFiles.Count -eq 0) {
    Write-Host "No C or C++ source files found."
    exit 0
}

$absoluteSourceFiles = @(
    $sourceFiles | ForEach-Object { Join-Path $repositoryRoot $_ }
)

& $clangFormatCommand.Source --dry-run --Werror --style=file @absoluteSourceFiles
if ($LASTEXITCODE -ne 0) {
    throw "clang-format found formatting violations."
}

Write-Host "clang-format checked $($sourceFiles.Count) files."
