[CmdletBinding()]
param(
    [string]$Preset = "windows-x64-release",
    [ValidateRange(1, 1000)]
    [int]$Repetitions = 10,
    [ValidateRange(30, 3600)]
    [int]$PerTestTimeoutSeconds = 300,
    [string]$ReportPath,
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$developerShell = Join-Path $PSScriptRoot "Enter-NoleaxDevShell.ps1"
. $developerShell

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(ValueFromRemainingArguments)]
        [string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE."
    }
}

function Get-GitText {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $output = @(& git -C $repositoryRoot @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed: $($output -join [Environment]::NewLine)"
    }
    return ($output -join [Environment]::NewLine).Trim()
}

if (-not $IsWindows) {
    throw "The V1 soak suite currently requires Windows x64."
}

$startedAt = [DateTimeOffset]::UtcNow
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $timestamp = $startedAt.ToString("yyyyMMdd-HHmmss")
    $ReportPath = Join-Path $repositoryRoot "_temp\reports\noleax-soak-$timestamp.json"
}
$ReportPath = [IO.Path]::GetFullPath($ReportPath)
$reportDirectory = Split-Path -Parent $ReportPath
if (-not [string]::IsNullOrEmpty($reportDirectory)) {
    $null = New-Item -ItemType Directory -Force -Path $reportDirectory
}

$testCases = @(
    [pscustomobject]@{ Name = "controller.suspended-launch-ready"; Capability = "run" },
    [pscustomobject]@{ Name = "controller.runtime-attach"; Capability = "attach" },
    [pscustomobject]@{ Name = "controller.capture-lifecycle"; Capability = "conservation" },
    [pscustomobject]@{ Name = "hook.windows-native-profile"; Capability = "native-profile" },
    [pscustomobject]@{ Name = "cli.end-to-end-trace-analyze"; Capability = "run-attach-analyze" }
)

$results = [Collections.Generic.List[object]]::new()
$failure = $null
$buildDirectory = Join-Path $repositoryRoot "build\$Preset"

Push-Location $repositoryRoot
try {
    if (-not $SkipBuild) {
        Invoke-CheckedCommand cmake --preset $Preset
        Invoke-CheckedCommand cmake --build --preset $Preset
    }
    if (-not (Test-Path -LiteralPath (Join-Path $buildDirectory "CTestTestfile.cmake"))) {
        throw "CTest metadata is missing from $buildDirectory. Build the preset first."
    }

    :soak for ($repetition = 1; $repetition -le $Repetitions; ++$repetition) {
        foreach ($testCase in $testCases) {
            $stopwatch = [Diagnostics.Stopwatch]::StartNew()
            $output = @(& ctest --test-dir $buildDirectory --output-on-failure `
                    --timeout $PerTestTimeoutSeconds -R "^$([regex]::Escape($testCase.Name))$" 2>&1)
            $exitCode = $LASTEXITCODE
            $stopwatch.Stop()
            $passed = $exitCode -eq 0 -and ($output -join "`n") -match "100% tests passed"
            $result = [pscustomobject]@{
                repetition = $repetition
                test = $testCase.Name
                capability = $testCase.Capability
                passed = $passed
                exitCode = $exitCode
                elapsedMilliseconds = $stopwatch.ElapsedMilliseconds
                output = $output -join [Environment]::NewLine
            }
            $results.Add($result)
            if (-not $passed) {
                $failure = "Soak test '$($testCase.Name)' failed on repetition $repetition."
                break soak
            }
            Write-Host ("soak {0}/{1}: {2} passed in {3:N0} ms" -f `
                    $repetition, $Repetitions, $testCase.Name, $stopwatch.ElapsedMilliseconds)
        }
    }
}
catch {
    $failure = $_.Exception.Message
}
finally {
    Pop-Location
}

$finishedAt = [DateTimeOffset]::UtcNow
$dirty = -not [string]::IsNullOrWhiteSpace((Get-GitText @("status", "--porcelain")))
$passedCount = @($results | Where-Object { $_.passed }).Count
$report = [ordered]@{
    schemaVersion = 1
    kind = "noleax-windows-x64-soak"
    status = if ($null -eq $failure) { "passed" } else { "failed" }
    preset = $Preset
    repetitionsRequested = $Repetitions
    testCasesPerRepetition = $testCases.Count
    checksPassed = $passedCount
    checksExpected = $Repetitions * $testCases.Count
    startedAtUtc = $startedAt.ToString("O")
    finishedAtUtc = $finishedAt.ToString("O")
    elapsedSeconds = [Math]::Round(($finishedAt - $startedAt).TotalSeconds, 3)
    git = [ordered]@{
        commit = Get-GitText @("rev-parse", "HEAD")
        dirty = $dirty
    }
    host = [ordered]@{
        os = [Environment]::OSVersion.VersionString
        architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        processorCount = [Environment]::ProcessorCount
        powershell = $PSVersionTable.PSVersion.ToString()
    }
    failure = $failure
    results = $results
}

$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding utf8
Write-Host "soak report: $ReportPath"
Write-Host ("status={0} checks={1}/{2} elapsed={3:N3}s" -f `
        $report.status, $report.checksPassed, $report.checksExpected, $report.elapsedSeconds)

if ($null -ne $failure) {
    throw $failure
}
