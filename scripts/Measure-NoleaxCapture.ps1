[CmdletBinding()]
param(
    [string]$Preset = "windows-x64-release",
    [ValidateRange(1, 20)]
    [int]$Repetitions = 3,
    [ValidateRange(0, 5)]
    [int]$WarmupRepetitions = 1,
    [ValidateRange(1, 64)]
    [int]$Threads = 2,
    [ValidateRange(100, 10000000)]
    [int]$IterationsPerThread = 3000,
    [ValidateRange(2, 60)]
    [int]$CaptureDurationSeconds = 5,
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
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments)][string[]]$ArgumentList
    )

    $output = @(& $FilePath @ArgumentList 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code ${LASTEXITCODE}: $($output -join [Environment]::NewLine)"
    }
    return $output
}

function Invoke-AcceptedCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][int[]]$AllowedExitCodes,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )

    $output = @(& $FilePath @ArgumentList 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -notin $AllowedExitCodes) {
        throw "$FilePath failed with exit code ${exitCode}: $($output -join [Environment]::NewLine)"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = $output }
}

function Get-GitText {
    param([Parameter(Mandatory)][string[]]$Arguments)

    return (@(Invoke-CheckedCommand git -C $repositoryRoot @Arguments) -join `
            [Environment]::NewLine).Trim()
}

function Get-Median {
    param([Parameter(Mandatory)][double[]]$Values)

    $sorted = @($Values | Sort-Object)
    $middle = [Math]::Floor($sorted.Count / 2)
    if (($sorted.Count % 2) -eq 1) {
        return $sorted[$middle]
    }
    return ($sorted[$middle - 1] + $sorted[$middle]) / 2.0
}

function Read-WorkloadReport {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][bool]$Captured
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Benchmark workload did not create $Path."
    }
    $report = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($report.schemaVersion -ne 1 -or $report.status -ne "ok" -or
        $report.captured -ne $Captured -or ($Captured -and -not $report.captureAliveAtEnd)) {
        throw "Benchmark workload report is invalid: $Path"
    }
    return $report
}

if (-not $IsWindows) {
    throw "The V1 capture benchmark currently requires Windows x64."
}

$startedAt = [DateTimeOffset]::UtcNow
$timestamp = $startedAt.ToString("yyyyMMdd-HHmmss")
$runDirectory = Join-Path $repositoryRoot "_temp\benchmarks\capture-$timestamp"
$null = New-Item -ItemType Directory -Force -Path $runDirectory
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $repositoryRoot "_temp\reports\noleax-capture-$timestamp.json"
}
$ReportPath = [IO.Path]::GetFullPath($ReportPath)
$null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ReportPath)

$buildDirectory = Join-Path $repositoryRoot "build\$Preset"
$binaryDirectory = Join-Path $buildDirectory "bin"
$noleax = Join-Path $binaryDirectory "noleax.exe"
$agent = Join-Path $binaryDirectory "noleax-agent.dll"
$target = Join-Path $binaryDirectory "noleax-capture-benchmark-target.exe"
$cases = @(
    [pscustomobject]@{ Name = "default"; Arguments = @(); Depth = 64; Compression = "lz4" },
    [pscustomobject]@{ Name = "stack-16"; Arguments = @("--max-stack-depth", "16"); Depth = 16; Compression = "lz4" },
    [pscustomobject]@{ Name = "stack-32"; Arguments = @("--max-stack-depth", "32"); Depth = 32; Compression = "lz4" },
    [pscustomobject]@{ Name = "compression-none"; Arguments = @("--compression", "none"); Depth = 64; Compression = "none" },
    [pscustomobject]@{ Name = "compression-zstd1"; Arguments = @("--compression", "zstd", "--compression-level", "1"); Depth = 64; Compression = "zstd-1" }
)

Push-Location $repositoryRoot
try {
    if (-not $SkipBuild) {
        $null = Invoke-CheckedCommand cmake --preset $Preset
        $null = Invoke-CheckedCommand cmake --build --preset $Preset
    }
    foreach ($path in @($noleax, $agent, $target)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Required benchmark artifact is missing: $path"
        }
    }

    $baselineRuns = [Collections.Generic.List[object]]::new()
    $baselineTotal = $WarmupRepetitions + $Repetitions
    for ($index = 1; $index -le $baselineTotal; ++$index) {
        $workloadPath = Join-Path $runDirectory "baseline-$index.json"
        $null = Invoke-CheckedCommand $target $workloadPath $Threads $IterationsPerThread baseline
        $workload = Read-WorkloadReport $workloadPath $false
        if ($index -gt $WarmupRepetitions) {
            $baselineRuns.Add($workload)
        }
    }
    $baselineMedian = Get-Median @($baselineRuns | ForEach-Object { [double]$_.elapsedNanoseconds })
    $expectedChecksum = $baselineRuns[0].checksum
    $expectedOperations = $baselineRuns[0].operations
    $expectedBytes = $baselineRuns[0].requestedBytes
    foreach ($run in $baselineRuns) {
        if ($run.checksum -ne $expectedChecksum -or $run.operations -ne $expectedOperations -or
            $run.requestedBytes -ne $expectedBytes) {
            throw "Baseline workload results are not deterministic."
        }
    }

    $caseReports = [Collections.Generic.List[object]]::new()
    foreach ($case in $cases) {
        $runs = [Collections.Generic.List[object]]::new()
        $caseTotal = $WarmupRepetitions + $Repetitions
        for ($index = 1; $index -le $caseTotal; ++$index) {
            $prefix = "$($case.Name)-$index"
            $workloadPath = Join-Path $runDirectory "$prefix-workload.json"
            $tracePath = Join-Path $runDirectory "$prefix.nlx"
            $analysisPath = Join-Path $runDirectory "$prefix-analysis.json"
            $captureArguments = @("run", "--agent", $agent, "--trace", $tracePath,
                "--capture-duration", "$($CaptureDurationSeconds)s") + $case.Arguments +
                @("--", $target, $workloadPath, "$Threads", "$IterationsPerThread", "captured")
            $captureResult = Invoke-AcceptedCommand -FilePath $noleax `
                -AllowedExitCodes @(0, 2) -ArgumentList $captureArguments
            $workload = Read-WorkloadReport $workloadPath $true
            if ($workload.checksum -ne $expectedChecksum -or
                $workload.operations -ne $expectedOperations -or
                $workload.requestedBytes -ne $expectedBytes) {
                throw "Captured workload changed observable behavior for case '$($case.Name)'."
            }

            $analysisArguments = @("analyze", "--mode", "events", "--format", "json",
                "--output", $analysisPath, "--min-size", "1GiB", $tracePath)
            $analysisResult = Invoke-AcceptedCommand -FilePath $noleax `
                -AllowedExitCodes @(0, 2) -ArgumentList $analysisArguments
            $analysis = Get-Content -LiteralPath $analysisPath -Raw | ConvertFrom-Json
            if ($analysis.summary.completeness.lifecycle -ne "complete" -or
                $analysis.summary.completeness.understanding -ne "full" -or
                $analysis.summary.truncated -or
                $analysis.summary.capture_statistics.dropped_events -ne 0 -or
                $analysis.summary.trace_events -lt $expectedOperations) {
                throw "Trace integrity failed for case '$($case.Name)' repetition $index."
            }
            if ($index -gt $WarmupRepetitions) {
                $runs.Add([pscustomobject]@{
                        elapsedNanoseconds = $workload.elapsedNanoseconds
                        traceBytes = (Get-Item -LiteralPath $tracePath).Length
                        traceEvents = $analysis.summary.trace_events
                        uniqueStacks = $analysis.summary.capture_statistics.unique_stacks
                        reusedStacks = $analysis.summary.capture_statistics.reused_stacks
                        captureExitCode = $captureResult.ExitCode
                        analysisExitCode = $analysisResult.ExitCode
                        completeness = $analysis.summary.completeness.overall
                        completenessIssues = @($analysis.summary.completeness.issues)
                    })
            }
        }
        $median = Get-Median @($runs | ForEach-Object { [double]$_.elapsedNanoseconds })
        $medianTraceBytes = Get-Median @($runs | ForEach-Object { [double]$_.traceBytes })
        $caseReports.Add([ordered]@{
                name = $case.Name
                maximumStackDepth = $case.Depth
                compression = $case.Compression
                medianElapsedNanoseconds = [uint64]$median
                overheadRatio = [Math]::Round($median / $baselineMedian, 3)
                medianTraceBytes = [uint64]$medianTraceBytes
                runs = $runs
            })
        Write-Host ("benchmark {0}: median={1:N3} ms overhead={2:N3}x trace={3:N0} bytes" -f `
                $case.Name, ($median / 1.0e6), ($median / $baselineMedian), $medianTraceBytes)
    }
}
finally {
    Pop-Location
}

$finishedAt = [DateTimeOffset]::UtcNow
$report = [ordered]@{
    schemaVersion = 1
    kind = "noleax-windows-x64-capture-benchmark"
    status = "passed"
    preset = $Preset
    startedAtUtc = $startedAt.ToString("O")
    finishedAtUtc = $finishedAt.ToString("O")
    elapsedSeconds = [Math]::Round(($finishedAt - $startedAt).TotalSeconds, 3)
    git = [ordered]@{
        commit = Get-GitText @("rev-parse", "HEAD")
        dirty = -not [string]::IsNullOrWhiteSpace((Get-GitText @("status", "--porcelain")))
    }
    host = [ordered]@{
        os = [Environment]::OSVersion.VersionString
        architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        processorCount = [Environment]::ProcessorCount
    }
    workload = [ordered]@{
        threads = $Threads
        iterationsPerThread = $IterationsPerThread
        operations = $expectedOperations
        requestedBytes = $expectedBytes
        checksum = $expectedChecksum
        repetitions = $Repetitions
        warmupRepetitions = $WarmupRepetitions
        captureDurationSeconds = $CaptureDurationSeconds
    }
    baseline = [ordered]@{
        medianElapsedNanoseconds = [uint64]$baselineMedian
        runs = $baselineRuns
    }
    cases = $caseReports
}
$report | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $ReportPath -Encoding utf8
Write-Host "benchmark report: $ReportPath"
