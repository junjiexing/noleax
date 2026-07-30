[CmdletBinding()]
param(
    [string]$Preset = "windows-x64-release",
    [ValidateRange(1, 1000)]
    [int]$MutationCount = 128,
    [ValidateRange(100, 60000)]
    [int]$TimeoutMilliseconds = 5000,
    [string]$NoleaxPath,
    [string]$RecoveryToolPath,
    [string]$ReportPath,
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$startedAt = [DateTimeOffset]::UtcNow
$timestamp = $startedAt.ToString("yyyyMMdd-HHmmss")
$workDirectory = Join-Path $repositoryRoot "_temp\security-corpus\$timestamp"
$null = New-Item -ItemType Directory -Force -Path $workDirectory

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

function Get-GitText {
    param([Parameter(Mandatory)][string[]]$Arguments)

    return (@(Invoke-CheckedCommand git -C $repositoryRoot @Arguments) -join `
            [Environment]::NewLine).Trim()
}

function Limit-Text {
    param([AllowEmptyString()][string]$Value)

    if ($Value.Length -le 2048) {
        return $Value
    }
    return $Value.Substring(0, 2048) + "..."
}

function Invoke-IsolatedAnalysis {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string]$TracePath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][int]$Timeout
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.WorkingDirectory = $repositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @("analyze", "--mode", "events", "--format", "json", "--output",
            $OutputPath, $TracePath)) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    if (-not $process.Start()) {
        throw "Failed to start isolated analyzer."
    }
    $standardOutput = $process.StandardOutput.ReadToEndAsync()
    $standardError = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($Timeout)
    if ($timedOut) {
        $process.Kill($true)
        $process.WaitForExit()
    }
    $stopwatch.Stop()
    $result = [pscustomobject]@{
        timedOut = $timedOut
        exitCode = if ($timedOut) { $null } else { $process.ExitCode }
        elapsedMilliseconds = $stopwatch.ElapsedMilliseconds
        standardOutput = Limit-Text ($standardOutput.GetAwaiter().GetResult())
        standardError = Limit-Text ($standardError.GetAwaiter().GetResult())
    }
    $process.Dispose()
    return $result
}

if (-not $IsWindows) {
    throw "The V1 untrusted-trace corpus currently requires Windows x64."
}

if (-not $SkipBuild) {
    . (Join-Path $PSScriptRoot "Enter-NoleaxDevShell.ps1")
    $null = Invoke-CheckedCommand cmake --preset $Preset
    $null = Invoke-CheckedCommand cmake --build --preset $Preset --target `
        noleax noleax-cli-recovery-test
}

$binaryDirectory = Join-Path $repositoryRoot "build\$Preset\bin"
if ([string]::IsNullOrWhiteSpace($NoleaxPath)) {
    $NoleaxPath = Join-Path $binaryDirectory "noleax.exe"
}
if ([string]::IsNullOrWhiteSpace($RecoveryToolPath)) {
    $RecoveryToolPath = Join-Path $binaryDirectory "noleax-cli-recovery-test.exe"
}
$NoleaxPath = [IO.Path]::GetFullPath($NoleaxPath)
$RecoveryToolPath = [IO.Path]::GetFullPath($RecoveryToolPath)
foreach ($path in @($NoleaxPath, $RecoveryToolPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required security-test artifact is missing: $path"
    }
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $repositoryRoot "_temp\reports\noleax-untrusted-$timestamp.json"
}
$ReportPath = [IO.Path]::GetFullPath($ReportPath)
$null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ReportPath)

$seedDirectory = Join-Path $workDirectory "seed"
$null = New-Item -ItemType Directory -Force -Path $seedDirectory
$null = Invoke-CheckedCommand $RecoveryToolPath $NoleaxPath $seedDirectory
$seedPath = Join-Path $seedDirectory "seed.nlx"
if (-not (Test-Path -LiteralPath $seedPath -PathType Leaf)) {
    throw "Recovery fixture did not produce the corpus seed."
}
[byte[]]$seed = [IO.File]::ReadAllBytes($seedPath)
if ($seed.Length -lt 69) {
    throw "Corpus seed is unexpectedly small."
}

$cases = [Collections.Generic.List[object]]::new()
function Add-CorpusCase {
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][AllowEmptyCollection()][byte[]]$Data,
        [Parameter(Mandatory)][string]$Strategy
    )

    if ($null -eq $Data) {
        $Data = [byte[]]@()
    }
    $cases.Add([pscustomobject]@{ Name = $Name; Data = $Data; Strategy = $Strategy })
}

$truncationOffsets = @(0, 1, 7, 8, 15, 31, 67, 68, [int]($seed.Length / 2),
    ($seed.Length - 1)) |
    Sort-Object -Unique
foreach ($length in $truncationOffsets) {
    [byte[]]$data = if ($length -eq 0) { @() } else { $seed[0..($length - 1)] }
    Add-CorpusCase -Name "truncate-$length" -Data $data -Strategy "truncation"
}

$headerBytes = [Math]::Min(68, $seed.Length)
for ($index = 0; $index -lt $headerBytes; ++$index) {
    [byte[]]$data = $seed.Clone()
    $data[$index] = $data[$index] -bxor [byte](1 -shl ($index % 8))
    Add-CorpusCase -Name "header-bit-$index" -Data $data -Strategy "header-bit-flip"
}

$random = [Random]::new(0x4e4f4c45)
for ($caseIndex = 0; $caseIndex -lt $MutationCount; ++$caseIndex) {
    [byte[]]$data = $seed.Clone()
    $changes = 1 + $random.Next(4)
    for ($change = 0; $change -lt $changes; ++$change) {
        $offset = $random.Next($data.Length)
        $bit = 1 -shl $random.Next(8)
        $data[$offset] = $data[$offset] -bxor [byte]$bit
    }
    Add-CorpusCase -Name "random-$caseIndex" -Data $data -Strategy "deterministic-random"
}

$results = [Collections.Generic.List[object]]::new()
$unexpected = 0
$timeouts = 0
$maximumElapsed = 0L
foreach ($case in $cases) {
    $tracePath = Join-Path $workDirectory "$($case.Name).nlx"
    $outputPath = Join-Path $workDirectory "$($case.Name).json"
    [IO.File]::WriteAllBytes($tracePath, $case.Data)
    $execution = Invoke-IsolatedAnalysis -Executable $NoleaxPath -TracePath $tracePath `
        -OutputPath $outputPath -Timeout $TimeoutMilliseconds
    $maximumElapsed = [Math]::Max($maximumElapsed, $execution.elapsedMilliseconds)
    $accepted = -not $execution.timedOut -and $execution.exitCode -in @(0, 2, 4)
    if ($execution.timedOut) {
        ++$timeouts
    }
    if (-not $accepted) {
        ++$unexpected
    }
    if ($execution.exitCode -in @(0, 2)) {
        try {
            $null = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
        }
        catch {
            $accepted = $false
            ++$unexpected
        }
    }
    $results.Add([ordered]@{
            name = $case.Name
            strategy = $case.Strategy
            inputBytes = $case.Data.Length
            accepted = $accepted
            timedOut = $execution.timedOut
            exitCode = $execution.exitCode
            elapsedMilliseconds = $execution.elapsedMilliseconds
            standardOutput = $execution.standardOutput
            standardError = $execution.standardError
        })
}

$finishedAt = [DateTimeOffset]::UtcNow
$exitCounts = [ordered]@{
    zero = @($results | Where-Object exitCode -eq 0).Count
    incomplete = @($results | Where-Object exitCode -eq 2).Count
    invalidInput = @($results | Where-Object exitCode -eq 4).Count
    other = @($results | Where-Object { $null -ne $_.exitCode -and $_.exitCode -notin @(0, 2, 4) }).Count
}
$status = if ($timeouts -eq 0 -and $unexpected -eq 0) { "passed" } else { "failed" }
$report = [ordered]@{
    schemaVersion = 1
    kind = "noleax-untrusted-trace-corpus"
    status = $status
    preset = $Preset
    deterministicSeed = "0x4e4f4c45"
    requestedRandomMutations = $MutationCount
    totalCases = $cases.Count
    timeoutMilliseconds = $TimeoutMilliseconds
    timeouts = $timeouts
    unexpected = $unexpected
    maximumElapsedMilliseconds = $maximumElapsed
    exitCounts = $exitCounts
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
    }
    results = $results
}
$report | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $ReportPath -Encoding utf8
Write-Host "untrusted trace report: $ReportPath"
Write-Host ("status={0} cases={1} timeouts={2} unexpected={3} max_ms={4}" -f `
        $status, $cases.Count, $timeouts, $unexpected, $maximumElapsed)
if ($status -ne "passed") {
    throw "Untrusted trace corpus found $timeouts timeout(s) and $unexpected unexpected result(s)."
}
