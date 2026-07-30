[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$NoleaxPath,

    [Parameter(Mandatory = $true)]
    [string]$AgentPath,

    [Parameter(Mandatory = $true)]
    [string]$TargetPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

function Resolve-RequiredFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description does not exist: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Invoke-ExpectedExit {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$CommandArguments,

        [Parameter(Mandatory = $true)]
        [int[]]$ExpectedExitCodes,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $output = @(& $Executable @CommandArguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($ExpectedExitCodes -notcontains $exitCode) {
        $renderedOutput = $output -join [Environment]::NewLine
        throw "$Description returned $exitCode; expected $($ExpectedExitCodes -join ', '):`n$renderedOutput"
    }
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$noleax = Resolve-RequiredFile -Path $NoleaxPath -Description "noleax executable"
$agent = Resolve-RequiredFile -Path $AgentPath -Description "noleax agent"
$target = Resolve-RequiredFile -Path $TargetPath -Description "documentation test target"

$examplesDirectory = Join-Path $repositoryRoot "examples"
$exampleFiles = @(
    "run-nt-heap.toml",
    "analyze-events.toml",
    "analyze-outstanding.toml"
)
foreach ($file in $exampleFiles) {
    [void](Resolve-RequiredFile -Path (Join-Path $examplesDirectory $file) -Description "example")
}

$temporaryRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot "_temp\docs-validation"))
$workspace = [IO.Path]::GetFullPath((Join-Path $temporaryRoot ([Guid]::NewGuid().ToString("N"))))
$expectedPrefix = $temporaryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
if (-not $workspace.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "refusing to use documentation workspace outside $temporaryRoot"
}

[void](New-Item -ItemType Directory -Path $workspace -Force)
try {
    foreach ($file in $exampleFiles) {
        Copy-Item -LiteralPath (Join-Path $examplesDirectory $file) -Destination $workspace
    }
    Copy-Item -LiteralPath $target -Destination (Join-Path $workspace "application.exe")

    $trace = Join-Path $workspace "capture.nlx"
    $marker = Join-Path $workspace "capture.ready"
    Invoke-ExpectedExit -Executable $noleax -Description "documentation capture" -ExpectedExitCodes @(0) `
        -CommandArguments @(
            "run", "--agent", $agent, "--trace", $trace, "--capture-duration", "1s",
            "--hook-profile", "windows-nt-heap", "--compression", "none", "--",
            $target, $marker, "1800", "launch"
        )
    if (-not (Test-Path -LiteralPath $trace -PathType Leaf)) {
        throw "documentation capture did not create $trace"
    }

    foreach ($file in $exampleFiles) {
        $configuration = Join-Path $workspace $file
        Invoke-ExpectedExit -Executable $noleax -Description "validate $file" -ExpectedExitCodes @(0) `
            -CommandArguments @("--config", $configuration, "config", "validate")
    }

    $eventsConfiguration = Join-Path $workspace "analyze-events.toml"
    Invoke-ExpectedExit -Executable $noleax -Description "events example" -ExpectedExitCodes @(0, 2) `
        -CommandArguments @("--config", $eventsConfiguration)
    $eventsOutput = Join-Path $workspace "events.json"
    $events = Get-Content -LiteralPath $eventsOutput -Raw | ConvertFrom-Json
    if ($events.mode -ne "events" -or $events.summary.matched_events -lt 1) {
        throw "events example did not produce event records"
    }

    $outstandingConfiguration = Join-Path $workspace "analyze-outstanding.toml"
    Invoke-ExpectedExit -Executable $noleax -Description "outstanding example" `
        -ExpectedExitCodes @(0, 2) -CommandArguments @("--config", $outstandingConfiguration)
    $outstandingOutput = Join-Path $workspace "outstanding.json"
    $outstanding = Get-Content -LiteralPath $outstandingOutput -Raw | ConvertFrom-Json
    if ($outstanding.mode -ne "outstanding" -or $outstanding.summary.outstanding -lt 1) {
        throw "outstanding example did not find the test allocation"
    }

    $patchInput = Join-Path $workspace "patch-input.exe"
    $patchOutput = Join-Path $workspace "patch-output.exe"
    Copy-Item -LiteralPath $target -Destination $patchInput
    Invoke-ExpectedExit -Executable $noleax -Description "deferred patch contract" `
        -ExpectedExitCodes @(5) -CommandArguments @(
            "patch", "--input", $patchInput, "--output", $patchOutput
        )
    if (Test-Path -LiteralPath $patchOutput) {
        throw "deferred patch command unexpectedly created an output file"
    }

    Invoke-ExpectedExit -Executable $noleax -Description "deferred thread hijack contract" `
        -ExpectedExitCodes @(5) -CommandArguments @(
            "run", "--inject-method", "thread-hijack", "--agent", $agent,
            "--trace", (Join-Path $workspace "unsupported.nlx"), "--capture-duration", "1ms",
            "--", $target, (Join-Path $workspace "unsupported.ready"), "1800", "launch"
        )

    Write-Output "status=ok configs=3 capture=1 events=1 outstanding=1 deferred=2"
}
finally {
    if (Test-Path -LiteralPath $workspace) {
        Remove-Item -LiteralPath $workspace -Recurse -Force
    }
}
