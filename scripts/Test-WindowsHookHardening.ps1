[CmdletBinding()]
param(
    [string]$Preset = "windows-x64-hardened",
    [ValidateRange(1, 1000)]
    [int]$RaceRepeats = 100,
    [ValidateRange(1, 100)]
    [int]$LongStressRepeats = 3,
    [ValidateRange(1, 100)]
    [int]$VerifierRepeats = 3,
    [switch]$RequireCetRuntime,
    [switch]$SkipBuild,
    [switch]$SkipApplicationVerifier
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

function Invoke-CapturedWorkload {
    param(
        [Parameter(Mandatory)]
        [string]$Executable,
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $output = @(& $Executable @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable failed with exit code ${LASTEXITCODE}: $($output -join [Environment]::NewLine)"
    }
    if ($output.Count -ne 1 -or -not $output[0].StartsWith("status=ok version=1 ")) {
        throw "$Executable produced an invalid summary: $($output -join [Environment]::NewLine)"
    }
    return $output[0]
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Convert-RegistryInteger {
    param([Parameter(Mandatory)]$Value)

    if ($Value -is [string]) {
        $text = $Value.Trim()
        if ($text.StartsWith("0x", [StringComparison]::OrdinalIgnoreCase)) {
            return [Convert]::ToUInt64($text.Substring(2), 16)
        }
        return [Convert]::ToUInt64($text, 10)
    }
    return [Convert]::ToUInt64($Value)
}

function Test-RegistryKeyEmpty {
    param([Parameter(Mandatory)][string]$LiteralPath)

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return $false
    }
    $key = Get-Item -LiteralPath $LiteralPath
    return $key.SubKeyCount -eq 0 -and $key.ValueCount -eq 0
}

function Assert-MatchingWorkloads {
    param(
        [Parameter(Mandatory)]
        [string]$MdExecutable,
        [Parameter(Mandatory)]
        [string]$MtExecutable,
        [Parameter(Mandatory)]
        [string]$HookHarness,
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [Parameter(Mandatory)]
        [int]$Repeats,
        [Parameter(Mandatory)]
        [string]$Label
    )

    for ($iteration = 1; $iteration -le $Repeats; ++$iteration) {
        $mdBaseline = Invoke-CapturedWorkload $MdExecutable $Arguments
        $mtBaseline = Invoke-CapturedWorkload $MtExecutable $Arguments
        $hookArguments = $Arguments + @("--hook-harness", $HookHarness)
        $mdHooked = Invoke-CapturedWorkload $MdExecutable $hookArguments
        $mtHooked = Invoke-CapturedWorkload $MtExecutable $hookArguments
        if ($mdBaseline -ne $mtBaseline -or $mdHooked -ne $mdBaseline -or
            $mtHooked -ne $mtBaseline) {
            throw "$Label workload mismatch on repetition $iteration."
        }
        Write-Host "$Label repetition $iteration/$Repeats passed: $mdBaseline"
    }
}

Push-Location $repositoryRoot
try {
    if (-not $SkipBuild) {
        Invoke-CheckedCommand cmake --preset $Preset
        Invoke-CheckedCommand cmake --build --preset $Preset
    }

    $binaryDirectory = Join-Path $repositoryRoot "build\$Preset\bin"
    $mdExecutable = Join-Path $binaryDirectory "noleax-rtl-heap-baseline-md.exe"
    $mtExecutable = Join-Path $binaryDirectory "noleax-rtl-heap-baseline-mt.exe"
    $hookHarness = Join-Path $binaryDirectory "noleax-rtl-allocate-heap-hook-harness.dll"
    $allocateQuiescenceExecutable =
        Join-Path $binaryDirectory "noleax-rtl-allocate-heap-quiescence-test.exe"
    $freeQuiescenceExecutable =
        Join-Path $binaryDirectory "noleax-rtl-free-heap-quiescence-test.exe"
    $reallocateQuiescenceExecutable =
        Join-Path $binaryDirectory "noleax-rtl-reallocate-heap-quiescence-test.exe"
    $heapLifecycleQuiescenceExecutable =
        Join-Path $binaryDirectory "noleax-rtl-heap-lifecycle-quiescence-test.exe"
    $ntVirtualMemoryQuiescenceExecutable =
        Join-Path $binaryDirectory "noleax-nt-virtual-memory-quiescence-test.exe"
    $allocateTraceWriterExecutable =
        Join-Path $binaryDirectory "noleax-rtl-allocate-heap-trace-writer-test.exe"
    $heapTraceWriterExecutable =
        Join-Path $binaryDirectory "noleax-rtl-heap-trace-writer-test.exe"
    $freeContractExecutable =
        Join-Path $binaryDirectory "noleax-rtl-free-heap-contract-test.exe"
    $reallocateContractExecutable =
        Join-Path $binaryDirectory "noleax-rtl-reallocate-heap-contract-test.exe"
    $reallocateExceptionExecutable =
        Join-Path $binaryDirectory "noleax-rtl-reallocate-heap-exception-test.exe"
    $heapLifecycleContractExecutable =
        Join-Path $binaryDirectory "noleax-rtl-heap-lifecycle-contract-test.exe"
    $destroyIsolationExecutable =
        Join-Path $binaryDirectory "noleax-rtl-destroy-heap-isolation-test.exe"
    $ntVirtualMemoryContractExecutable =
        Join-Path $binaryDirectory "noleax-nt-virtual-memory-contract-test.exe"
    $ntSectionViewContractExecutable =
        Join-Path $binaryDirectory "noleax-nt-section-view-contract-test.exe"
    $ntVirtualMemoryTraceWriterExecutable =
        Join-Path $binaryDirectory "noleax-nt-virtual-memory-trace-writer-test.exe"
    $nativeProfileExecutable =
        Join-Path $binaryDirectory "noleax-windows-native-profile-test.exe"
    $moduleGenerationTraceExecutable =
        Join-Path $binaryDirectory "noleax-module-generation-trace-test.exe"
    $moduleTrackerExecutable =
        Join-Path $binaryDirectory "noleax-module-tracker-test.exe"
    foreach ($path in @($mdExecutable, $mtExecutable, $hookHarness,
            $allocateQuiescenceExecutable, $freeQuiescenceExecutable,
            $reallocateQuiescenceExecutable, $heapLifecycleQuiescenceExecutable,
            $ntVirtualMemoryQuiescenceExecutable,
            $allocateTraceWriterExecutable, $heapTraceWriterExecutable,
            $freeContractExecutable, $reallocateContractExecutable,
            $reallocateExceptionExecutable, $heapLifecycleContractExecutable,
            $destroyIsolationExecutable, $ntVirtualMemoryContractExecutable,
            $ntSectionViewContractExecutable, $ntVirtualMemoryTraceWriterExecutable,
            $nativeProfileExecutable, $moduleGenerationTraceExecutable,
            $moduleTrackerExecutable)) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Required hardened artifact is missing: $path"
        }
    }

    Invoke-CheckedCommand ctest --preset $Preset --output-on-failure
    foreach ($quiescenceExecutable in @($allocateQuiescenceExecutable,
            $freeQuiescenceExecutable, $reallocateQuiescenceExecutable,
            $heapLifecycleQuiescenceExecutable, $ntVirtualMemoryQuiescenceExecutable)) {
        $mitigationOutput = @(& $quiescenceExecutable)
        if ($LASTEXITCODE -ne 0 -or $mitigationOutput.Count -ne 1 -or
            $mitigationOutput[0] -notmatch " cfg=1 ") {
            throw "The hardened hook target did not report CFG enforcement: " +
                "$($mitigationOutput -join ' ')"
        }
        if ($mitigationOutput[0] -notmatch " cet=1 ") {
            if ($RequireCetRuntime) {
                throw "The hardened hook target did not report CET shadow-stack enforcement."
            }
            Write-Warning ("CET metadata is present, but this machine did not enforce a user " +
                "shadow stack for $([IO.Path]::GetFileName($quiescenceExecutable)).")
        } else {
            Write-Host "Runtime mitigations passed: $($mitigationOutput[0])"
        }
    }
    Invoke-CheckedCommand ctest --preset $Preset `
        -R "hook.(rtl-((allocate|reallocate|free)-heap|heap-lifecycle)|nt-virtual-memory)-quiescence-race" `
        --repeat "until-fail:$RaceRepeats" --output-on-failure
    Invoke-CheckedCommand ctest --preset $Preset `
        -R "^hook.windows-native-profile$" `
        --repeat "until-fail:$RaceRepeats" --output-on-failure

    $longArguments = @(
        "--threads", "8",
        "--iterations", "20000",
        "--rounds", "2",
        "--seed", "5642812718451281972"
    )
    Assert-MatchingWorkloads $mdExecutable $mtExecutable $hookHarness $longArguments `
        $LongStressRepeats "hardened"

    if ($SkipApplicationVerifier) {
        Write-Host "Application Verifier/Page Heap phase skipped by request."
        return
    }
    if (-not (Test-Administrator)) {
        throw "Application Verifier settings require an elevated PowerShell terminal."
    }
    if (-not [Environment]::Is64BitProcess) {
        throw "Application Verifier must be configured from 64-bit PowerShell for x64 targets."
    }

    $appVerifier = Join-Path $env:SystemRoot "System32\appverif.exe"
    if (-not (Test-Path -LiteralPath $appVerifier)) {
        throw "Application Verifier is not installed: $appVerifier"
    }

    $targetNames = @(
        [IO.Path]::GetFileName($mdExecutable),
        [IO.Path]::GetFileName($mtExecutable),
        [IO.Path]::GetFileName($allocateQuiescenceExecutable),
        [IO.Path]::GetFileName($freeQuiescenceExecutable),
        [IO.Path]::GetFileName($reallocateQuiescenceExecutable),
        [IO.Path]::GetFileName($heapLifecycleQuiescenceExecutable),
        [IO.Path]::GetFileName($ntVirtualMemoryQuiescenceExecutable),
        [IO.Path]::GetFileName($allocateTraceWriterExecutable),
        [IO.Path]::GetFileName($heapTraceWriterExecutable),
        [IO.Path]::GetFileName($freeContractExecutable),
        [IO.Path]::GetFileName($reallocateContractExecutable),
        [IO.Path]::GetFileName($reallocateExceptionExecutable),
        [IO.Path]::GetFileName($heapLifecycleContractExecutable),
        [IO.Path]::GetFileName($ntVirtualMemoryContractExecutable),
        [IO.Path]::GetFileName($ntSectionViewContractExecutable),
        [IO.Path]::GetFileName($ntVirtualMemoryTraceWriterExecutable),
        [IO.Path]::GetFileName($nativeProfileExecutable),
        [IO.Path]::GetFileName($moduleGenerationTraceExecutable),
        [IO.Path]::GetFileName($moduleTrackerExecutable)
    )
    $ifeoRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    foreach ($targetName in $targetNames) {
        $keyPath = Join-Path $ifeoRoot $targetName
        if (Test-Path -LiteralPath $keyPath) {
            $kind = if (Test-RegistryKeyEmpty $keyPath) { "empty IFEO key" } else { "IFEO settings" }
            throw "Refusing to replace pre-existing ${kind}: $keyPath"
        }
    }

    $configuredTargets = [Collections.Generic.List[string]]::new()
    $cleanupFailures = [Collections.Generic.List[string]]::new()
    $phaseFailure = $null
    try {
        foreach ($targetName in $targetNames) {
            # The target names were proven absent above, so track the cleanup responsibility before
            # invoking appverif. This also rolls back a partially-created IFEO key if appverif fails.
            $configuredTargets.Add($targetName)
            Invoke-CheckedCommand $appVerifier -enable Heaps -for $targetName `
                -with Heaps.Full=true
            $keyPath = Join-Path $ifeoRoot $targetName
            if (-not (Test-Path -LiteralPath $keyPath)) {
                throw "Application Verifier did not create settings for $targetName."
            }
            $settings = Get-ItemProperty -LiteralPath $keyPath
            $globalFlag = Convert-RegistryInteger $settings.GlobalFlag
            $pageHeapFlags = Convert-RegistryInteger $settings.PageHeapFlags
            if (($globalFlag -band 0x00000100L) -eq 0) {
                throw "Application Verifier is not enabled for $targetName " +
                    "(GlobalFlag=$globalFlag)."
            }
            if (($pageHeapFlags -band 0x00000001L) -eq 0) {
                throw "Full Page Heap is not enabled for $targetName " +
                    "(PageHeapFlags=$pageHeapFlags)."
            }
        }

        $verifierArguments = @(
            "--threads", "4",
            "--iterations", "2000",
            "--rounds", "2",
            "--seed", "5642812718451281972",
            "--require-app-verifier",
            "--require-page-heap"
        )
        Assert-MatchingWorkloads $mdExecutable $mtExecutable $hookHarness $verifierArguments `
            $VerifierRepeats "appverifier-pageheap"
        Invoke-CheckedCommand ctest --preset $Preset `
            -R "hook.(rtl-((allocate|reallocate|free)-heap|heap-lifecycle)|nt-virtual-memory)-quiescence-race" `
            --repeat "until-fail:$VerifierRepeats" --output-on-failure
        Invoke-CheckedCommand ctest --preset $Preset `
            -R "hook.rtl-allocate-heap-trace-writer-normal|hook.rtl-heap-trace-writer-lifecycle|hook.rtl-(free|reallocate)-heap-contract|hook.rtl-reallocate-heap-seh-contract|hook.rtl-heap-lifecycle-contract|hook.nt-virtual-memory-(contract|trace-writer)|hook.nt-section-view-(contract|unmatched-trace)|hook.windows-native-profile|hook.module-(generation-trace|tracker-bounded-queue)" `
            --repeat "until-fail:$VerifierRepeats" --output-on-failure
    } catch {
        $phaseFailure = $_
    } finally {
        # Finish every appverif mutation before inspecting/removing container keys. A later
        # appverif invocation may otherwise recreate an empty key already checked in this loop.
        foreach ($targetName in $configuredTargets) {
            $keyPath = Join-Path $ifeoRoot $targetName
            try {
                if (Test-Path -LiteralPath $keyPath) {
                    & $appVerifier -delete settings -for $targetName
                    if ($LASTEXITCODE -ne 0) {
                        $cleanupFailures.Add("cleanup command failed for $targetName")
                    }
                }
            } catch {
                $cleanupFailures.Add("cleanup command raised for ${targetName}: $($_.Exception.Message)")
            }
        }

        foreach ($targetName in $configuredTargets) {
            $keyPath = Join-Path $ifeoRoot $targetName
            try {
                # Current appverif builds can delete every value but retain the target's empty IFEO
                # container. It is safe to remove here because preflight proved the key did not exist.
                if (Test-RegistryKeyEmpty $keyPath) {
                    Remove-Item -LiteralPath $keyPath
                }
                if (Test-Path -LiteralPath $keyPath) {
                    $cleanupFailures.Add("settings remain after cleanup: $keyPath")
                }
            } catch {
                $cleanupFailures.Add("cleanup verification raised for ${targetName}: $($_.Exception.Message)")
            }
        }
    }

    if ($null -ne $phaseFailure) {
        if ($cleanupFailures.Count -ne 0) {
            throw "Application Verifier phase failed: $($phaseFailure.Exception.Message); " +
                "cleanup also failed: $($cleanupFailures -join '; ')"
        }
        throw $phaseFailure
    }
    if ($cleanupFailures.Count -ne 0) {
        throw "Application Verifier cleanup failed: $($cleanupFailures -join '; ')"
    }

    Write-Host ("Windows memory hook hardening gate passed " +
        "(CFG, CET metadata/runtime, fail-fast, Page Heap, AppVerifier).")
} finally {
    Pop-Location
}
