[CmdletBinding()]
param(
    [string]$BuildDirectory = "build/windows-x64-release",
    [string]$TargetPath,
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
. (Join-Path $PSScriptRoot "Enter-NoleaxDevShell.ps1") *> $null

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$CommandArguments,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $output = @(& $Executable @CommandArguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code ${LASTEXITCODE}:`n$($output -join [Environment]::NewLine)"
    }
}

function Resolve-RequiredFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description is missing: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-PeDependencies {
    param([Parameter(Mandatory = $true)][string]$ImagePath)

    $output = @(& dumpbin.exe /nologo /dependents $ImagePath 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin failed for ${ImagePath}:`n$($output -join [Environment]::NewLine)"
    }
    return @($output | ForEach-Object {
            $line = $_.ToString().Trim()
            if ($line -match '^[A-Za-z0-9_.-]+\.dll$') {
                $line.ToLowerInvariant()
            }
        } | Sort-Object -Unique)
}

function Assert-X64Image {
    param([Parameter(Mandatory = $true)][string]$ImagePath)

    $output = @(& dumpbin.exe /nologo /headers $ImagePath 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($output -join "`n") -notmatch '8664 machine \(x64\)') {
        throw "package image is not Windows x64: $ImagePath"
    }
}

function Assert-DependencyClosure {
    param([Parameter(Mandatory = $true)][string]$BinaryDirectory)

    $packaged = @{}
    foreach ($file in Get-ChildItem -LiteralPath $BinaryDirectory -File) {
        $packaged[$file.Name.ToLowerInvariant()] = $file.FullName
    }

    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($packaged['noleax.exe'])
    $queue.Enqueue($packaged['noleax-agent.dll'])
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $systemDirectory = [Environment]::SystemDirectory

    while ($queue.Count -gt 0) {
        $image = $queue.Dequeue()
        if (-not $visited.Add($image)) {
            continue
        }
        foreach ($dependency in Get-PeDependencies -ImagePath $image) {
            if ($packaged.ContainsKey($dependency)) {
                $queue.Enqueue($packaged[$dependency])
                continue
            }
            if ($dependency -match '^(api-ms-win-|ext-ms-win-)') {
                continue
            }
            if ($dependency -match '^(msvcp|vcruntime|concrt)[0-9_].*\.dll$') {
                throw "package image unexpectedly uses the dynamic MSVC runtime: $dependency (required by $image)"
            }
            if (Test-Path -LiteralPath (Join-Path $systemDirectory $dependency) -PathType Leaf) {
                continue
            }
            throw "dependency is neither packaged nor a Windows system DLL: $dependency (required by $image)"
        }
    }
    return $visited.Count
}

function Assert-PackageLayout {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $requiredFiles = @(
        'bin/noleax.exe',
        'bin/noleax-agent.dll',
        'README.md',
        'BUILDING.md',
        'SECURITY.md',
        'THIRD_PARTY_NOTICES.md',
        'docs/quickstart.md',
        'docs/troubleshooting.md',
        'docs/cli.md',
        'docs/config.md',
        'docs/console-output.md',
        'docs/json-output.md',
        'docs/csv-output.md',
        'docs/trace-format.md',
        'docs/trace-recovery.md',
        'docs/symbolization.md',
        'docs/symbols.md',
        'docs/static-pe-patch.md',
        'docs/hook-profiles.md',
        'docs/roadmap.md',
        'docs/schema/noleax-analysis-v1.schema.json',
        'docs/schema/noleax-analysis-v2.schema.json',
        'docs/schema/noleax-analysis-v3.schema.json',
        'docs/schema/noleax-symbols-v1.schema.json',
        'examples/README.md',
        'examples/run-nt-heap.toml',
        'examples/analyze-events.toml',
        'examples/analyze-outstanding.toml',
        'licenses/catch2.txt',
        'licenses/cli11.txt',
        'licenses/hoox.txt',
        'licenses/lz4.txt',
        'licenses/tomlplusplus.txt',
        'licenses/zstd.txt'
    )
    foreach ($relativePath in $requiredFiles) {
        $nativePath = $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        [void](Resolve-RequiredFile -Path (Join-Path $PackageRoot $nativePath) `
            -Description "package file $relativePath")
    }

    $expectedLicenseHashes = @{
        'catch2.txt' = 'C9BFF75738922193E67FA726FA225535870D2AA1059F91452C411736284AD566'
        'cli11.txt' = '009A05A07C254FE5A3BD8DA28C8B8DB91995E9447A2EDB54B302EE5B46D8FA18'
        'hoox.txt' = 'E98D9406F33DD14ACD0228FAAEEC61A2EFAD0BD2C95A8AC13CC2DB7F86C50C0B'
        'lz4.txt' = '8B58C446121A109CCF32EDC094BBA3010A3D85E4EE3702950DB55E4D3E87736C'
        'tomlplusplus.txt' = '529BC3900A9571E49DB285B0DF432397E70B881CC3BF48DE6667AE74FF4B06D8'
        'zstd.txt' = '434DCA949C6DA7C500413AEF694539FE37F867DD1A94D83D4ED1D260194E2660'
    }
    foreach ($entry in $expectedLicenseHashes.GetEnumerator()) {
        $licensePath = Join-Path (Join-Path $PackageRoot 'licenses') $entry.Key
        $actualHash = (Get-FileHash -LiteralPath $licensePath -Algorithm SHA256).Hash
        if ($actualHash -ne $entry.Value) {
            throw "locked copyright text changed for $($entry.Key): $actualHash"
        }
    }

    $notice = Get-Content -LiteralPath (Join-Path $PackageRoot 'THIRD_PARTY_NOTICES.md') -Raw
    foreach ($component in @('Catch2', 'CLI11', 'Hoox', 'LZ4', 'toml++', 'Zstandard')) {
        if ($notice -notmatch [regex]::Escape($component)) {
            throw "third-party notice does not name $component"
        }
    }

    $binaryDirectory = Join-Path $PackageRoot 'bin'
    foreach ($file in Get-ChildItem -LiteralPath $binaryDirectory -File) {
        $name = $file.Name.ToLowerInvariant()
        if ($name -in @('noleax.exe', 'noleax-agent.dll')) {
            continue
        }
        throw "unexpected file in package bin directory: $($file.Name)"
    }
    Assert-X64Image -ImagePath (Join-Path $binaryDirectory 'noleax.exe')
    Assert-X64Image -ImagePath (Join-Path $binaryDirectory 'noleax-agent.dll')
    return Assert-DependencyClosure -BinaryDirectory $binaryDirectory
}

function Test-RunnablePackage {
    param(
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)][string]$WorkloadTarget
    )

    $binaryDirectory = Join-Path $PackageRoot 'bin'
    $noleax = Join-Path $binaryDirectory 'noleax.exe'
    $agent = Join-Path $binaryDirectory 'noleax-agent.dll'
    Invoke-CheckedCommand -Executable $noleax -Description 'packaged --version' `
        -CommandArguments @('--version')
    Invoke-CheckedCommand -Executable $noleax -Description 'packaged doctor' `
        -CommandArguments @('doctor', '--agent', $agent, '--target', $WorkloadTarget)

    $documentationTest = Join-Path $PSScriptRoot 'Test-DocumentationExamples.ps1'
    Invoke-CheckedCommand -Executable 'pwsh' -Description 'packaged capture/analyze workflow' `
        -CommandArguments @(
            '-NoProfile', '-File', $documentationTest,
            '-NoleaxPath', $noleax,
            '-AgentPath', $agent,
            '-TargetPath', $WorkloadTarget,
            '-ExamplesDirectory', (Join-Path $PackageRoot 'examples')
        )
}

if (-not $IsWindows -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'The V1 package smoke test requires Windows x64.'
}

if ([IO.Path]::IsPathRooted($BuildDirectory)) {
    $build = [IO.Path]::GetFullPath($BuildDirectory)
}
else {
    $build = [IO.Path]::GetFullPath((Join-Path $repositoryRoot $BuildDirectory))
}
[void](Resolve-RequiredFile -Path (Join-Path $build 'CPackConfig.cmake') `
    -Description 'CPack configuration')
if ([string]::IsNullOrWhiteSpace($TargetPath)) {
    $TargetPath = Join-Path $build 'bin/noleax-cli-e2e-target.exe'
}
$target = Resolve-RequiredFile -Path $TargetPath -Description 'package smoke target'

$temporaryRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '_temp/package-smoke'))
$workspace = [IO.Path]::GetFullPath((Join-Path $temporaryRoot ([Guid]::NewGuid().ToString('N'))))
$expectedPrefix = $temporaryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar
if (-not $workspace.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "refusing to use package workspace outside $temporaryRoot"
}

[void](New-Item -ItemType Directory -Path $workspace -Force)
try {
    if (-not $SkipBuild) {
        Invoke-CheckedCommand -Executable 'cmake' -Description 'package build' `
            -CommandArguments @('--build', $build)
    }

    $stage = Join-Path $workspace 'stage'
    Invoke-CheckedCommand -Executable 'cmake' -Description 'staging install' `
        -CommandArguments @('--install', $build, '--prefix', $stage)
    $stageImages = Assert-PackageLayout -PackageRoot $stage
    Test-RunnablePackage -PackageRoot $stage -WorkloadTarget $target

    $archiveDirectory = Join-Path $workspace 'archive'
    [void](New-Item -ItemType Directory -Path $archiveDirectory -Force)
    Invoke-CheckedCommand -Executable 'cpack' -Description 'ZIP package generation' `
        -CommandArguments @('--config', (Join-Path $build 'CPackConfig.cmake'), '-G', 'ZIP',
            '-B', $archiveDirectory)
    $archives = @(Get-ChildItem -LiteralPath $archiveDirectory -Filter 'noleax-*.zip' -File)
    if ($archives.Count -ne 1) {
        throw "expected one release archive, found $($archives.Count)"
    }
    if ($archives[0].Name -notmatch '^noleax-[0-9]+\.[0-9]+\.[0-9]+-windows-x64\.zip$') {
        throw "unexpected release archive name: $($archives[0].Name)"
    }
    $checksums = @(Get-ChildItem -LiteralPath $archiveDirectory -Filter '*.zip.sha256' -File)
    if ($checksums.Count -ne 1) {
        throw "expected one SHA256 companion, found $($checksums.Count)"
    }

    $extract = Join-Path $workspace 'extract'
    Expand-Archive -LiteralPath $archives[0].FullName -DestinationPath $extract
    $topLevel = @(Get-ChildItem -LiteralPath $extract -Directory)
    if ($topLevel.Count -ne 1) {
        throw "ZIP must contain exactly one top-level directory"
    }
    $archiveImages = Assert-PackageLayout -PackageRoot $topLevel[0].FullName
    Test-RunnablePackage -PackageRoot $topLevel[0].FullName -WorkloadTarget $target

    $archiveHash = (Get-FileHash -LiteralPath $archives[0].FullName -Algorithm SHA256).Hash
    $recordedHash = ((Get-Content -LiteralPath $checksums[0].FullName -Raw) -split '\s+')[0]
    if ($archiveHash -ne $recordedHash) {
        throw 'CPack SHA256 companion does not match the ZIP archive'
    }

    Write-Output ("status=ok stage=1 archive=1 workflows=2 images={0}/{1} licenses=6 sha256=1" -f `
            $stageImages, $archiveImages)
}
finally {
    if (Test-Path -LiteralPath $workspace) {
        Remove-Item -LiteralPath $workspace -Recurse -Force
    }
}
