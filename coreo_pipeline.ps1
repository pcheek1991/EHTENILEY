$ErrorActionPreference = "Stop"

try {
    $sourcePath = Join-Path $PSScriptRoot "coreo_pipeline.cs"
    if ($null -eq ("CoreoPipeline" -as [type])) {
        Add-Type -Path $sourcePath -ErrorAction Stop
    }

    $exitCode = [CoreoPipeline]::Run([string[]]$args, $PSScriptRoot)
    exit [int]$exitCode
}
catch {
    [Console]::Error.WriteLine("COREO wrapper failed: " + $_.Exception.Message)
    exit 1
}
