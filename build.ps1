$ErrorActionPreference = 'Stop'

$source = Join-Path $PSScriptRoot 'Program.cs'
$outputDirectory = Join-Path $PSScriptRoot 'dist'
$output = Join-Path $outputDirectory 'TcpPortDoctor.exe'
$compilerCandidates = @(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
)
$compiler = $compilerCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if (-not $compiler) {
    throw 'Compilador C# do .NET Framework não encontrado.'
}

New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
& $compiler /nologo /target:exe /platform:anycpu /optimize+ /debug- "/out:$output" /reference:System.dll /reference:System.Core.dll $source

if ($LASTEXITCODE -ne 0) {
    throw "Falha na compilação (código $LASTEXITCODE)."
}

Write-Host "Executável criado: $output"
