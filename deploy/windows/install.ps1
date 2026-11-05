<#
.SYNOPSIS
    OQVIAN installer for Windows (CISO laptop: i7 11th gen, 16 GB, Iris Xe MAX).

.DESCRIPTION
    Sets up, in order: hardware probe, Ollama + Intel GPU offload, the single
    OQVIAN model with the Qwen2.5 tool-calling template, the knowledge corpus
    and FTS5 index, the deepseek harness, the MCP tool server wiring, and a
    smoke test. Idempotent — safe to re-run.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1

.EXAMPLE
    .\install.ps1 -SkipTools -SkipIndex
#>
[CmdletBinding()]
param(
    [switch]$SkipTools,
    [switch]$SkipModel,
    [switch]$SkipIndex,
    [switch]$SkipHarness,
    [switch]$Status,
    [string]$OllamaBin = ""
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root

# The single OQVIAN model. One model, one persona, one tool template.
$Model = "oqvian-cyber-control-full-unlocked-v1.1"

$script:Ok = 0
$script:Skip = 0
$script:Fail = 0

function Step($title) { Write-Host ""; Write-Host "== $title" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "  ok   $msg" -ForegroundColor Green;  $script:Ok++ }
function Skip($msg) { Write-Host "  skip $msg" -ForegroundColor DarkGray; $script:Skip++ }
function Bad($msg)  { Write-Host "  FAIL $msg" -ForegroundColor Red;    $script:Fail++ }
function Info($msg) { Write-Host "  $msg" -ForegroundColor Gray }

function Have($cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# --------------------------------------------------------------------------- #
Step "1/8  hardware"
try {
    $cpu  = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
    $ram  = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    $gpus = Get-CimInstance Win32_VideoController |
            Select-Object Name, @{n='VRAM_GB';e={ [math]::Round($_.AdapterRAM / 1GB, 1) }}
    $free = [math]::Round((Get-PSDrive $Root.Substring(0,1)).Free / 1GB, 1)
    Info "cpu     $cpu"
    Info "memory  $ram GB"
    foreach ($g in $gpus) { Info "gpu     $($g.Name) (~$($g.VRAM_GB) GB reported)" }
    Info "disk    $free GB free on $($Root.Substring(0,1)):"
    if ($free -lt 15) { Bad "need ~15 GB free — free space before continuing" }
    else { Ok "hardware probed" }
} catch { Bad "hardware probe: $_" }

if ($Status) {
    Step "status"
    foreach ($pair in @(
        @("ollama",     (Have "ollama")),
        @("python",     ((Have "py") -or (Have "python"))),
        @("node/npm",   (Have "npm")),
        @("dsh",        (Have "dsh")),
        @("git",        (Have "git")),
        @("index",      (Test-Path "index\meta.json")),
        @("venv",       (Test-Path ".venv")),
        @("dsh config", (Test-Path (Join-Path $HOME ".dsh")))))
    {
        $mark = "MISSING"; if ($pair[1]) { $mark = "present" }
        Write-Host ("  {0,-12} {1}" -f $pair[0], $mark)
    }
    if (Have "ollama") { & ollama list }
    exit 0
}

# --------------------------------------------------------------------------- #
Step "2/8  base dependencies"
if (-not (Have "git")) {
    if (Have "winget") {
        Info "installing git via winget"
        winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements | Out-Null
    }
}
if (Have "git") { Ok "git" } else { Bad "git — install from https://git-scm.com/download/win" }

$pyExe = $null
if (Have "py")          { $pyExe = "py" }
elseif (Have "python")  { $pyExe = "python" }
if ($pyExe) { Ok "python ($pyExe)" }
else {
    Bad "python — installing via winget"
    if (Have "winget") {
        winget install --id Python.Python.3.12 -e --accept-source-agreements --accept-package-agreements | Out-Null
        if (Have "python") { $pyExe = "python"; Ok "python installed" }
    }
    if (-not $pyExe) { Bad "install Python 3.11+ from python.org, then re-run" }
}

# venv
$venvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    if ($pyExe -eq "py") { & py -3 -m venv .venv } else { & python -m venv .venv }
}
if (Test-Path $venvPy) { Ok "virtualenv (.venv)" } else { Bad "venv creation" }

if (Test-Path $venvPy) {
    & $venvPy -m pip install --quiet --upgrade pip 2>$null
    & $venvPy -m pip install --quiet -r requirements.txt
    if ($LASTEXITCODE -eq 0) { Ok "python deps (mcp, numpy, pyyaml)" }
    else { Bad "python deps — check network access to pypi" }
}

# --------------------------------------------------------------------------- #
Step "3/8  ollama + Intel GPU offload"
$ollama = $OllamaBin
if (-not $ollama) {
    $c = Get-Command ollama -ErrorAction SilentlyContinue
    if ($c) { $ollama = $c.Source }
}
if (-not $ollama) {
    Info "installing Ollama via winget"
    if (Have "winget") {
        winget install --id Ollama.Ollama -e --accept-source-agreements --accept-package-agreements | Out-Null
    }
    $cand = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"
    if (Test-Path $cand) { $ollama = $cand }
}
if ($ollama) { Ok "ollama at $ollama" } else { Bad "ollama — install from https://ollama.com/download/windows" }

# user-level env for GPU offload + cache behaviour
$envVars = @{
    "OLLAMA_VULKAN"           = "1"
    "OLLAMA_FLASH_ATTENTION"  = "1"
    "OLLAMA_KV_CACHE_TYPE"    = "q8_0"
    "OLLAMA_KEEP_ALIVE"       = "30m"
    "OLLAMA_HOST"             = "127.0.0.1:11434"
    "OLLAMA_MAX_LOADED_MODELS"= "1"
    "OLLAMA_NUM_PARALLEL"     = "1"
}
foreach ($k in $envVars.Keys) {
    [Environment]::SetEnvironmentVariable($k, $envVars[$k], "User")
    Set-Item -Path "Env:$k" -Value $envVars[$k]
}
Ok "user env: OLLAMA_VULKAN + flash-attention + q8_0 KV + 30m keep-alive"

# start / restart the service so the new env applies
if ($ollama) {
    Get-Process -Name "ollama" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process -FilePath $ollama -ArgumentList "serve" -WindowStyle Hidden
}
$up = $false
for ($i = 0; $i -lt 40; $i++) {
    try { Invoke-RestMethod -Uri "http://127.0.0.1:11434/" -TimeoutSec 2 | Out-Null; $up = $true; break } catch { Start-Sleep -Milliseconds 700 }
}
if ($up) { Ok "API answers on 127.0.0.1:11434" } else { Bad "API not answering — start 'ollama serve'" }

# --------------------------------------------------------------------------- #
if (-not $SkipModel -and $ollama) {
    Step "4/8  model (single, ~4.7 GB)"

    # The model extracted from the release already carries the template and the
    # current system prompt. Rebuilding it would make Ollama resolve the
    # upstream GGUF reference, which fails on an offline machine.
    $present = $true
    & $ollama show $Model --modelfile 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { $present = $false }
    $refs = (& $ollama show $Model --template 2>$null | Select-String -Pattern '\.Tools' -AllMatches | Measure-Object).Count
    if ($present -and $refs -ge 1) {
        Ok "$Model already built with the tool template — nothing to rebuild"
        Step "4b/8  verify tool template"
        $n = (& $ollama show $Model --template 2>$null | Select-String -Pattern '\.Tools' -AllMatches | Measure-Object).Count
        if ($n -ge 1) { Ok "$Model tool template ($n refs)" } else { Bad "$Model has no .Tools block" }
        $SkipModel = $true
    }
}

if (-not $SkipModel -and $ollama) {
    $base = Join-Path $Root "models\Modelfile.unlocked"
    $tpl  = Join-Path $Root "models\qwen-tools.template"
    if (-not (Test-Path $base) -or -not (Test-Path $tpl)) {
        Bad "models\Modelfile.unlocked or qwen-tools.template missing"
    } else {
        # Modelfile.unlocked has FROM + PARAMETER + SYSTEM, no TEMPLATE.
        # Append the official Qwen2.5 tool template so Ollama renders tool schemas.
        $built = (Get-Content -Raw $base).TrimEnd() + "`r`n`r`n" +
                 'TEMPLATE """' + "`r`n" +
                 (Get-Content -Raw $tpl).TrimEnd() + "`r`n" + '"""' + "`r`n"
        $builtPath = Join-Path $Root "models\Modelfile.unlocked.built"
        [System.IO.File]::WriteAllText($builtPath, $built, (New-Object System.Text.UTF8Encoding($false)))

        & $ollama create $Model -f $builtPath | Out-Null
        if ($LASTEXITCODE -eq 0) { Ok "$Model (GGUF pull on first run)" } else { Bad "ollama create $Model" }

        # Prune retired multi-persona / pre-rename builds so exactly one remains.
        foreach ($m in @("oqvian","oqvian-ciso","oqvian-offensive","oqvian-defensive","oqvian-ir")) {
            & $ollama rm $m 2>$null | Out-Null
        }

        Step "4b/8  verify tool template"
        $n = (& $ollama show $Model --template 2>$null | Select-String -Pattern '\.Tools' -AllMatches | Measure-Object).Count
        if ($n -ge 1) { Ok "$Model tool template ($n refs)" } else { Bad "$Model has no .Tools block" }
    }
} elseif (-not $SkipModel) { Step "4/8  model"; Skip "model (no ollama)" }

# --------------------------------------------------------------------------- #
if (-not $SkipIndex) {
    Step "5/8  corpus + FTS5 index"
    $raw = Join-Path $Root "corpus\raw"
    New-Item -ItemType Directory -Force -Path $raw | Out-Null

    $files = @{
        "enterprise-attack.json" = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        "cwec_latest.xml.zip"    = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        "kev.json"               = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        "lolbas.json"            = "https://lolbas-project.github.io/api/lolbas.json"
    }
    foreach ($name in $files.Keys) {
        $dest = Join-Path $raw $name
        if (Test-Path $dest) { Info "have $name"; continue }
        try {
            curl.exe -fsSL -o $dest $files[$name]
            if (Test-Path $dest) { Ok "$name" } else { Bad "$name download" }
        } catch { Bad "$name download: $_" }
    }

    if (Have "git") {
        foreach ($repo in @("SigmaHQ/sigma","OWASP/wstg","GTFOBins/GTFOBins.github.io")) {
            $d = Join-Path $raw (Split-Path $repo -Leaf)
            if (Test-Path $d) { Info "have $(Split-Path $repo -Leaf)" }
            else {
                & git clone --depth 1 "https://github.com/$repo" $d 2>$null
                if (Test-Path $d) { Ok (Split-Path $repo -Leaf) } else { Bad "clone $repo" }
            }
        }
    } else { Bad "git missing — Sigma/WSTG/GTFOBins corpus cannot be cloned" }

    if (Test-Path $venvPy) {
        & $venvPy -u ingest.py
        if (Test-Path "index\meta.json") { Ok "index built (index\fts.db)" } else { Bad "ingest" }
    }
} else { Step "5/8  index"; Skip "index" }

# --------------------------------------------------------------------------- #
Step "6/8  Windows toolchain"
if (-not $SkipTools) {
    if (Have "winget") {
        if (-not (Have "nmap")) {
            try { winget install --id Insecure.Nmap -e --accept-source-agreements --accept-package-agreements | Out-Null } catch {}
        }
    }
    foreach ($t in @("nmap","nuclei","httpx","subfinder","naabu","ffuf","trivy","gitleaks","syft","grype","katana")) {
        if (Have $t) { Ok $t } else { Info "missing: $t (download the *_windows_amd64.zip, put the .exe on PATH)" }
    }
    Info "full Kali-class toolset needs WSL2 — see deploy\windows\README.md section 4"
} else { Skip "tools" }

# --------------------------------------------------------------------------- #
Step "7/8  harness (deepseek dsh)"
if (-not $SkipHarness) {
    if (-not (Have "npm")) {
        Info "installing Node.js LTS via winget"
        if (Have "winget") {
            winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements | Out-Null
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                        [System.Environment]::GetEnvironmentVariable("Path","User")
        }
    }
    if (Have "npm") {
        Ok "node/npm"
        if (-not (Have "dsh")) {
            Info "installing @deepseek-ai/dsh@0.1.1-rc.2 (pinned: config schema matches these profiles)"
            & npm i -g "@deepseek-ai/dsh@0.1.1-rc.2" 2>$null
        }
        if (Have "dsh") { Ok "dsh" } else { Bad "dsh install — check npm prefix is on PATH" }
    } else { Bad "node/npm" }

    $dshHome = Join-Path $HOME ".dsh"
    if (-not (Test-Path $dshHome)) {
        Info "priming ~/.dsh (10 s boot, then stopping it)"
        $p = Start-Process -FilePath "dsh" -ArgumentList "web","--no-open","--port","0" -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 12
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    if (Test-Path $venvPy) {
        & $venvPy scripts\setup_harness.py
        if ($LASTEXITCODE -eq 0) { Ok "profiles, settings, scope wired" } else { Bad "setup_harness.py" }
        & $venvPy scripts\brand_harness.py 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { Ok "harness branded OQVIAN HARNESS" } else { Skip "harness branding (re-run scripts\brand_harness.py)" }
    }
} else { Step "7/8  harness"; Skip "harness" }

# --------------------------------------------------------------------------- #
Step "8/8  verification"
if (Test-Path $venvPy) {
    & $venvPy mcp\smoke_test.py
    if ($LASTEXITCODE -eq 0) { Ok "tool server smoke test" } else { Bad "smoke test" }
}
if ($ollama) {
    Info "GPU check — PROCESSOR column should show GPU:"
    & $ollama ps
}

Write-Host ""
Write-Host "== summary ==" -ForegroundColor White
Write-Host "  ok $script:Ok   skipped $script:Skip   failed $script:Fail"
Write-Host ""
if ($script:Fail -eq 0) {
    Write-Host "  Ready." -ForegroundColor Green
    Write-Host "    dsh web                        # UI, the OQVIAN model"
    Write-Host '    dsh --profile headless "..."    # one-shot'
    Write-Host "    ollama run $Model   # direct"
    Write-Host ""
    Write-Host "  Scope:  $HOME\.config\oqvian\scope.json"
    Write-Host "  Audit:  $HOME\.local\share\oqvian\audit.jsonl"
} else {
    Write-Host "  Fix the FAIL lines above and re-run this script." -ForegroundColor Yellow
}
