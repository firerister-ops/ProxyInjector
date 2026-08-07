<#
.SYNOPSIS
    Launches Path of Exile through SOCKS5 proxy via DLL injection.
#>
param(
    [string]$GamePath = "D:\Games\PathofExile2",
    [string]$DllPath = "C:\ABF\ProxyInjector\bin\ProxyPayload.dll",
    [string]$InjectorPath = "C:\ABF\ProxyInjector\bin\Injector.exe",
    [int]$MaxWaitMinutes = 15,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Script log file (always verbose)
$scriptLog = "$env:TEMP\launch_poe_log.txt"
function Log-Write($msg) {
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $msg"
    Write-Host $line
    Add-Content -Path $scriptLog -Value $line -ErrorAction SilentlyContinue
}

function Write-Step($msg) { Log-Write ""; Log-Write "=== $msg ===" }
function Write-Ok($msg)   { Log-Write "[OK] $msg" }
function Write-Wait($msg) { Log-Write "[..] $msg" }
function Write-Err($msg)  { Log-Write "[ERR] $msg" }

# Fresh log
if (Test-Path $scriptLog) { Remove-Item $scriptLog -Force }
Log-Write "==== launch_poe.ps1 STARTED ===="
Log-Write "GamePath: $GamePath"
Log-Write "DllPath: $DllPath"
Log-Write "MaxWait: $MaxWaitMinutes min"

# Stop leftover Injectors
Get-Process -Name "Injector" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# ============================================================================
# Pre-flight checks
# ============================================================================
Write-Step "Pre-flight checks"

if (-not (Test-Path $GamePath)) { Write-Err "Game path not found: $GamePath"; exit 1 }
if (-not (Test-Path "$GamePath\PathOfExile.exe")) { Write-Err "Game client not found"; exit 1 }
if (-not (Test-Path $DllPath)) { Write-Err "DLL not found: $DllPath"; exit 1 }
if (-not (Test-Path $InjectorPath)) { Write-Err "Injector not found: $InjectorPath"; exit 1 }

$logsDir = "$GamePath\logs"
$archiveDir = "$logsDir\archive"
New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null
$proxyLog = "$env:TEMP\proxy_v2_log.txt"
$exePath = "$GamePath\PathOfExile.exe"

Write-Ok "All paths verified"
Log-Write "EXE: $exePath"

# ============================================================================
# Phase 1: Archive current log
# ============================================================================
Write-Step "Phase 1: Archive current log"

if (Test-Path "$logsDir\Client.txt") {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $archivePath = "$archiveDir\Client_$timestamp.txt"
    Move-Item "$logsDir\Client.txt" $archivePath -Force
    Write-Ok "Archived to $(Split-Path $archivePath -Leaf)"
} else {
    Write-Wait "No existing log"
}
if (Test-Path $proxyLog) { Remove-Item $proxyLog -Force }

# ============================================================================
# Phase 2: Launch with --watch + --launch
# ============================================================================
Write-Step "Phase 2: Launch PathOfExile.exe via proxy"

if ($DryRun) { Write-Wait "DRY RUN"; exit 0 }

# Start --watch in background (catches self-restart of PathOfExile.exe)
# IMPORTANT: redirect output to avoid Start-Process blocking on pipe
Log-Write "Starting watch mode..."
$watchLog = "$env:TEMP\watch_output.log"
if (Test-Path $watchLog) { Remove-Item $watchLog -Force }
$watchErrLog = "$env:TEMP\watch_error.log"
if (Test-Path $watchErrLog) { Remove-Item $watchErrLog -Force }

$watchProc = Start-Process -FilePath $InjectorPath `
    -ArgumentList @("--watch","PathOfExile.exe",$DllPath) `
    -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $watchLog `
    -RedirectStandardError $watchErrLog
Log-Write "Watch PID: $($watchProc.Id)"
Write-Ok "Watch started"

# Launch with --launch (CREATE_SUSPENDED + inject + resume)
# Use redirect too in case it blocks
Log-Write "Starting launcher..."
$launchOut = "$env:TEMP\launch_output.log"
if (Test-Path $launchOut) { Remove-Item $launchOut -Force }
$launchErr = "$env:TEMP\launch_error.log"
if (Test-Path $launchErr) { Remove-Item $launchErr -Force }

$launchProc = Start-Process -FilePath $InjectorPath `
    -ArgumentList @("--launch",$exePath,"--dll",$DllPath) `
    -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $launchOut `
    -RedirectStandardError $launchErr
Log-Write "Launch PID: $($launchProc.Id)"

# Wait for launcher injector to exit (it exits after CreateProcess+ResumeThread)
Log-Write "Waiting for launcher injector to finish (max 30s)..."
$launcherWait = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $launcherWait) {
    if ($launchProc.HasExited) {
        Log-Write "Launcher injector exited (code $($launchProc.ExitCode))"
        break
    }
    Start-Sleep 1
}
if (-not $launchProc.HasExited) {
    Write-Wait "Launcher injector still running after 30s, continuing anyway"
}

# Show launcher output
if (Test-Path $launchOut) {
    $launchOutput = Get-Content $launchOut -ErrorAction SilentlyContinue
    if ($launchOutput) {
        Log-Write "Launcher stdout:"
        $launchOutput | ForEach-Object { Log-Write "  $_" }
    }
}
if (Test-Path $launchErr) {
    $launchErrOutput = Get-Content $launchErr -ErrorAction SilentlyContinue
    if ($launchErrOutput) {
        Log-Write "Launcher stderr:"
        $launchErrOutput | ForEach-Object { Log-Write "  $_" }
    }
}

# Wait for PathOfExile.exe process to appear
Log-Write "Waiting for PathOfExile.exe process (max 30s)..."
$procWait = (Get-Date).AddSeconds(30)
$launcher = $null
while ((Get-Date) -lt $procWait) {
    $launcher = Get-Process -Name "PathOfExile" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($launcher) { break }
    Start-Sleep 2
}
if (-not $launcher) { Write-Err "PathOfExile.exe not started"; exit 1 }
Write-Ok "PathOfExile.exe started, PID=$($launcher.Id)"

# ============================================================================
# Phase 3: Wait for launcher phase end
# ============================================================================
Write-Step "Phase 3: Wait for launcher phase end"
Write-Host "Waiting for: 'Finished checking files' or '[STARTUP] Loading Start'"
Write-Host "Max wait: $MaxWaitMinutes minutes"

$startTime = Get-Date
$maxWait = (Get-Date).AddMinutes($MaxWaitMinutes)
$phase3Done = $false
$lastLogSize = 0
$updateCount = 0
$pollIter = 0

while ((Get-Date) -lt $maxWait) {
    $pollIter++
    
    # Check process still alive
    $proc = Get-Process -Name "PathOfExile" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $proc) {
        # Self-restart may have just happened — wait briefly for new process
        Write-Wait "PathOfExile.exe disappeared — waiting for self-restart..."
        Start-Sleep 3
        $proc = Get-Process -Name "PathOfExile" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $proc) {
            Write-Err "PathOfExile.exe did not restart"
            break
        }
        Write-Ok "PathOfExile.exe restarted, PID=$($proc.Id)"
    }

    if (-not (Test-Path "$logsDir\Client.txt")) { Start-Sleep 3; continue }

    $logFile = Get-Item "$logsDir\Client.txt" -ErrorAction SilentlyContinue
    if (-not $logFile) { Start-Sleep 3; continue }

    # Log every 10s even if no size change
    if (($pollIter % 3) -eq 0) {
        $elapsed = [int]((Get-Date) - $startTime).TotalSeconds
        $mem = if ($proc) { [math]::Round($proc.WorkingSet64/1MB, 0) } else { 0 }
        Log-Write "[$elapsed s] PathOfExile alive (PID $($proc.Id), Mem ${mem}MB), log size $($logFile.Length)"
    }

    if ($logFile.Length -eq $lastLogSize) { Start-Sleep 3; continue }
    $lastLogSize = $logFile.Length

    $content = Get-Content "$logsDir\Client.txt" -ErrorAction SilentlyContinue
    if (-not $content) { Start-Sleep 3; continue }

    # Detect self-update cycles
    $newUpdateCount = ($content | Select-String -Pattern "Updating client executable" -SimpleMatch).Count
    if ($newUpdateCount -gt $updateCount) {
        $updateCount = $newUpdateCount
        Write-Wait "Self-update cycle #$updateCount detected"
    }

    # Check phase markers
    if (($content | Select-String -Pattern "Finished checking files" -SimpleMatch).Count -gt 0) {
        Write-Ok "Finished checking files (no update needed)"
        $phase3Done = $true
        break
    }
    if (($content | Select-String -Pattern "[STARTUP] Loading Start" -SimpleMatch).Count -gt 0) {
        Write-Ok "[STARTUP] Loading Start (update complete)"
        $phase3Done = $true
        break
    }

    Start-Sleep 3
}

if (-not $phase3Done) {
    Write-Err "Timeout waiting for launcher phase end"
    if ($watchProc) { Stop-Process -Id $watchProc.Id -Force -ErrorAction SilentlyContinue }
    exit 1
}

$elapsed = [int]((Get-Date) - $startTime).TotalSeconds
Write-Ok "Phase 3 done in ${elapsed}s"

# ============================================================================
# Phase 4: Wait for game login
# ============================================================================
Write-Step "Phase 4: Wait for game login"
Write-Host "Waiting for login / instance server connection (max 180s)..."

$gameStart = (Get-Date).AddSeconds(180)
$loginOk = $false
$lastTailLen = 0

while ((Get-Date) -lt $gameStart) {
    if (-not (Test-Path "$logsDir\Client.txt")) { Start-Sleep 3; continue }

    $tail = Get-Content "$logsDir\Client.txt" -Tail 10 -ErrorAction SilentlyContinue
    if (-not $tail) { Start-Sleep 3; continue }

    if (($tail | Select-String -Pattern "login.pathofexile.com" -SimpleMatch).Count -gt 0) {
        Write-Ok "Login activity detected"
        $loginOk = $true
        break
    }
    if (($tail | Select-String -Pattern "Connecting to instance server" -SimpleMatch).Count -gt 0) {
        Write-Ok "Instance server connecting"
        $loginOk = $true
        break
    }
    if (($tail | Select-String -Pattern "You have entered" -SimpleMatch).Count -gt 0) {
        Write-Ok "Player entered zone"
        $loginOk = $true
        break
    }
    if (($tail | Select-String -Pattern "Abnormal disconnect" -SimpleMatch).Count -gt 0) {
        Write-Wait "Abnormal disconnect detected (likely proxy IP change)"
        # Don't break — wait for user/manual restart
    }

    # Periodic status
    if ($tail.Count -ne $lastTailLen) {
        $lastTailLen = $tail.Count
        $lastLine = ($tail | Select-Object -Last 1) -replace '\[.*?\]\s*',''
        if ($lastLine.Length -gt 80) { $lastLine = $lastLine.Substring(0,80) + "..." }
        Log-Write "Last log line: $lastLine"
    }

    Start-Sleep 3
}

if (-not $loginOk) { Write-Wait "Login not auto-detected" }

# Stop watch
if ($watchProc) {
    Log-Write "Stopping watch mode (PID $($watchProc.Id))..."
    Stop-Process -Id $watchProc.Id -Force -ErrorAction SilentlyContinue
}

# ============================================================================
# Done
# ============================================================================
Write-Step "Done"

$proxyOk = 0
$proxyFail = 0
if (Test-Path $proxyLog) {
    $proxyContent = Get-Content $proxyLog -ErrorAction SilentlyContinue
    if ($proxyContent) {
        $proxyOk = ($proxyContent | Select-String -Pattern "PROXY_OK" -SimpleMatch).Count
        $proxyFail = ($proxyContent | Select-String -Pattern "PROXY_FAIL" -SimpleMatch).Count
    }
}

$game = Get-Process -Name "PathOfExile" -ErrorAction SilentlyContinue | Select-Object -First 1

Write-Host ""
Write-Host "Summary:" -ForegroundColor White
if ($game) { Write-Host "  Game PID:           $($game.Id)" }
Write-Host "  PROXY_OK events:    $proxyOk"
Write-Host "  PROXY_FAIL events:  $proxyFail"
Write-Host "  Script log:         $scriptLog"
Write-Host "  Proxy log:          $proxyLog"
Write-Host "  Game log:           $logsDir\Client.txt"
Write-Host ""
if ($proxyFail -eq 0 -and $proxyOk -gt 0) {
    Write-Ok "Game running through proxy"
} elseif ($proxyOk -eq 0) {
    Write-Wait "No proxy traffic yet"
} else {
    Write-Wait "Some failures detected"
}

Log-Write "==== launch_poe.ps1 FINISHED ===="
