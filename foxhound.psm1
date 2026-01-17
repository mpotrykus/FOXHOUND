# FOXHOUND Core Module

# ---------------------------
# Helper: Write debug to step log
# ---------------------------
function Write-StepLog {
    param (
        [string]$StepId,
        [string]$Message,
        [string]$ProjectRoot,
        [string]$ManifestName
    )
    $logsRoot = Join-Path $ProjectRoot "logs"
    if ($ManifestName) {
        $logsFolder = Join-Path $logsRoot $ManifestName
    } else {
        $logsFolder = $logsRoot
    }
    if (-not (Test-Path $logsFolder)) { New-Item -ItemType Directory -Path $logsFolder -Force | Out-Null }

    $logFile = Join-Path $logsFolder "${StepId}.log"
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    "$timestamp | $Message" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

# ---------------------------
# Helper: Track timeline
# ---------------------------
function Write-Timeline {
    param (
        [string]$StepId,
        [string]$Message,
        [string]$ProjectRoot,
        [string]$ManifestName
    )

    $logsRoot = Join-Path $ProjectRoot "logs"
    if ($ManifestName) {
        $logsFolder = Join-Path $logsRoot $ManifestName
    } else {
        $logsFolder = $logsRoot
    }
    if (-not (Test-Path $logsFolder)) { New-Item -ItemType Directory -Path $logsFolder -Force | Out-Null }

    $timelineFile = Join-Path $logsFolder "timeline.log"
    $now = Get-Date
    $timestamp = $now.ToString("yyyy-MM-dd HH:mm:ss.fff")

    if (-not $script:FoxhoundTimeline) { $script:FoxhoundTimeline = @{} }

    switch ($Message) {
        'START' {
            if (-not $script:FoxhoundTimeline.ContainsKey($StepId)) {
                $script:FoxhoundTimeline[$StepId] = @{ AccumMs = 0; CurrentStart = $now }
            } else {
                $script:FoxhoundTimeline[$StepId].CurrentStart = $now
            }
            return
        }
        default {
            $totalMs = 0
            if ($script:FoxhoundTimeline.ContainsKey($StepId)) {
                $entry = $script:FoxhoundTimeline[$StepId]
                $acc = 0
                try { $acc = [int]$entry.AccumMs } catch {}

                if ($entry.CurrentStart) {
                    # The step runner (Invoke-Step) already adds the attempt's elapsed to AccumMs.
                    # Prefer AccumMs when it's non-zero to avoid double-counting across places.
                    if ($acc -gt 0) {
                        $totalMs = $acc
                    } else {
                        $start = $entry.CurrentStart
                        $elapsed = $now - $start
                        $totalMs = [int]$elapsed.TotalMilliseconds
                    }
                } else {
                    $totalMs = $acc
                }
            }

            $seconds = [double]$totalMs / 1000
            $totalStr = ('{0:F2}s' -f $seconds)
            "$timestamp | $StepId | $Message | $totalStr" | Out-File -FilePath $timelineFile -Append -Encoding UTF8

            if ($script:FoxhoundTimeline.ContainsKey($StepId)) {
                $script:FoxhoundTimeline.Remove($StepId) | Out-Null
            }
        }
    }
}

# ---------------------------
# Helper: Write run start separator to logs
# ---------------------------
function Write-RunSeparator {
    param(
        [string]$ProjectRoot,
        [string]$ManifestName
    )

    $logsRoot = Join-Path $ProjectRoot "logs"
    if ($ManifestName) { $logsFolder = Join-Path $logsRoot $ManifestName } else { $logsFolder = $logsRoot }
    if (-not (Test-Path $logsFolder)) { New-Item -ItemType Directory -Path $logsFolder -Force | Out-Null }

    $sep = "==================== RUN START: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') ===================="
    $timelineFile = Join-Path $logsFolder "timeline.log"
    $sep | Out-File -FilePath $timelineFile -Append -Encoding UTF8

    # Also write a separator to each step log header file, excluding timeline.log
    Get-ChildItem -Path $logsFolder -Filter "*.log" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'timeline.log' } | ForEach-Object {
        $path = $_.FullName
        $sep | Out-File -FilePath $path -Append -Encoding UTF8
    }
}

# ---------------------------
# Helper: Convert args to a single quoted string
# ---------------------------
function ConvertTo-ArgumentString {
    param(
        [Parameter(Mandatory=$false, Position=0)]
        [Alias('Args')]
        [string[]]$StringArgs
    )

    if (-not $StringArgs) { return "" }

    $escaped = $StringArgs | ForEach-Object {
        $s = $_.ToString()
        '"' + ($s -replace '"', '""') + '"'
    }
    return ($escaped -join ' ')
}

# ---------------------------
# Helper: Resolve script path expressions ($env:FOO, %FOO%, ~, relative -> ProjectRoot)
# ---------------------------
function Resolve-ScriptPath {
    param(
        [Parameter(Mandatory=$true)] [string]$Path,
        [string]$ProjectRoot
    )

    if (-not $Path) { return $Path }

    # Trim surrounding quotes
    $p = $Path.Trim('"')

    # Expand ~ to home
    if ($p -like '~*') {
        $homePath = $env:USERPROFILE
        if ($p -eq '~') {
            $p = $homePath
        } else {
            # Remove leading "~", "~/" or "~\" and recompose using Join-Path to avoid quoting issues
            $rest = ($p -replace '^~[\\\/]?','')
            if ([string]::IsNullOrEmpty($rest)) {
                $p = $home
            } else {
                $p = Join-Path $homePath $rest
            }
        }
    }

    # Expand PowerShell-style $env:VAR
    $p = [regex]::Replace($p, '\$env:([A-Za-z_][A-Za-z0-9_]*)', {
        param($m)
        $val = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
        return $val
    })

    # Expand batch-style %VAR%
    $p = [regex]::Replace($p, '%([^%]+)%', {
        param($m)
        $val = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
        return $val
    })

    # If still not rooted and we have a ProjectRoot, make absolute
    try {
        if (-not [IO.Path]::IsPathRooted($p) -and $ProjectRoot) {
            $p = Join-Path $ProjectRoot $p
        }
    } catch { }

    return $p
}

# ---------------------------
# Run a single step
# ---------------------------
function Invoke-Step {
    param (
        [pscustomobject]$Step,
        [string]$ProjectRoot,
        [string]$ManifestName,
        [switch]$InBackgroundJob
        )
                
    $StepId = $Step.id

    $OrigScriptPath = $Step.script
    $ScriptPath = Resolve-ScriptPath -Path $OrigScriptPath -ProjectRoot $ProjectRoot

    $TimeoutMs = if ($Step.timeoutMs) { $Step.timeoutMs } else { 30000 }
    $RetryCount = if ($Step.retryCount) { $Step.retryCount } else { 0 }
    $RetryDelayMs = if ($Step.retryDelayMs) { $Step.retryDelayMs } else { 200 }
    $ContinueOnError = if ($Step.continueOnError) { $true } else { $false }

    Write-StepLog $StepId "Invoked step - $StepId" $ProjectRoot $ManifestName
    
    $StepArgsArray = if ($Step.args) { $Step.args } else { @() }

    try {
        # Evaluate condition
        $ConditionScript = if ($Step.condition) { [scriptblock]::Create($Step.condition) } else { { $true } }
            if (-not (& $ConditionScript)) {
            Write-StepLog $StepId "Condition evaluated to false. Skipping step." $ProjectRoot $ManifestName
            Write-Timeline $StepId "SKIPPED" $ProjectRoot $ManifestName
            return
        }

        # Prepare PS1 arg array for execution display
        $argArray = if ($Step.args) { $Step.args } else { @() }

        # For batch calls we want option/value pairs to be separate tokens (eg -WIDTH 1920)
        $tokens = @()
        if ($StepArgsArray) {
            foreach ($a in $StepArgsArray) {
                if ($a -match '^\s*-\S+\s+.+' ) {
                    $firstSpace = $a.IndexOf(' ')
                    $tokens += $a.Substring(0,$firstSpace)
                    $tokens += $a.Substring($firstSpace+1)
                } else {
                    $tokens += $a
                }
            }
        }

        # Determine extension and prepare accurate debug command
        $ext = [IO.Path]::GetExtension($ScriptPath).ToLower()

        if ($ext -eq ".ps1") {
            $psExec = if ($argArray.Count -gt 0) { $argArray | ForEach-Object { '"' + ($_ -replace '"','""') + '"' } -join ' ' } else { '' }
            $ActualCommand = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" $psExec"
        } elseif ($ext -eq ".bat" -or $ext -eq ".cmd") {
            # Build command inner string: script path plus tokens; quote only tokens that contain spaces
            $cmdPieces = @()
            foreach ($t in $tokens) {
                if ($t -match '\s') {
                    $cmdPieces += '"' + ($t -replace '"','""') + '"'
                } else {
                    $cmdPieces += $t
                }
            }
            # Quote the script path only if it contains spaces
            if ($ScriptPath -and $ScriptPath -match '\s') {
                $scriptPathInner = '"' + ($ScriptPath -replace '"','""') + '"'
            } else {
                $scriptPathInner = $ScriptPath
            }
            $cmdInner = if ($cmdPieces.Count -gt 0) { "$scriptPathInner $($cmdPieces -join ' ')" } else { $scriptPathInner }
            $ActualCommand = "cmd.exe /c `"$cmdInner`""
        } else {
            $ActualCommand = "Start-Job -FilePath `"$ScriptPath`""
        }

        Write-Host "FOXHOUND executing $StepId - $ActualCommand"
        Write-StepLog $StepId "Executing '$ActualCommand'" $ProjectRoot $ManifestName
        
        $attempt = 0
        do {
            $attempt++
            Write-StepLog $StepId "Starting step attempt $attempt/$RetryCount." $ProjectRoot $ManifestName

            if (-not $script:FoxhoundTimeline) { $script:FoxhoundTimeline = @{} }
            if (-not $script:FoxhoundTimeline.ContainsKey($StepId)) {
                $script:FoxhoundTimeline[$StepId] = @{ AccumMs = 0; CurrentStart = (Get-Date) }
            } else {
                $script:FoxhoundTimeline[$StepId].CurrentStart = (Get-Date)
            }

            Write-Timeline $StepId "START" $ProjectRoot $ManifestName

            # Run step for timeout handling
            # Use Start-Process with redirected stdout/stderr for reliable exit codes and output capture.
            $outFile = [IO.Path]::GetTempFileName()
            $errFile = [IO.Path]::GetTempFileName()
            $proc = $null
            $argArray = if ($Step.args) { $Step.args } else { @() }

            $isSta = [System.Threading.Thread]::CurrentThread.ApartmentState -eq 'STA'

            # Prepare Start-Process parameters for all cases
            $startParams = @{
                RedirectStandardOutput = $outFile
                RedirectStandardError  = $errFile
                PassThru               = $true
            }

            switch ($ext) {
                '.ps1' {
                    $startParams.FilePath     = (Get-Command powershell).Source
                    $startParams.ArgumentList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$ScriptPath) + $argArray
                }
                { ($_ -eq '.bat') -or ($_ -eq '.cmd') } {
                    # For '.bat' and '.cmd' we use cmd.exe /c <cmdInner>
                    $startParams.FilePath     = (Get-Command cmd.exe).Source
                    $startParams.ArgumentList = @('/c', $cmdInner)
                }
                default {
                    $startParams.FilePath = $ScriptPath
                }
            }

            if ($isSta -and $InBackgroundJob) {
                Write-StepLog $StepId "Starting $ext process in hidden window." $ProjectRoot $ManifestName
                $startParams.WindowStyle = 'Hidden'
            } else {
                $startParams.NoNewWindow = $true
            }

            $proc = Start-Process @startParams

            if ($InBackgroundJob) {
                if ($proc) {
                    Write-StepLog $StepId "Started asynchronously: Id=$($proc.Id)" $ProjectRoot $ManifestName
                } else {
                    Write-StepLog $StepId "Start-Process returned null for async start." $ProjectRoot $ManifestName
                }

                # Launch a background job to wait for the process, capture its output and append to the step logs
                if ($proc) {
                    $monitor = {
                        param($processId, $outFile, $errFile, $StepId, $ProjectRoot, $ManifestName)

                        # Prepare log folder
                        $logsRoot = Join-Path $ProjectRoot "logs"
                        if ($ManifestName) { $logsFolder = Join-Path $logsRoot $ManifestName } else { $logsFolder = $logsRoot }
                        if (-not (Test-Path $logsFolder)) { New-Item -ItemType Directory -Path $logsFolder -Force | Out-Null }
                        $stepLog = Join-Path $logsFolder ("$StepId.log")
                        $timeline = Join-Path $logsFolder "timeline.log"

                        try {
                            $p = [System.Diagnostics.Process]::GetProcessById([int]$processId)
                            $p.WaitForExit()
                        } catch { }

                        foreach ($f in @($outFile, $errFile)) {
                            if (Test-Path $f) {
                                try {
                                    $lines = Get-Content $f -ErrorAction SilentlyContinue
                                    foreach ($l in $lines) {
                                        $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
                                        "$ts | $l" | Out-File -FilePath $stepLog -Append -Encoding UTF8
                                    }
                                } catch { }
                                Remove-Item $f -ErrorAction SilentlyContinue
                            }
                        }

                        # Record that the async process finished (optional)
                        $ts2 = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
                        "$ts2 | $StepId | ASYNC-COMPLETE" | Out-File -FilePath $timeline -Append -Encoding UTF8
                    }

                    Start-Job -ScriptBlock $monitor -ArgumentList $proc.Id, $outFile, $errFile, $StepId, $ProjectRoot, $ManifestName | Out-Null
                }

                # Mark success for async start and record timeline then skip waiting/output handling
                $success = $true
                Write-Timeline $StepId "STARTED-ASYNC" $ProjectRoot $ManifestName
                
                return
            }

            # Wait for the process to finish (or time out)
            $waitMs = $TimeoutMs
            $poll = 100
            while ($proc -and $proc.HasExited -eq $false -and $waitMs -gt 0) {
                Start-Sleep -Milliseconds $poll
                $waitMs -= $poll
            }

            $endTime = Get-Date
            $start = $script:FoxhoundTimeline[$StepId].CurrentStart
            if ($start) {
                $elapsed = $endTime - $start
                $script:FoxhoundTimeline[$StepId].AccumMs += [int]$elapsed.TotalMilliseconds
            }

            if ($proc -and $proc.HasExited -eq $false) {
                # Timed out — kill process
                try { $proc.Kill() } catch { }
                Write-StepLog $StepId "Step timed out after $TimeoutMs ms." $ProjectRoot $ManifestName
                $success = $false
            } else {
                # Read and write captured output (store for inspection)
                $outLines = @()
                $errLines = @()
                if (Test-Path $outFile) {
                    $outLines = Get-Content $outFile -ErrorAction SilentlyContinue
                    foreach ($l in $outLines) { Write-StepLog $StepId $l $ProjectRoot $ManifestName }
                    Remove-Item $outFile -ErrorAction SilentlyContinue
                }
                if (Test-Path $errFile) {
                    $errLines = Get-Content $errFile -ErrorAction SilentlyContinue
                    foreach ($l in $errLines) { Write-StepLog $StepId $l $ProjectRoot $ManifestName }
                    Remove-Item $errFile -ErrorAction SilentlyContinue
                }

                # Inspect process exit code and scan output for error-like text to determine success.
                $exitCode = $null
                try { $exitCode = $proc.ExitCode } catch { $exitCode = $null }

                $combinedText = (($outLines + $errLines) -join "`n").ToString()
                $errorPattern = '(?i)\b(error|exception|failed|cannot|not found|no such file|invalid|syntax is incorrect)\b'

                if ($null -ne $exitCode -and $exitCode -ne 0) {
                    Write-StepLog $StepId "Process exited with code $exitCode." $ProjectRoot $ManifestName
                    $null -ne $exitCode
                } elseif ($combinedText -and ($combinedText -match $errorPattern)) {
                    Write-StepLog $StepId "Detected error-like text in output; treating step as failed." $ProjectRoot $ManifestName
                    $success = $false
                } else {
                    $success = $true
                }
            }

            if (-not $success -and $attempt -le $RetryCount) {
                Write-StepLog $StepId "Retrying in $RetryDelayMs ms..." $ProjectRoot $ManifestName
                Start-Sleep -Milliseconds $RetryDelayMs
            }

        } while (-not $success -and $attempt -le $RetryCount)

        if ($success) {
            Write-StepLog $StepId "Step completed successfully." $ProjectRoot $ManifestName
            Write-Timeline $StepId "SUCCESS" $ProjectRoot $ManifestName
        } elseif ($ContinueOnError) {
            Write-StepLog $StepId "Step failed but ContinueOnError=true. Continuing." $ProjectRoot $ManifestName
            Write-Timeline $StepId "FAIL-CONTINUE" $ProjectRoot $ManifestName
        } else {
            Write-StepLog $StepId "Step failed and ContinueOnError=false. Halting pipeline." $ProjectRoot $ManifestName
            Write-Timeline $StepId "FAIL" $ProjectRoot $ManifestName
            throw ([System.Exception]::new("Step $StepId failed."))
        }

    } catch {
        Write-StepLog $StepId "Exception: $_" $ProjectRoot $ManifestName
        Write-Timeline $StepId "EXCEPTION" $ProjectRoot $ManifestName
        if (-not $ContinueOnError) { throw $_ }
    }
}

# ---------------------------
# Run multiple steps from manifest
# ---------------------------
function Invoke-Manifest {
    param (
        [string]$ManifestPath,
        [string]$ProjectRoot
    )

    if (-not (Test-Path $ManifestPath)) {
        throw "Manifest file not found: $ManifestPath"
    }

    Write-RunSeparator -ProjectRoot $ProjectRoot -ManifestName ([IO.Path]::GetFileNameWithoutExtension($ManifestPath))

    $manifest = Get-Content $ManifestPath | ConvertFrom-Json
    $manifestName = [IO.Path]::GetFileNameWithoutExtension($ManifestPath)
    foreach ($step in $manifest.steps) {
        if ($step.wait) {
            Invoke-Step -Step $step -ProjectRoot $ProjectRoot -ManifestName $manifestName
        } else {
            Invoke-Step -Step $step -ProjectRoot $ProjectRoot -ManifestName $manifestName -InBackgroundJob
        }
    }
}
