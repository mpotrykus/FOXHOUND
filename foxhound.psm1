# FOXHOUND Core Module

# Main executors (top of file)

function Invoke-Manifest {
    param (
        [string]$ManifestPath,
        [string]$ProjectRoot
    )

    if (-not (Test-Path $ManifestPath)) {
        Stop-Run "Manifest file not found: $ManifestPath"
    }

    Write-RunSeparator -ProjectRoot $ProjectRoot -ManifestName ([IO.Path]::GetFileNameWithoutExtension($ManifestPath))

    $manifest = Get-Content $ManifestPath | ConvertFrom-Json
    $manifestName = [IO.Path]::GetFileNameWithoutExtension($ManifestPath)

    # Build step map
    # preserve manifest order for scheduling
    $stepsById = [ordered]@{
    }
    foreach ($s in $manifest.steps) {
        $stepsById[$s.id] = $s
        # Normalize dependsOn to array
        if (-not $s.PSObject.Properties.Name -contains 'dependsOn') {
            $s | Add-Member -NotePropertyName dependsOn -NotePropertyValue @() -Force
        } elseif ($s.dependsOn -and -not ($s.dependsOn -is [System.Array])) {
            $s.dependsOn = @($s.dependsOn)
        }
    }

    # Status map: Pending, Running, Success, Failed, Skipped
    $statuses = @{
    }
    foreach ($id in $stepsById.Keys) { $statuses[$id] = 'Pending' }

    # Track steps that have had a terminal timeline entry emitted (to avoid duplicate final entries)
    if (-not $script:FoxhoundCompleted) { $script:FoxhoundCompleted = @{} }

    # Active jobs mapping job.Id -> stepId
    $activeJobs = @{
    }

    # Main scheduling loop
    $maxIterations = ($stepsById.Keys.Count * 5) + 100
    $iter = 0
    while ($true) {
        $iter++
        if ($iter -gt $maxIterations) {
            Stop-Run  "Stuck scheduling steps (possible cycle in dependsOn). Statuses: $($statuses | Out-String)"
        }

        $started = Start-ReadySteps -StepsById $stepsById -Statuses $statuses -ProjectRoot $ProjectRoot -ManifestName $manifestName -ActiveJobs $activeJobs

        # Process completed jobs
        $completedJobs = Get-Job | Where-Object { $_.State -in @('Completed','Failed','Stopped','Blocked') }
        foreach ($j in $completedJobs) {
            if ($activeJobs.ContainsKey($j.Id)) {
                $stepId = $activeJobs[$j.Id]
                try {
                    $res = Receive-Job -Job $j -ErrorAction SilentlyContinue
                } catch {
                    $res = $null
                }
                Remove-Job -Job $j -ErrorAction SilentlyContinue
                $activeJobs.Remove($j.Id) | Out-Null

                if ($res -and ($res -is [psobject] -or $res -is [hashtable])) {
                    $resObj = [pscustomobject]$res
                    if ($resObj.Success) {
                        $statuses[$stepId] = 'Success'
                        $script:FoxhoundCompleted[$stepId] = $true
                    } else {
                        $statuses[$stepId] = 'Failed'
                        $script:FoxhoundCompleted[$stepId] = $true
                    }
                } else {
                    # If monitor job didn't return expected object, conservatively mark failed
                    $statuses[$stepId] = 'Failed'
                    $script:FoxhoundCompleted[$stepId] = $true
                }
            }
        }

        # If any pending or running remain?
        $pendingOrRunning = $false
        foreach ($v in $statuses.Values) {
            if ($v -in @('Pending','Running')) { $pendingOrRunning = $true; break }
        }
        if (-not $pendingOrRunning) { break }

        # If nothing started this iteration and there are running jobs, wait briefly for jobs to complete
        if (-not $started -and ($activeJobs.Count -gt 0)) {
            Start-Sleep -Milliseconds 200
            continue
        }

        # If nothing started, no active jobs, but still pending steps -> cycle or unsatisfiable deps
        if (-not $started -and ($activeJobs.Count -eq 0)) {
            # Mark remaining pending steps as skipped to break cycle, and Abort-Run 
            $remaining = $statuses.Keys | Where-Object { $statuses[$_] -eq 'Pending' }
            if ($remaining.Count -gt 0) {
                Stop-Run "Unable to make progress scheduling steps. Remaining pending steps: $($remaining -join ', '). Possible cycle in dependsOn."
            }
        }
    }

    # Final summary: log statuses
    foreach ($id in $statuses.Keys) {
        Write-StepLog $id "Final status: $($statuses[$id])" $ProjectRoot $manifestName
        # Skip writing a final timeline entry if a terminal entry was already emitted by the step/monitor
        if (-not $script:FoxhoundCompleted.ContainsKey($id)) {
            Write-Timeline $id $($statuses[$id].ToUpper()) $ProjectRoot $manifestName
        }
    }

    # If any non-skipped failed, throw to indicate overall failure
    $anyFailed = $false
    foreach ($s in $statuses.GetEnumerator()) {
        if ($s.Value -eq 'Failed') { $anyFailed = $true; break }
    }
    if ($anyFailed) { Stop-Run "One or more steps failed. See logs for details." }
}

# Keep Invoke-Step near top as a main executor
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

    Write-StepLog $StepId "Invoked step - $StepId" $ProjectRoot $ManifestName
    
    $StepArgsArray = if ($Step.args) { $Step.args } else { @() }

    try {
        # Evaluate condition
        $ConditionScript = if ($Step.condition) { [scriptblock]::Create($Step.condition) } else { { $true } }
        if (-not (& $ConditionScript)) {
            Write-StepLog $StepId "Condition evaluated to false. Skipping step." $ProjectRoot $ManifestName
            Write-Timeline $StepId "SKIPPED" $ProjectRoot $ManifestName
            return [pscustomobject]@{ StepId = $StepId; Success = $false; Message = 'SKIPPED' }
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

        Write-Host "FOXHOUND executing $StepId ($ActualCommand)"
        Write-StepLog $StepId "Executing '$ActualCommand'" $ProjectRoot $ManifestName
        
        $attempt = 0
        do {
            $attempt++
            Write-StepLog $StepId "Starting step attempt $attempt out of $RetryCount." $ProjectRoot $ManifestName

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

                if (-not $proc) {
                    Write-StepLog $StepId "Start-Process returned null for async start." $ProjectRoot $ManifestName
                    return [pscustomobject]@{ StepId = $StepId; Success = $false; Message = 'Failed to start process' }
                }

                Write-StepLog $StepId "Started asynchronously: Id=$($proc.Id)" $ProjectRoot $ManifestName

                # Build detached monitor script (written to temp file) so it can finish logging after foxhound exits
                $monitorPath = Join-Path ([IO.Path]::GetTempPath()) ("foxhound-monitor-$($StepId)-$([Guid]::NewGuid().ToString()).ps1")
                $monitorScript = New-MonitorScript

                $monitorScript | Out-File -FilePath $monitorPath -Encoding UTF8 -Force

                # Launch the detached monitor process (passes args as positional parameters)
                $psExe = (Get-Command powershell).Source
                Start-Process -FilePath $psExe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$monitorPath,$proc.Id,$outFile,$errFile,$StepId,$ProjectRoot,$ManifestName) -WindowStyle Hidden -WorkingDirectory $ProjectRoot | Out-Null

                # Record started-async and return immediate success so dependents run without waiting
                Write-Timeline $StepId "STARTED-ASYNC" $ProjectRoot $ManifestName
                return [pscustomobject]@{ StepId = $StepId; Success = $true; ExitCode = $proc.Id }
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
                $exitCode = $null
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
                    $success = $false
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
            return [pscustomobject]@{ StepId = $StepId; Success = $true; ExitCode = $exitCode }
        } else {
            Write-StepLog $StepId "Step failed." $ProjectRoot $ManifestName
            Write-Timeline $StepId "FAIL" $ProjectRoot $ManifestName
            return [pscustomobject]@{ StepId = $StepId; Success = $false; ExitCode = $exitCode }
        }

    } catch {
        Write-StepLog $StepId "Exception: $_" $ProjectRoot $ManifestName
        Write-Timeline $StepId "EXCEPTION" $ProjectRoot $ManifestName
        return [pscustomobject]@{ StepId = $StepId; Success = $false; Message = $_.ToString() }
    }
}

# Large task methods (scheduling etc.)

function Start-ReadySteps {
    param(
        [Parameter(Mandatory=$true)] [hashtable]$StepsById,
        [Parameter(Mandatory=$true)] [hashtable]$Statuses,
        [string]$ProjectRoot,
        [string]$ManifestName,
        [Parameter(Mandatory=$true)] [hashtable]$ActiveJobs
    )

    $startedAny = $false
    foreach ($id in $StepsById.Keys) {
        if ($Statuses[$id] -ne 'Pending') { continue }
        $step = $StepsById[$id]
        $deps = if ($step.dependsOn) { $step.dependsOn } else { @() }

        # Validate dependencies exist
        foreach ($d in $deps) {
            if (-not $StepsById.Contains($d)) {
                Stop-Run "Step '$id' dependsOn unknown step '$d'"
            }
        }

        # If any dependency failed or skipped, mark this as Skipped
        $depFailed = $false
        foreach ($d in $deps) {
            if ($Statuses[$d] -in @('Failed','Skipped')) { $depFailed = $true; break }
        }
        if ($depFailed) {
            Write-StepLog $id "Skipping step because a dependency failed or was skipped." $ProjectRoot $ManifestName
            Write-Timeline $id "SKIPPED" $ProjectRoot $ManifestName
            $Statuses[$id] = 'Skipped'
            $script:FoxhoundCompleted[$id] = $true
            $startedAny = $true
            continue
        }

        # If all dependencies succeeded (or no deps), start the step
        $allDepsDone = $true
        foreach ($d in $deps) {
            if ($Statuses[$d] -ne 'Success') { $allDepsDone = $false; break }
        }
        if ($allDepsDone) {
            # Start this step
            $inBg = -not ($step.wait)
            Write-StepLog $id "Scheduling step. Background=$inBg" $ProjectRoot $ManifestName
            $result = Invoke-Step -Step $step -ProjectRoot $ProjectRoot -ManifestName $ManifestName -InBackgroundJob:($inBg)

            if ($result -is [System.Management.Automation.Job]) {
                $job = $result
                $ActiveJobs[$job.Id] = $id
                $Statuses[$id] = 'Running'
            } elseif ($result -is [psobject] -or $result -is [hashtable]) {
                $resObj = [pscustomobject]$result
                if ($resObj.Success) {
                    $Statuses[$id] = 'Success'
                    $script:FoxhoundCompleted[$id] = $true
                } else {
                    $Statuses[$id] = 'Failed'
                    $script:FoxhoundCompleted[$id] = $true
                }
            } else {
                # Unknown return - mark failed
                $Statuses[$id] = 'Failed'
                $script:FoxhoundCompleted[$id] = $true
            }

            $startedAny = $true
        }
    }
    return $startedAny
}

# Helper methods (after large tasks)

function Get-LogsFolderPath {
    param(
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
    return $logsFolder
}

function New-MonitorScript {
    # returns the content of the detached monitor script (literal, no interpolation)
    return @'
param($processId,$outFile,$errFile,$StepId,$ProjectRoot,$ManifestName)

$logsRoot = Join-Path $ProjectRoot "logs"
if ($ManifestName) { $logsFolder = Join-Path $logsRoot $ManifestName } else { $logsFolder = $logsRoot }
if (-not (Test-Path $logsFolder)) { New-Item -ItemType Directory -Path $logsFolder -Force | Out-Null }
$stepLog = Join-Path $logsFolder ("$StepId.log")
$timeline = Join-Path $logsFolder "timeline.log"

$p = $null
try {
    $p = [System.Diagnostics.Process]::GetProcessById([int]$processId)
    $p.WaitForExit()
} catch { }

$outLines = @()
$errLines = @()
foreach ($f in @($outFile, $errFile)) {
    if (Test-Path $f) {
        try {
            $lines = Get-Content $f -ErrorAction SilentlyContinue
            foreach ($l in $lines) {
                $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
                "$ts | $l" | Out-File -FilePath $stepLog -Append -Encoding UTF8
            }
            if ($f -eq $outFile) { $outLines = $lines }
            if ($f -eq $errFile) { $errLines = $lines }
        } catch { }
        Remove-Item $f -ErrorAction SilentlyContinue
    }
}

$exitCode = $null
try { if ($p) { $exitCode = $p.ExitCode } } catch { $exitCode = $null }

$combinedText = (($outLines + $errLines) -join "`n").ToString()
$errorPattern = '(?i)\b(error|exception|failed|cannot|not found|no such file|invalid|syntax is incorrect)\b'

if ($null -ne $exitCode -and $exitCode -ne 0) {
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')) | $StepId | Process exited with code $exitCode" | Out-File -FilePath $timeline -Append -Encoding UTF8
} elseif ($combinedText -and ($combinedText -match $errorPattern)) {
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')) | $StepId | Detected error-like text in output; treating step as failed." | Out-File -FilePath $timeline -Append -Encoding UTF8
} else {
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')) | $StepId | SUCCESS" | Out-File -FilePath $timeline -Append -Encoding UTF8
}

# attempt to remove ourself
try { Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue } catch {}
'@
}

function Write-StepLog {
    param (
        [string]$StepId,
        [string]$Message,
        [string]$ProjectRoot,
        [string]$ManifestName
    )

    $logsFolder = Get-LogsFolderPath -ProjectRoot $ProjectRoot -ManifestName $ManifestName

    $logFile = Join-Path $logsFolder "${StepId}.log"
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    "$timestamp | $Message" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

function Write-Timeline {
    param (
        [string]$StepId,
        [string]$Message,
        [string]$ProjectRoot,
        [string]$ManifestName
    )

    $logsFolder = Get-LogsFolderPath -ProjectRoot $ProjectRoot -ManifestName $ManifestName

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

function Write-RunSeparator {
    param(
        [string]$ProjectRoot,
        [string]$ManifestName
    )

    $logsFolder = Get-LogsFolderPath -ProjectRoot $ProjectRoot -ManifestName $ManifestName

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

# Helper: Abort with plain message (writes to stderr and exits)
function Stop-Run {
    param(
        [string]$Message,
        [int]$ExitCode = 1
    )
    $prevColor = [Console]::ForegroundColor
    try {
        [Console]::ForegroundColor = [System.ConsoleColor]::Red
        [Console]::Error.WriteLine($Message)
    } finally {
        [Console]::ForegroundColor = $prevColor
    }
    exit $ExitCode
}
