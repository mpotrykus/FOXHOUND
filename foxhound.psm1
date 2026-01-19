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

    # record current run context so helpers can write/read artifacts/data
    $script:CurrentProjectRoot = $ProjectRoot
    $script:CurrentManifestName = $manifestName

    # Initialize the in-memory ExecutionContext.Steps so Set-StepData can attach data
    Initialize-FoxhoundExecutionContext

    # Per-step config (generateArtifact flag defaults to $true)
    if (-not $script:FoxhoundStepConfig) { $script:FoxhoundStepConfig = @{} }

    # Build step map
    # preserve manifest order for scheduling
    $stepsById = [ordered]@{ }
    foreach ($s in $manifest.steps) {
        $stepsById[$s.id] = $s
        # Normalize dependsOn to array
        if (-not ($s.PSObject.Properties.Name -contains 'dependsOn')) {
            $s | Add-Member -NotePropertyName dependsOn -NotePropertyValue @() -Force
        } elseif ($s.dependsOn -and -not ($s.dependsOn -is [System.Array])) {
            $s.dependsOn = @($s.dependsOn)
        }

        # Normalize generateArtifact flag (default true) and register in script-level lookup
        if (-not ($s.PSObject.Properties.Name -contains 'generateArtifact')) {
            $s | Add-Member -NotePropertyName generateArtifact -NotePropertyValue $true -Force
        } else {
            # coerce to boolean
            try { $s.generateArtifact = [bool]$s.generateArtifact } catch { $s.generateArtifact = $true }
        }
        $script:FoxhoundStepConfig[$s.id] = $s.generateArtifact

        # Normalize artifactPath -> artifactPaths (allow single string or array). Ensure artifactPaths is always an array.
        if ($s.PSObject.Properties.Name -contains 'artifactPaths') {
            if ($s.artifactPaths -and -not ($s.artifactPaths -is [System.Array])) {
                $s.artifactPaths = @($s.artifactPaths)
            }
        } else {
            $s | Add-Member -NotePropertyName artifactPaths -NotePropertyValue @() -Force
        }
    }

    # Status map: Pending, Running, Success, Failed, Skipped
    $statuses = @{
    }
    foreach ($id in $stepsById.Keys) { $statuses[$id] = 'Pending' }

    # Track steps that have had a terminal timeline entry emitted (to avoid duplicate final entries)
    if (-not $script:FoxhoundCompleted) { $script:FoxhoundCompleted = @{} }

    # Active jobs mapping job.Id -> stepId
    $activeJobs = @{ }

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

    # Print a single ExecutionContext snapshot now that the run is finished.
    $execJson = $ExecutionContext.Steps['check-display'].Data.Name | ConvertTo-Json -Depth 10 -ErrorAction Stop
    Write-Host $execJson
   
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

    # Emit run artifact at the end of manifest execution
    Send-RunArtifact -StepsById $stepsById -Statuses $statuses -ProjectRoot $ProjectRoot -ManifestName $manifestName | Out-Null
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
            $ActualCommand = "Start-Process -FilePath `"$ScriptPath`""
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

                # record an initial entry so conditions can see that step started async
                Set-StepData -StepId $StepId -Data $null -Output @() -ErrLines @() -Combined "" -ExitCode $proc.Id -Status 'STARTED-ASYNC' | Out-Null

                # Launch a detached PowerShell that imports FOXHOUND and runs a real monitor function
                $psExe = (Get-Command powershell).Source
                $monitorArgs = @(
                    '-NoProfile','-ExecutionPolicy','Bypass',
                    '-Command',
                    # Pass generateArtifact flag so the detached monitor knows whether to emit artifacts
                    "Import-Module `"$PSScriptRoot\foxhound.psm1`"; Start-FoxhoundMonitor -Pid $($proc.Id) -OutFile `"$outFile`" -ErrFile `"$errFile`" -StepId `"$StepId`" -ProjectRoot `"$ProjectRoot`" -ManifestName `"$ManifestName`" -GenerateArtifact $($([bool]$Step.generateArtifact))"
                )

                Start-Process -FilePath $psExe -ArgumentList $monitorArgs -WindowStyle Hidden -WorkingDirectory $ProjectRoot | Out-Null

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
                $output = @()
                $errLines = @()
                if (Test-Path $outFile) {
                    $output = Get-Content $outFile -ErrorAction SilentlyContinue
                    foreach ($l in $output) { Write-StepLog $StepId $l $ProjectRoot $ManifestName }
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

                $combinedText = (($output + $errLines) -join "`n").ToString()
                $errorPattern = '(?i)\b(error|exception|failed|cannot|not found|no such file|invalid|syntax is incorrect)\b'

                # Parse structured data if present
                $parsedData = ParseOutputToData -Output $output -ErrLines $errLines -CombinedText $combinedText

                if ($null -ne $exitCode -and $exitCode -ne 0) {
                    Write-StepLog $StepId "Process exited with code $exitCode." $ProjectRoot $ManifestName
                    $success = $false
                } elseif ($combinedText -and ($combinedText -match $errorPattern)) {
                    Write-StepLog $StepId "Detected error-like text in output; treating step as failed." $ProjectRoot $ManifestName
                    $success = $false
                } else {
                    $success = $true
                }

                # Store parsed output/data for other steps to reference
                $statusStr = if ($success) { 'SUCCESS' } else { 'FAIL' }
                Set-StepData -StepId $StepId -Data $parsedData -Output $output -ErrLines $errLines -Combined $combinedText -ExitCode $exitCode -Status $statusStr | Out-Null
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

# ---------------------------
# Async monitor as a real function (no string script)
# ---------------------------
function Start-FoxhoundMonitor {
    param(
        [Parameter(Mandatory=$true)][int]$Pid,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [Parameter(Mandatory=$true)][string]$ErrFile,
        [Parameter(Mandatory=$true)][string]$StepId,
        [Parameter(Mandatory=$true)][string]$ProjectRoot,
        [Parameter(Mandatory=$true)][string]$ManifestName,
        [Parameter(Mandatory=$false)][bool]$GenerateArtifact = $true
    )

    # Re-establish minimal context for artifact helpers
    $script:CurrentProjectRoot  = $ProjectRoot
    $script:CurrentManifestName = $ManifestName
    # Ensure the per-step config exists in this process and respect the passed flag
    if (-not $script:FoxhoundStepConfig) { $script:FoxhoundStepConfig = @{} }
    try { $script:FoxhoundStepConfig[$StepId] = [bool]$GenerateArtifact } catch {}

    # Hard safety cap so this monitor can never leak forever
    $maxSeconds = 1800  # 30 minutes
    $start = Get-Date

    try {
        # Wait for target process to exit or disappear
        while ($true) {
            $proc = $null
            try {
                $proc = Get-Process -Id $Pid -ErrorAction SilentlyContinue
            } catch {
                $proc = $null
            }

            if (-not $proc) { break }

            if ((Get-Date) - $start -gt [TimeSpan]::FromSeconds($maxSeconds)) {
                try { $proc.Kill() } catch { }
                break
            }

            Start-Sleep -Milliseconds 500
        }

        # Read captured output
        $output   = @()
        $errLines = @()

        if (Test-Path $OutFile) {
            $output = Get-Content $OutFile -ErrorAction SilentlyContinue
        }
        if (Test-Path $ErrFile) {
            $errLines = Get-Content $ErrFile -ErrorAction SilentlyContinue
        }

        # Try to get exit code if process still queryable
        $exitCode = $null
        try {
            $p = Get-Process -Id $Pid -ErrorAction SilentlyContinue
            if ($p) { $exitCode = $p.ExitCode }
        } catch {
            $exitCode = $null
        }

        $combinedText = (($output + $errLines) -join "`n").ToString()
        $errorPattern = '(?i)\b(error|exception|failed|cannot|not found|no such file|invalid|syntax is incorrect)\b'

        $parsedData = ParseOutputToData -Output $output -ErrLines $errLines -CombinedText $combinedText

        if ($null -ne $exitCode -and $exitCode -ne 0) {
            $success = $false
        } elseif ($combinedText -and ($combinedText -match $errorPattern)) {
            $success = $false
        } else {
            $success = $true
        }

        $statusStr = if ($success) { 'SUCCESS' } else { 'FAIL' }

        # Log lines into the step log
        foreach ($l in $output)   { Write-StepLog $StepId $l $ProjectRoot $ManifestName }
        foreach ($l in $errLines) { Write-StepLog $StepId $l $ProjectRoot $ManifestName }

        # Store parsed data and emit artifacts
        Set-StepData -StepId $StepId -Data $parsedData -Output $output -ErrLines $errLines -Combined $combinedText -ExitCode $exitCode -Status $statusStr | Out-Null

        # Emit final timeline entry if orchestrator didn't already
        if (-not $script:FoxhoundCompleted) { $script:FoxhoundCompleted = @{} }
        if (-not $script:FoxhoundCompleted.ContainsKey($StepId)) {
            Write-Timeline $StepId $statusStr $ProjectRoot $ManifestName
            $script:FoxhoundCompleted[$StepId] = $true
        }

    } catch {
        Write-StepLog $StepId "Monitor exception: $_" $ProjectRoot $ManifestName
        try {
            Set-StepData -StepId $StepId -Data $null -Output @() -ErrLines @("Monitor exception: $_") -Combined "" -ExitCode $null -Status 'FAIL' | Out-Null
            if (-not $script:FoxhoundCompleted) { $script:FoxhoundCompleted = @{} }
            if (-not $script:FoxhoundCompleted.ContainsKey($StepId)) {
                Write-Timeline $StepId "FAIL" $ProjectRoot $ManifestName
                $script:FoxhoundCompleted[$StepId] = $true
            }
        } catch { }
    }
    finally {
        # Best-effort cleanup of temp files
        try { if (Test-Path $OutFile) { Remove-Item $OutFile -ErrorAction SilentlyContinue } } catch { }
        try { if (Test-Path $ErrFile) { Remove-Item $ErrFile -ErrorAction SilentlyContinue } } catch { }
    }
}

# ---------------------------
# Execution context / step-data helpers
# ---------------------------
function Initialize-FoxhoundExecutionContext {
    # Ensure an in-memory steps store and expose it on $ExecutionContext as .Steps
    if (-not $script:FoxhoundSteps) { $script:FoxhoundSteps = @{} }
    try {
        if (-not $ExecutionContext.PSObject.Properties['Steps']) {
            $ExecutionContext | Add-Member -MemberType NoteProperty -Name Steps -Value $script:FoxhoundSteps -Force
        } else {
            $ExecutionContext.Steps = $script:FoxhoundSteps
        }
    } catch { }
}

function ParseOutputToData {
    param(
        [string[]]$Output,
        [string[]]$ErrLines,
        [string]$CombinedText
    )
    # Prefer explicit marker: lines like "FOXHOUND:DATA { ...json... }"
    $all = @()
    if ($Output) { $all += $Output }
    if ($ErrLines) { $all += $ErrLines }

    foreach ($l in $all) {
        if ($l -match '^\s*FOXHOUND:DATA\s+(.*)$') {
            $json = $Matches[1].Trim()
            try { return $json | ConvertFrom-Json -ErrorAction Stop } catch { break }
        }
    }

    # Try to parse the entire combined output as JSON (handles multi-line JSON)
    if ($CombinedText) {
        $combinedTrim = $CombinedText.Trim()
        if ($combinedTrim.StartsWith('{') -and $combinedTrim.EndsWith('}')) {
            try { return $combinedTrim | ConvertFrom-Json -ErrorAction Stop } catch {}
        }
    }

    # Try joining Output into a single JSON block (multi-line JSON printed to stdout)
    if ($Output) {
        $joined = ($Output -join "`n").Trim()
        if ($joined.StartsWith('{') -and $joined.EndsWith('}')) {
            try { return $joined | ConvertFrom-Json -ErrorAction Stop } catch {}
        }
    }

    # If no explicit marker, try to find a JSON object line (single-line JSON)
    foreach ($l in $all) {
        $t = $l.Trim()
        if ($t.StartsWith('{') -and $t.EndsWith('}')) {
            try { return $t | ConvertFrom-Json -ErrorAction Stop } catch { break }
        }
    }

    # Fallback: parse simple key=value lines into a hashtable
    $ht = @{}
    foreach ($l in $all) {
        if ($l -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.+)$') {
            $ht[$Matches[1]] = $Matches[2].Trim()
        }
    }
    if ($ht.Count -gt 0) { return $ht }

    return $null
}

function Set-StepData {
    param(
        [string]$StepId,
        $Data,
        [string[]]$Output,
        [string[]]$ErrLines,
        [string]$Combined,
        [int]$ExitCode,
        [string]$Status
    )
    if (-not $script:FoxhoundSteps) { $script:FoxhoundSteps = @{} }
    $entry = [pscustomobject]@{
        StepId    = $StepId
        Data      = $Data
        Output    = $Output
        ErrLines  = $ErrLines
        Combined  = $Combined
        ExitCode  = $ExitCode
        Status    = $Status
        Timestamp = (Get-Date).ToString("o")
    }
    $script:FoxhoundSteps[$StepId] = $entry
    try { $ExecutionContext.Steps = $script:FoxhoundSteps } catch {}

    # Do NOT write a per-step .data.json here; rely on .artifact.json as the canonical artifact.
    # Emit artifact for this step (if we can determine logs location)
    try {
        if ($script:CurrentProjectRoot -and $script:CurrentManifestName) {
            $shouldEmit = $true
            if ($script:FoxhoundStepConfig -and $script:FoxhoundStepConfig.ContainsKey($StepId)) {
                $shouldEmit = $script:FoxhoundStepConfig[$StepId]
            }
            if ($shouldEmit) {
                Send-StepArtifact -StepId $StepId -Entry $entry -ProjectRoot $script:CurrentProjectRoot -ManifestName $script:CurrentManifestName
            }
        }
    } catch { }

    return $entry
}

# ---------------------------
# Artifact helpers
# ---------------------------
function Get-LogsFolderPath {
    param(
        [string]$ProjectRoot,
        [string]$ManifestName
    )
    # Manifest root (ProjectRoot\<ManifestName>) or ProjectRoot when no manifest name
    if ($ManifestName) {
        $manifestRoot = Join-Path $ProjectRoot $ManifestName
    } else {
        $manifestRoot = $ProjectRoot
    }

    # Single manifest-level logs folder: <manifestRoot>\logs
    $logsFolder = Join-Path $manifestRoot "logs"
    if (-not (Test-Path $logsFolder)) { New-Item -ItemType Directory -Path $logsFolder -Force | Out-Null }
    return $logsFolder
}

function Get-ArtifactsFolderPath {
    param(
        [string]$ProjectRoot,
        [string]$ManifestName
    )
    if ($ManifestName) {
        $manifestRoot = Join-Path $ProjectRoot $ManifestName
    } else {
        $manifestRoot = $ProjectRoot
    }

    # Single manifest-level artifacts folder: <manifestRoot>\artifacts
    $artFolder = Join-Path $manifestRoot "artifacts"
    if (-not (Test-Path $artFolder)) { New-Item -ItemType Directory -Path $artFolder -Force | Out-Null }
    return $artFolder
}

function New-StepArtifactObject {
    param(
        [string]$StepId,
        [psobject]$Entry,
        [string]$ProjectRoot,
        [string]$ManifestName
    )

    # Manifest-level logs and artifacts
    $logsFolder = Get-LogsFolderPath -ProjectRoot $ProjectRoot -ManifestName $ManifestName
    $artifactsFolder = Get-ArtifactsFolderPath -ProjectRoot $ProjectRoot -ManifestName $ManifestName

    # Try to obtain duration from timeline accumulator if present
    $durationMs = $null
    if ($script:FoxhoundTimeline -and $script:FoxhoundTimeline.ContainsKey($StepId)) {
        try { $durationMs = [int]$script:FoxhoundTimeline[$StepId].AccumMs } catch {}
    }
    $startTime = $null
    if ($durationMs -ne $null) {
        try { $startTime = (Get-Date).AddMilliseconds(-$durationMs).ToString("o") } catch {}
    }

    $artifact = [pscustomobject]@{
        StepId       = $StepId
        Status       = $Entry.Status
        ExitCode     = $Entry.ExitCode
        Data         = $Entry.Data
        Output       = if ($Entry.Output) { $Entry.Output } else { $Entry.OutLines }
        ErrLines     = $Entry.ErrLines
        Combined     = $Entry.Combined
        DurationMs   = $durationMs
        StartTime    = $startTime
        LogPath      = (Join-Path $logsFolder ("$StepId.log"))
        DataPath     = (Join-Path $logsFolder ("$StepId.data.json"))
        ArtifactPath = (Join-Path $artifactsFolder ("$StepId.artifact.json"))
        Timestamp    = $Entry.Timestamp
    }
    return $artifact
}

function Send-StepArtifact {
    param(
        [string]$StepId,
        [psobject]$Entry,
        [string]$ProjectRoot,
        [string]$ManifestName
    )
    $artifactsFolder = Get-ArtifactsFolderPath -ProjectRoot $ProjectRoot -ManifestName $ManifestName
    $artifact = New-StepArtifactObject -StepId $StepId -Entry $Entry -ProjectRoot $ProjectRoot -ManifestName $ManifestName
    $artifactFile = Join-Path $artifactsFolder ("$StepId.artifact.json")
    try {
        $artifact | ConvertTo-Json -Depth 10 | Out-File -FilePath $artifactFile -Encoding UTF8 -Force
    } catch { }
    return $artifactFile
}

function New-RunArtifact {
    param(
        [hashtable]$StepsById,
        [hashtable]$Statuses,
        [string]$ProjectRoot,
        [string]$ManifestName
    )

    $nodes = @()
    foreach ($id in $StepsById.Keys) {
        $step = $StepsById[$id]
        $entry = $null
        if ($script:FoxhoundSteps -and $script:FoxhoundSteps.ContainsKey($id)) { $entry = $script:FoxhoundSteps[$id] }

        # Resolve declared artifactPaths (if any) into absolute paths; fall back to manifest artifacts/<id>.artifact.json
        $artifactPathsResolved = @()
        $manifestRoot = if ($ManifestName) { Join-Path $ProjectRoot $ManifestName } else { $ProjectRoot }
        $artifactsFolder = Get-ArtifactsFolderPath -ProjectRoot $ProjectRoot -ManifestName $ManifestName
        if ($step.artifactPaths) {
            $decl = if ($step.artifactPaths -is [System.Array]) { $step.artifactPaths } else { @($step.artifactPaths) }
            foreach ($p in $decl) {
                if (-not $p) { continue }
                $pstr = $p.ToString()
                if (-not [IO.Path]::IsPathRooted($pstr)) {
                    $cand = Join-Path $manifestRoot $pstr
                    if (-not (Test-Path $cand)) { $cand = Join-Path $artifactsFolder $pstr }
                } else {
                    $cand = $pstr
                }
                $artifactPathsResolved += $cand
            }
        }
        if (-not $artifactPathsResolved -or $artifactPathsResolved.Count -eq 0) {
            $artifactPathsResolved = @((Join-Path $artifactsFolder ("$id.artifact.json")))
        }


        $artifactNode = [pscustomobject]@{
            Id = $id
            Name = $step.name
            Status = if ($Statuses.ContainsKey($id)) { $Statuses[$id] } else { ($entry.Status -or 'Unknown') }
            DependsOn = if ($step.dependsOn) { $step.dependsOn } else { @() }
            ArtifactPaths = $artifactPathsResolved
            Data = if ($entry) { $entry.Data } else { $null }
        }
         $nodes += $artifactNode
    }

    $edges = @()
    foreach ($n in $nodes) {
        foreach ($d in $n.DependsOn) {
            $edges += [pscustomobject]@{ From = $d; To = $n.Id }
        }
    }

    $totalMs = 0
    foreach ($n in $nodes) {
        $dur = $null
        if ($script:FoxhoundTimeline -and $script:FoxhoundTimeline.ContainsKey($n.Id)) {
            try { $dur = [int]$script:FoxhoundTimeline[$n.Id].AccumMs } catch {}
        }
        if ($dur) { $totalMs += $dur }
    }

    $artifact = [pscustomobject]@{
        Manifest = $ManifestName
        ProjectRoot = $ProjectRoot
        Nodes = $nodes
        Edges = $edges
        TotalDurationMs = $totalMs
        GeneratedAt = (Get-Date).ToString("o")
    }
    return $artifact
}

function Send-RunArtifact {
    param(
        [hashtable]$StepsById,
        [hashtable]$Statuses,
        [string]$ProjectRoot,
        [string]$ManifestName
    )
    $artifactsFolder = Get-ArtifactsFolderPath -ProjectRoot $ProjectRoot -ManifestName $ManifestName
    $runArtifact = New-RunArtifact -StepsById $StepsById -Statuses $Statuses -ProjectRoot $ProjectRoot -ManifestName $ManifestName
    $artifactFile = Join-Path $artifactsFolder ("$ManifestName.artifact.json")
    try {
        $runArtifact | ConvertTo-Json -Depth 20 | Out-File -FilePath $artifactFile -Encoding UTF8 -Force
    } catch { }
    return $artifactFile
}

# ---------------------------
# Large task methods (scheduling etc.)
# ---------------------------
function Start-ReadySteps {
    param(
        [Parameter(Mandatory=$true)] [hashtable]$StepsById,
        [Parameter(Mandatory=$true)] [hashtable]$Statuses,
        [string]$ProjectRoot,
        [string]$ManifestName,
        [Parameter(Mandatory=$true)] [hashtable]$ActiveJobs
    )

    # Refresh any on-disk step data (from async monitors) so conditions see latest values
    Update-StepDataFromLogs -ProjectRoot $ProjectRoot -ManifestName $ManifestName

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

            # Record that we attempted to start something this iteration
            $startedAny = $true

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
            }
        }
    }

    return $startedAny
}

# Helper methods (logging, etc.)

function Write-StepLog {
    param (
        [string]$StepId,
        [string]$Message,
        [string]$ProjectRoot,
        [string]$ManifestName
    )

    # Write into manifest-level logs folder (files named <StepId>.log)
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

    # Run-level timeline stays in manifest-level logs folder
    $manifestLogsFolder = Get-LogsFolderPath -ProjectRoot $ProjectRoot -ManifestName $ManifestName
    $timelineFile = Join-Path $manifestLogsFolder "timeline.log"

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

    # Write separator to manifest-level timeline and all step logs in manifest logs folder
    $manifestLogsFolder = Get-LogsFolderPath -ProjectRoot $ProjectRoot -ManifestName $ManifestName

    $sep = "==================== RUN START: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') ===================="
    $timelineFile = Join-Path $manifestLogsFolder "timeline.log"
    $sep | Out-File -FilePath $timelineFile -Append -Encoding UTF8

    # Append to each step log file in manifest-level logs folder (exclude timeline.log)
    if (Test-Path $manifestLogsFolder) {
        Get-ChildItem -Path $manifestLogsFolder -Filter "*.log" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'timeline.log' } | ForEach-Object {
            $path = $_.FullName
            $sep | Out-File -FilePath $path -Append -Encoding UTF8
        }
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

# ---------------------------
# Helper: Refresh step-data from on-disk .data.json files
# ---------------------------
function Update-StepDataFromLogs {
    param(
        [string]$ProjectRoot,
        [string]$ManifestName
    )

    if (-not $ProjectRoot) { return }
    try {
        $manifestRoot = if ($ManifestName) { Join-Path $ProjectRoot $ManifestName } else { $ProjectRoot }
    } catch { return }
    if (-not (Test-Path $manifestRoot)) { return }

    if (-not $script:FoxhoundSteps) { $script:FoxhoundSteps = @{} }

    # Try to read manifest JSON (optional) to discover per-step artifactPath entries
    $manifestDef = $null
    try {
        $candidate = Get-ChildItem -Path $manifestRoot -Filter "$ManifestName*.json" -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($candidate) {
            $manifestDef = Get-Content $candidate.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        }
    } catch { $manifestDef = $null }

    # Read .artifact.json files from manifest-level artifacts folder (no .data.json usage)
    $manifestArtifacts = Join-Path $manifestRoot "artifacts"
    if (-not (Test-Path $manifestArtifacts)) { return }

    # Start with all artifact files in the artifacts folder
    $files = @()
    $files += (Get-ChildItem -Path $manifestArtifacts -Filter '*.artifact.json' -File -ErrorAction SilentlyContinue)

    # If manifest declares per-step artifactPaths, include those paths (allows custom locations)
    if ($manifestDef -and $manifestDef.steps) {
        foreach ($s in $manifestDef.steps) {
            # Support artifactPaths collection (or legacy artifactPath)
            $declaredPaths = @()
            if ($s.artifactPaths) {
                if ($s.artifactPaths -is [System.Array]) { $declaredPaths = $s.artifactPaths } else { $declaredPaths = @($s.artifactPaths) }
            } elseif ($s.artifactPath) {
                $declaredPaths = @($s.artifactPath)
            }
            foreach ($ap in $declaredPaths) {
                if (-not $ap) { continue }
                $apStr = $ap.ToString()
                if (-not [IO.Path]::IsPathRooted($apStr)) {
                    $candidatePath = Join-Path $manifestRoot $apStr
                    if (-not (Test-Path $candidatePath)) { $candidatePath = Join-Path $manifestArtifacts $apStr }
                } else {
                    $candidatePath = $apStr
                }
                if (Test-Path $candidatePath) {
                    $fi = Get-Item -LiteralPath $candidatePath -ErrorAction SilentlyContinue
                    if ($fi) { $files += $fi }
                }
            }
         }
     }

    # Unique files only
    $files = $files | Sort-Object -Property FullName -Unique

    if (-not $files) { return }

    foreach ($f in $files) {
        try {
            $raw = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
            if (-not $raw) { continue }
            $j = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($j -and $j.StepId) {
                $script:FoxhoundSteps[$j.StepId] = [pscustomobject]@{
                    StepId    = $j.StepId
                    Data      = $j.Data
                    Output    = if ($j.Output) { $j.Output } else { $j.OutLines }
                    ErrLines  = $j.ErrLines
                    Combined  = $j.Combined
                    ExitCode  = $j.ExitCode
                    Status    = $j.Status
                    Timestamp = $j.Timestamp
                }
            }
        } catch { continue }
    }

    try { $ExecutionContext.Steps = $script:FoxhoundSteps } catch {}
}
