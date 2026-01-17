# FOXHOUND

FOXHOUND is a lightweight PowerShell orchestrator that runs scripted pipeline steps described in JSON manifests. It supports foreground (wait) and background (fire-and-forget) steps, captures stdout/stderr into per-step logs, and writes a timeline summary with per-step durations.

## Quick start
1. Put `foxhound.psm1` (module) and `FOXHOUND.ps1` (invoker) in:
   `c:\fullpath\`
2. From PowerShell:
```powershell
Import-Module 'c:\fullpath\foxhound.psm1' -Force
& 'c:\fullpath\FOXHOUND.ps1' -Manifest 'C:\path\to\manifest.json' -ProjectRoot 'C:\path\to\project'
```

## Manifest format
A manifest is a JSON object with a `steps` array. Minimal example:
```json
{
  "steps": [
    {
      "id": "start-programs",
      "script": "scripts\\start-programs.ps1",
      "args": ["-Profile", "prod"],
      "wait": true,
      "timeoutMs": 30000
    },
    {
      "id": "stop-streaming",
      "script": "%TOOLS%\\stop-streaming.bat",
      "wait": true,
      "timeoutMs": 60000,
      "retryCount": 2,
      "retryDelayMs": 500
    }
  ]
}
```

### Step fields
- `id` (string, required): unique identifier for the step (used for logs and timeline).
- `script` (string, required): path or command. Supports:
  - ~ expansion (home),
  - PowerShell `$env:VAR` and batch `%VAR%` expansion,
  - relative paths resolved against `ProjectRoot`.
- `args` (array[string], optional): argument tokens passed to scripts.
- `wait` (bool, optional): true to block until step completes; false runs as background job.
- `timeoutMs` (int, optional): timeout in milliseconds (default 30000).
- `retryCount` (int, optional): retry attempts on failure (default 0).
- `retryDelayMs` (int, optional): delay between retries in ms (default 200).
- `continueOnError` (bool, optional): continue pipeline after failure.
- `condition` (string, optional): PowerShell expression evaluated; skip step if false.

## Logs and timeline
- Logs are written under `ProjectRoot\logs\{manifestName}\`.
  - Per-step logs: `{stepId}.log`
  - Timeline summary: `timeline.log`
- Timeline entries: timestamp | step id | status | elapsed (seconds).
- If durations look off, check for:
  - scripts that spawn long-lived child processes,
  - steps run as background jobs,
  - multiple attempts being accumulated correctly.

## Behavior notes
- The module captures stdout/stderr via Start-Process redirect; exit codes and common error strings are used to determine success/failure.
- Background (non-wait) steps are launched with Start-Job; their logs are written asynchronously.
- The orchestrator prefers absolute paths; use `ProjectRoot` for relative script resolution.

## Troubleshooting
- Ensure `ProjectRoot` is writable and `logs` can be created.
- If a step times out, the orchestrator attempts to kill its process and marks the step failed.
- If output contains common error words (error|exception|failed|cannot|not found|invalid), it may be treated as failure even when exit code is zero — adjust scripts or wrap output if needed.
- To debug path resolution, call `Resolve-FoxhoundScriptPath` interactively and inspect the returned path.

## Example invocation (CI)
```powershell
$manifest = 'C:\repo\ci\deploy-manifest.json'
$projectRoot = 'C:\repo'
Import-Module 'c:\fullpath\foxhound.psm1' -Force
Invoke-FoxhoundManifest -ManifestPath $manifest -ProjectRoot $projectRoot
```

## License
Add your preferred license or mark for internal use.
