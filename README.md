# Foxhound — PowerShell orchestration module

Foxhound is a lightweight PowerShell orchestration helper for running ordered/graph-based steps defined in a JSON manifest. It runs steps, enforces dependencies, collects logs/artifacts, supports background/async steps with detached monitors, and emits machine-readable artifacts summarizing the run.

## Highlights
- Declarative manifest-driven step execution
- Per-step timeouts, retries, and conditional execution
- Background (async) steps with detached monitoring
- Log and artifact collection into per-manifest folders

## Prerequisites
- Windows PowerShell (or PowerShell compatible environment)
- File system access to project folder for logs/artifacts

## Install / Load
From the module folder:
- Import the module in your session:
  powershell
  Import-Module 'c:\Users\mpotr\source\repos\foxhound\foxhound.psm1'

## Quick start
1. Create a manifest JSON (example):
{
  "steps": [
    { "id": "step1", "name": "Echo", "script": "scripts\\echo.ps1", "args": ["hello"] },
    { "id": "step2", "name": "Dependent", "script": "scripts\\dep.ps1", "dependsOn": ["step1"] }
  ]
}

2. Run the manifest:
  powershell
  Invoke-Manifest -ManifestPath 'c:\path\to\manifest.json' -ProjectRoot 'c:\path\to\project'

Notes:
- Steps default to generating artifacts; set `generateArtifact` to false to disable.
- Use `wait: true` in a step to force the orchestrator to wait (sync) rather than start async.

## Key functions (what to look for)
- Invoke-Manifest: main entry that schedules and runs steps.
- Invoke-Step: executes individual step scripts, enforces timeout/retries, produces step artifacts.
- Start-FoxhoundMonitor: detached monitor used for async/background steps to collect output and finalize artifact state.
- Set-StepData / Update-StepDataFromLogs: store and refresh per-step in-memory state from on-disk artifacts.
- Send-StepArtifact / Send-RunArtifact: write per-step and run-level artifact JSON into artifacts folder.

## Logs & Artifacts
- Manifest-level logs: <ManifestRoot>\logs\*.log and timeline.log
- Artifacts: <ManifestRoot>\artifacts\<stepId>.artifact.json and <ManifestName>.artifact.json
- The module also keeps an in-memory ExecutionContext.Steps snapshot for programmatic inspection.

## Troubleshooting
- "Manifest file not found" — check ManifestPath and file name.
- Cycles in dependencies — the orchestrator will detect stuck scheduling and abort; inspect timeline and statuses.
- Permission issues writing logs/artifacts — ensure process has write access to ProjectRoot.
- Async steps: detached monitors have a safety cap (30 minutes) and run a separate PowerShell instance; ensure the environment can launch child processes.

## Contributing / Notes
- This repository contains a single module file foxhound.psm1 implementing the engine.
- No license specified in this README — add a LICENSE file if needed.

## Usage (concise)

1. Load the module from the module folder:
   powershell
   Import-Module 'c:\Users\mpotr\source\repos\foxhound\foxhound.psm1'

2. Run a manifest (synchronous example):
   powershell
   Invoke-Manifest -ManifestPath 'c:\path\to\manifest.json' -ProjectRoot 'c:\path\to\project'

3. Useful flags:
   - Per-step: wait (force sync), generateArtifact (true/false), timeoutMs, retryCount.
   - Module-level: manifest maxParallelism (in manifest root).

4. Where outputs go:
   - Logs: <ProjectRoot>\<ManifestName>\logs\*.log and timeline.log
   - Artifacts: <ProjectRoot>\<ManifestName>\artifacts\<stepId>.artifact.json and <ManifestName>.artifact.json

## Example manifests

1) Simple linear manifest (two steps, step2 depends on step1)
```json
{
  "maxParallelism": 4,
  "steps": [
    {
      "id": "step1",
      "name": "Echo Hello",
      "script": "scripts\\echo.ps1",
      "args": [ "hello" ],
      "generateArtifact": true
    },
    {
      "id": "step2",
      "name": "Dependent step",
      "script": "scripts\\do-work.ps1",
      "dependsOn": [ "step1" ],
      "wait": true
    }
  ]
}
```

2) Background/async step that spawns a long-running process (monitored by Foxhound)
```json
{
  "steps": [
    {
      "id": "background",
      "name": "Start long task",
      "script": "scripts\\long-task.bat",
      "args": [ "-run" ],
      "wait": false,
      "generateArtifact": true
    },
    {
      "id": "followup",
      "name": "After background completes",
      "script": "scripts\\finalize.ps1",
      "dependsOn": [ "background" ],
      "wait": true
    }
  ]
}
```

3) Reusable imported manifests (template expansion)
Foxhound supports inlining/importing other manifests and expanding placeholders via the [`Inline-ImportsIntoManifest`](foxhound.psm1) helper (used by [`Invoke-Manifest`](foxhound.psm1)). This lets you centralize common step definitions and reuse them with different parameters.

Parent manifest (imports another manifest, adds prefix and parameters):
```json
{
  "name": "parent-pipeline",
  "version": "1.0",
  "steps": [
    {
      "id": "check-display",
      "name": "Display check",
      "script": "scripts\\echo.ps1",
      "args": ["parent-start"]
    }
  ],
  "imports": [
    {
      "path": "common/common-manifest.json",
      "prefix": "common",
      "with": {
        "NAME": "project-42",
        "RETRIES": 2
      }
    }
  ]
}
```

Imported manifest (common/common-manifest.json) showing placeholder usage:

```json
{
  "name": "common-steps",
  "version": "1.0",
  "steps": [
    {
      "id": "setup",
      "name": "Setup for ${NAME}",
      "script": "scripts\\setup.ps1",
      "args": ["--name", "${NAME}", "--retries", "${RETRIES}"]
    },
    {
      "id": "teardown",
      "name": "Teardown ${NAME}",
      "script": "scripts\\teardown.ps1"
    }
  ]
}
```

Notes / tips
- Use `wait: true` on steps you must block on; by default steps run backgrounded when possible to increase parallelism.
- Inspect timeline.log and per-step .log files for quick debugging; artifacts in the artifacts folder contain structured run/step data.
- If a step prints structured JSON, use the FOXHOUND:DATA marker or print a JSON object to stdout — the module will parse it into step Data.

