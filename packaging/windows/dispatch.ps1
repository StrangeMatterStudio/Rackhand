<#
Rackhand dispatcher for Windows (design 7.3.7, D53, D91). sshd runs it as the forced command of the `rackhand` account, so the only
thing a hub's key can do on the machine is what this accepts: `<script-name> <json-args>`, for a script that ships in
`scripts\` and has a schema in `schemas\`. The arguments must be exactly the schema's parameters, each of its type and matching
its pattern as a whole; a string starting with `-` is refused, as on Linux (E51). Nothing is run through a shell.

  rackhand dispatch exit codes: 126 not a request, 127 no such script, 2 arguments refused, 1 the script failed,
  otherwise the script's own.

Built-ins, taking JSON too: `job-start`, `job-status` and `job-clean` run a script as a scheduled task of its own, so that a
dropped connection doesn't stop it (detached steps), and report on it the way the Linux wrapper does.
#>
param(
    [string]$Root = (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Rackhand'),
    [string]$Command = $env:SSH_ORIGINAL_COMMAND,
    # where detached jobs keep their files
    [string]$JobsDir = (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Rackhand\jobs')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Dispatch([int]$Code, [string]$Message) {
    [Console]::Error.WriteLine("rackhand dispatch: $Message")
    exit $Code
}

# A schema's value for one argument, converted to what the script is given, or a reason it is refused.
function Test-Argument([string]$Name, $Spec, $Value) {
    $text = $null
    switch ($Spec.type) {
        'string' {
            if ($Value -isnot [string]) { return @{ Error = "'$Name' must be a string" } }
            $text = $Value
        }
        'int' {
            if ($Value -is [string]) {
                if ($Value -notmatch '^[0-9]{1,9}$') { return @{ Error = "'$Name' must be a whole number" } }
                $text = $Value
            } elseif ($Value -is [int] -or $Value -is [long]) {
                if ($Value -lt 0) { return @{ Error = "'$Name' must not be negative" } }
                $text = [string]$Value
            } else {
                return @{ Error = "'$Name' must be a whole number" }
            }
        }
        'bool' {
            if ($Value -isnot [bool]) { return @{ Error = "'$Name' must be true or false" } }
            return @{ Value = $Value }
        }
        default { return @{ Error = "'$Name' has a type this dispatcher doesn't know" } }
    }
    if ($text.Length -gt 4096) { return @{ Error = "'$Name' is too long" } }
    if ($text -match '[\x00-\x1f\x7f]') { return @{ Error = "'$Name' holds a control character" } }
    if ($text.StartsWith('-')) { return @{ Error = "'$Name' may not start with -" } }
    if (-not [regex]::IsMatch($text, "^(?:$($Spec.pattern))$")) { return @{ Error = "'$Name' doesn't match what the script accepts" } }
    if ($Spec.type -eq 'int') { return @{ Value = [int]$text } }
    return @{ Value = $text }
}

# Checks a script name and its JSON arguments against the schema; returns the script's path and the validated arguments.
function Get-Call([string]$Name, [string]$Json) {
    if ($Name -notmatch '^[a-z][a-z0-9-]{0,63}$') { Stop-Dispatch 126 'not a script name' }
    $script = Join-Path $Root "scripts/$Name.ps1"
    $schemaPath = Join-Path $Root "schemas/$Name.json"
    if (-not (Test-Path -LiteralPath $script -PathType Leaf) -or -not (Test-Path -LiteralPath $schemaPath -PathType Leaf)) {
        Stop-Dispatch 127 "no such script: $Name"
    }
    try { $schema = Get-Content -LiteralPath $schemaPath -Raw | ConvertFrom-Json } catch { Stop-Dispatch 127 "the schema of $Name can't be read" }
    $given = [ordered]@{}
    if ($Json.Trim().Length -gt 0) {
        try { $parsed = $Json | ConvertFrom-Json } catch { Stop-Dispatch 2 'the arguments are not JSON' }
        if ($parsed -isnot [System.Management.Automation.PSCustomObject]) { Stop-Dispatch 2 'the arguments are not a JSON object' }
        foreach ($p in $parsed.PSObject.Properties) { $given[$p.Name] = $p.Value }
    }
    $wanted = @($schema.params.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($key in $given.Keys) {
        if ($wanted -notcontains $key) { Stop-Dispatch 2 "no such argument: $key" }
    }
    $call = [ordered]@{}
    foreach ($name in $wanted) {
        if (-not $given.Contains($name)) { Stop-Dispatch 2 "missing argument: $name" }
        $checked = Test-Argument $name $schema.params.$name $given[$name]
        if ($checked.ContainsKey('Error')) { Stop-Dispatch 2 $checked.Error }
        $call[$name] = $checked.Value
    }
    return @{ Script = $script; Arguments = $call; Name = $Name }
}

function Invoke-Call($Call) {
    $arguments = $Call.Arguments
    $global:LASTEXITCODE = 0
    try {
        $output = & $Call.Script @arguments 2>&1 | Out-String -Width 220
    } catch {
        [Console]::Error.WriteLine("rackhand dispatch: $($Call.Name) failed: $($_.Exception.Message)")
        exit 1
    }
    [Console]::Out.Write($output)
    if ($global:LASTEXITCODE -ne 0) { exit $global:LASTEXITCODE }
    exit 0
}

# ---- detached jobs ---------------------------------------------------------------------------------------------------------

function Get-JobDirectory([string]$Job) {
    if ($Job -notmatch '^[A-Za-z0-9-]{1,64}/[A-Za-z0-9-]{1,64}$') { Stop-Dispatch 2 'not a job reference' }
    return Join-Path $JobsDir ($Job -replace '/', '_')
}

function Read-JobJson([string]$Json) {
    try { $body = $Json | ConvertFrom-Json } catch { Stop-Dispatch 2 'the arguments are not JSON' }
    if ($body -isnot [System.Management.Automation.PSCustomObject]) { Stop-Dispatch 2 'the arguments are not a JSON object' }
    return $body
}

function Quote-Single([string]$Text) { return "'" + $Text.Replace("'", "''") + "'" }

function Start-Job-Detached([string]$Json) {
    $body = Read-JobJson $Json
    $dir = Get-JobDirectory ([string]$body.job)
    $argsJson = if ($body.PSObject.Properties.Name -contains 'args') { $body.args | ConvertTo-Json -Compress } else { '{}' }
    $call = Get-Call ([string]$body.script) $argsJson
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $line = "$($call.Name) $argsJson"
    $runner = @(
        "& $(Quote-Single $PSCommandPath) -Root $(Quote-Single $Root) -JobsDir $(Quote-Single $JobsDir) -Command $(Quote-Single $line) *> $(Quote-Single (Join-Path $dir 'out.txt'))"
        "Set-Content -LiteralPath $(Quote-Single (Join-Path $dir 'exit.txt')) -Value `$LASTEXITCODE"
    ) -join "`r`n"
    Set-Content -LiteralPath (Join-Path $dir 'run.ps1') -Value $runner
    $name = 'Rackhand-' + ([string]$body.job -replace '/', '_')
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $dir 'run.ps1') + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $name
    exit 0
}

function Get-JobStatus([string]$Json) {
    $body = Read-JobJson $Json
    $dir = Get-JobDirectory ([string]$body.job)
    $offset = [long]$body.offset
    $state = 'unknown'; $exit = $null; $text = ''; $next = $offset
    if (Test-Path -LiteralPath $dir) {
        $outFile = Join-Path $dir 'out.txt'
        $exitFile = Join-Path $dir 'exit.txt'
        if (Test-Path -LiteralPath $exitFile) {
            $state = 'exited'
            $exit = [int](Get-Content -LiteralPath $exitFile -Raw).Trim()
        } else {
            $state = 'running'
        }
        if (Test-Path -LiteralPath $outFile) {
            $bytes = [IO.File]::ReadAllBytes($outFile)
            if ($offset -lt $bytes.Length) {
                $take = [Math]::Min(65536, $bytes.Length - $offset)
                $text = [Text.Encoding]::UTF8.GetString($bytes, [int]$offset, [int]$take)
                $next = $offset + $take
            }
        }
    }
    [Console]::Out.Write((@{ state = $state; exit_code = $exit; output = $text; next_offset = $next } | ConvertTo-Json -Compress))
    exit 0
}

function Remove-Job-Detached([string]$Json) {
    $body = Read-JobJson $Json
    $dir = Get-JobDirectory ([string]$body.job)
    $name = 'Rackhand-' + ([string]$body.job -replace '/', '_')
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    exit 0
}

# ---- the request -------------------------------------------------------------------------------------------------------------

if ([string]::IsNullOrWhiteSpace($Command)) { Stop-Dispatch 126 'no command' }
if ($Command.Length -gt 8192 -or $Command -match '[\x00-\x08\x0a-\x1f\x7f]') { Stop-Dispatch 126 'not a request' }
if ($Command.Trim() -notmatch '^(?<name>[a-z][a-z0-9-]{0,63})(?:\s+(?<json>\{.*\}))?$') { Stop-Dispatch 126 'expected <script-name> <json-args>' }
$requestedName = $Matches['name']
$requestedJson = if ($Matches.ContainsKey('json')) { $Matches['json'] } else { '' }

switch ($requestedName) {
    'job-start' { Start-Job-Detached $requestedJson }
    'job-status' { Get-JobStatus $requestedJson }
    'job-clean' { Remove-Job-Detached $requestedJson }
    default { Invoke-Call (Get-Call $requestedName $requestedJson) }
}
