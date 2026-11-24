<#
Rackhand installer for Windows (design 7.3.12, 7.3.7, D105). Run in an elevated PowerShell:

  & ([scriptblock]::Create((irm https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<X>/install.ps1))) `
      -Ticket <ticket> -Token <token> [-Monitor] [-Remote] [-Role <role>]

It checks rackhand-verify against the SHA-256 below, then has the verifier check every other file against the two pinned release
keys, and installs nothing until all of them pass. The release fills in the two values below. The dashboard's offline variant
runs it from the hub with `-ReleaseUrl https://<hub>:8443/release -SelfSigned`: the hub's HTTPS certificate is its own, so the
downloads don't check it; the SHA-256 and the signatures still do.

A managed machine also gets OpenSSH Server, the accounts `rackhand` and `rackhand-ai`, the dispatcher and its scripts, and the
SSH configuration of 7.3.7. A monitor machine gets none of that, and loses it if it had it.
#>
param(
    [string]$Ticket,
    [string]$Token,
    [switch]$Monitor,
    [switch]$Remote,
    [string]$Role = '',
    [string]$ReleaseUrl = 'https://github.com/StrangeMatterStudio/Rackhand/releases/download/v__VERSION__',
    [switch]$SelfSigned,
    [string]$Root = '',
    [string]$Data = '',
    # for tests: load the functions and run nothing
    [switch]$NoRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# where things go: C:\Program Files\Rackhand and C:\ProgramData\Rackhand (7.3.3); the fallbacks are for tests on another system
$ProgramFiles = if ([Environment]::GetFolderPath('ProgramFiles')) { [Environment]::GetFolderPath('ProgramFiles') } else { [IO.Path]::GetTempPath() }
$ProgramData = if ($env:ProgramData) { $env:ProgramData } elseif ([Environment]::GetFolderPath('CommonApplicationData')) { [Environment]::GetFolderPath('CommonApplicationData') } else { [IO.Path]::GetTempPath() }
if (-not $Root) { $Root = Join-Path $ProgramFiles 'Rackhand' }
if (-not $Data) { $Data = Join-Path $ProgramData 'Rackhand' }

$Version = '__VERSION__'
$VerifySha256 = '__VERIFY_SHA256__'
$Target = 'x86_64-pc-windows-gnu'
$SshdConfigPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ssh\sshd_config'
$BlockStart = '# BEGIN rackhand'
$BlockEnd = '# END rackhand'

# ---- what the installer does, one thing to a function, so a test can say what was and wasn't called ---------------------------

function Test-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Download([string]$Url, [string]$Path, [bool]$SkipCertificateCheck) {
    $params = @{ Uri = $Url; OutFile = $Path; UseBasicParsing = $true }
    if ($SkipCertificateCheck) {
        if ($PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
        else { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
    }
    Invoke-WebRequest @params
}

function Get-FileSha256([string]$Path) { return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLower() }

# `rackhand-verify <file> <signature>` exits 0 for a file signed by one of the two pinned release keys.
function Test-ReleaseFile([string]$Verifier, [string]$File, [string]$Signature) {
    & $Verifier $File $Signature *> $null
    return ($LASTEXITCODE -eq 0)
}

function Install-OpenSSHServer {
    $capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
    if ($capability.State -ne 'Installed') { Add-WindowsCapability -Online -Name $capability.Name | Out-Null }
    Set-Service -Name sshd -StartupType Automatic
}

function New-HubAccount([string]$Name) {
    if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) { return }
    # a password nobody knows: the account takes keys only (the SSH block turns passwords off for it)
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $password = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
    New-LocalUser -Name $Name -Password $password -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires -Description 'Rackhand' | Out-Null
    Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $Name
}

function Remove-HubAccount([string]$Name) {
    if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $Name }
}

function Get-SshdConfig { if (Test-Path -LiteralPath $SshdConfigPath) { return Get-Content -LiteralPath $SshdConfigPath -Raw } else { return '' } }
function Set-SshdConfigText([string]$Text) { Set-Content -LiteralPath $SshdConfigPath -Value $Text -NoNewline }

# Transcription of what `rackhand-ai` does, to a folder only administrators can read (7.3.7).
function Set-Transcription([string]$Directory) {
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name EnableTranscripting -Value 1 -Type DWord
    Set-ItemProperty -Path $key -Name OutputDirectory -Value $Directory -Type String
    Set-ItemProperty -Path $key -Name EnableInvocationHeader -Value 1 -Type DWord
}

# A folder only SYSTEM and Administrators may use, and the extra account if one is given.
function Protect-Directory([string]$Path, [string]$Also = '', [string]$AlsoRights = 'RX') {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    if ($Also) { $grants += "$($Also):(OI)(CI)$AlsoRights" }
    icacls $Path /inheritance:r /grant:r @grants | Out-Null
}

function Install-Files([string]$Work, [string]$Destination) {
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Copy-Item -LiteralPath (Join-Path $Work "rackhand-probe-$Target.exe") -Destination (Join-Path $Destination 'rackhand-probe.exe') -Force
    Expand-Archive -LiteralPath (Join-Path $Work 'rackhand-windows-scripts.zip') -DestinationPath $Destination -Force
}

# The join: prints `machine_id=`, `managed=` and `assistant=` lines.
function Invoke-Enroll([string]$Exe, [string[]]$Arguments) {
    $out = & $Exe enroll @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'the join failed' }
    $result = @{}
    foreach ($line in $out) { if ($line -match '^(?<k>[a-z_]+)=(?<v>.*)$') { $result[$Matches.k] = $Matches.v } }
    return $result
}

function Start-RackhandService([string]$Name) { Start-Service -Name $Name }
function Restart-Sshd { Restart-Service -Name sshd }

function Install-Service([string]$Name, [string]$Exe, [string]$Mode, [string]$Account) {
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) { Stop-Service -Name $Name -ErrorAction SilentlyContinue; sc.exe delete $Name | Out-Null; Start-Sleep -Seconds 1 }
    New-Service -Name $Name -BinaryPathName ('"{0}" service {1}' -f $Exe, $Mode) -DisplayName "Rackhand $Mode" -StartupType Automatic | Out-Null
    if ($Account) { sc.exe config $Name obj= $Account | Out-Null; sc.exe sidtype $Name unrestricted | Out-Null }
    sc.exe failure $Name reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null
}

# ---- the SSH configuration (7.3.7) ----------------------------------------------------------------------------------------

# The block sshd_config gets: keys from Rackhand's folder for the two accounts, no passwords, and for `rackhand` only the
# dispatcher. It goes before the default `Match Group administrators` block, whose own AuthorizedKeysFile would otherwise
# win (the first value of a keyword is the one used), and `rackhand-ai` could then log in with an administrator's keys.
function Get-RackhandBlock([string]$Root) {
    $dispatch = $Root.TrimEnd('\') + '\dispatch.ps1'
    return @(
        $BlockStart
        'Match User rackhand,rackhand-ai'
        '    AuthorizedKeysFile __PROGRAMDATA__/rackhand/keys/%u'
        '    PasswordAuthentication no'
        'Match User rackhand'
        "    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$dispatch`""
        $BlockEnd
    ) -join "`r`n"
}

# The configuration without any earlier Rackhand block.
function Remove-RackhandBlock([string]$Config) {
    $pattern = '(?ms)^' + [regex]::Escape($BlockStart) + '.*?^' + [regex]::Escape($BlockEnd) + '[ \t]*\r?\n?'
    return [regex]::Replace($Config, $pattern, '')
}

function Add-RackhandBlock([string]$Config, [string]$Root) {
    $clean = Remove-RackhandBlock $Config
    $block = (Get-RackhandBlock $Root) + "`r`n"
    $admin = [regex]::Match($clean, '(?mi)^[ \t]*Match[ \t]+Group[ \t]+administrators\b')
    if ($admin.Success) { return $clean.Insert($admin.Index, $block) }
    if ($clean.Length -gt 0 -and -not $clean.EndsWith("`n")) { $clean += "`r`n" }
    return $clean + $block
}

# ---- the install -----------------------------------------------------------------------------------------------------------

function Invoke-Install {
    if (-not $Ticket -or -not $Token) { throw 'usage: install.ps1 -Ticket <ticket> -Token <token> [-Monitor] [-Remote] [-Role <role>]' }
    if (-not (Test-Administrator)) { throw 'run it in an elevated PowerShell (as an administrator)' }
    $managed = -not $Monitor
    $work = Join-Path ([IO.Path]::GetTempPath()) ('rackhand-install-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        # 1. the verifier, checked against this script's own SHA-256 for it
        $verifier = Join-Path $work 'rackhand-verify.exe'
        Invoke-Download "$ReleaseUrl/rackhand-verify-$Target.exe" $verifier ([bool]$SelfSigned)
        if ((Get-FileSha256 $verifier) -ne $VerifySha256) { throw "rackhand-verify doesn't match this installer; nothing was installed" }

        # 2. everything else, checked against the pinned release keys
        foreach ($name in @("rackhand-probe-$Target.exe", 'rackhand-windows-scripts.zip')) {
            $file = Join-Path $work $name
            Invoke-Download "$ReleaseUrl/$name" $file ([bool]$SelfSigned)
            Invoke-Download "$ReleaseUrl/$name.minisig" "$file.minisig" ([bool]$SelfSigned)
            if (-not (Test-ReleaseFile $verifier $file "$file.minisig")) { throw "$name isn't signed by a pinned release key; nothing was installed" }
        }

        # 3. what a managed machine's accounts need
        if ($managed) { Install-OpenSSHServer }

        # 4. the files, laid out as 7.3.3 says: the program where only administrators write, the data where the probe's account can
        Install-Files $work $Root
        $probeAccount = 'NT SERVICE\RackhandProbe'
        Protect-Directory $Data
        Protect-Directory (Join-Path $Data 'probe') $probeAccount 'M'
        Protect-Directory (Join-Path $Data 'keys')
        $exe = Join-Path $Root 'rackhand-probe.exe'

        # 5. the join
        $arguments = @('--ticket', $Ticket, '--token', $Token)
        if ($Monitor) { $arguments += '--monitor' }
        if ($Remote) { $arguments += '--remote' }
        if ($Role) { $arguments += @('--role', $Role) }
        $joined = Invoke-Enroll $exe $arguments

        # 6. a managed machine's accounts, keys and SSH configuration (7.3.7)
        if ($managed) {
            New-HubAccount 'rackhand'
            if ($joined['assistant'] -eq 'true') {
                New-HubAccount 'rackhand-ai'
                Set-Transcription (Join-Path $Data 'transcripts')
            } else {
                Remove-HubAccount 'rackhand-ai'
            }
            Set-SshdConfigText (Add-RackhandBlock (Get-SshdConfig) $Root)
            Restart-Sshd
        } else {
            # a machine changing from managed to monitor loses the accounts, the keys and the configuration (7.3.12, D89)
            Remove-HubAccount 'rackhand'
            Remove-HubAccount 'rackhand-ai'
            Remove-Item -LiteralPath (Join-Path $Data 'keys') -Recurse -Force -ErrorAction SilentlyContinue
            $config = Get-SshdConfig
            if ($config) { Set-SshdConfigText (Remove-RackhandBlock $config) }
        }

        # 7. the services: the helper first (SYSTEM), then the probe (its own account)
        Install-Service 'RackhandHelper' $exe 'helper' ''
        Install-Service 'RackhandProbe' $exe 'probe' $probeAccount
        Start-RackhandService 'RackhandHelper'
        Start-RackhandService 'RackhandProbe'
        $access = if ($managed) { 'managed' } else { 'monitor' }
        Write-Output ("Rackhand: enrolled as machine {0} ({1})." -f $joined['machine_id'], $access)
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (-not $NoRun) {
    try { Invoke-Install } catch { [Console]::Error.WriteLine("rackhand install: $($_.Exception.Message)"); exit 1 }
}
