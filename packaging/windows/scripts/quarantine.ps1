# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param([string]$hubs, [int]$quicPort)
# Cuts the machine off from everything but the hub (7.5.6): Windows Firewall blocks both directions except DHCP, the probe's QUIC
# to the hub, and the hub's SSH and ping. What the profiles were is saved first, and `quarantine-release` puts it back.

$Group = 'RackhandQuarantine'
$SavedPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Rackhand\quarantine.json'

# The rules that stay open, as data. The firewall keeps state, so what the machine starts to the hub is answered, and what the hub
# starts to SSH and ping is answered; nothing else is let through in either direction.
function New-QuarantineRuleSet([string[]]$Hubs, [int]$QuicPort) {
    $rules = @(
        [pscustomobject]@{ Name = 'DHCP out'; Direction = 'Outbound'; Protocol = 'UDP'; LocalPort = '68'; RemotePort = '67'; RemoteAddress = 'Any' }
        [pscustomobject]@{ Name = 'DHCP in'; Direction = 'Inbound'; Protocol = 'UDP'; LocalPort = '68'; RemotePort = '67'; RemoteAddress = 'Any' }
        [pscustomobject]@{ Name = 'probe to the hub'; Direction = 'Outbound'; Protocol = 'UDP'; LocalPort = 'Any'; RemotePort = [string]$QuicPort; RemoteAddress = ($Hubs -join ',') }
        [pscustomobject]@{ Name = 'hub SSH'; Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = '22'; RemotePort = 'Any'; RemoteAddress = ($Hubs -join ',') }
        [pscustomobject]@{ Name = 'hub ping'; Direction = 'Inbound'; Protocol = 'ICMPv4'; LocalPort = 'Any'; RemotePort = 'Any'; RemoteAddress = ($Hubs -join ',') }
    )
    return $rules
}

function Enable-Quarantine([string[]]$Hubs, [int]$QuicPort) {
    # what was there is saved once: a second call (a retry) keeps the first record
    if (-not (Test-Path -LiteralPath $SavedPath)) {
        $profiles = Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Enabled = [string]$_.Enabled; DefaultInboundAction = [string]$_.DefaultInboundAction; DefaultOutboundAction = [string]$_.DefaultOutboundAction } }
        New-Item -ItemType Directory -Force -Path (Split-Path $SavedPath) | Out-Null
        $profiles | ConvertTo-Json | Set-Content -LiteralPath $SavedPath
    }
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    foreach ($r in (New-QuarantineRuleSet $Hubs $QuicPort)) {
        $spec = @{ DisplayName = "Rackhand quarantine: $($r.Name)"; Group = $Group; Direction = $r.Direction; Action = 'Allow'; Protocol = $r.Protocol; Profile = 'Any' }
        if ($r.LocalPort -ne 'Any') { $spec.LocalPort = $r.LocalPort }
        if ($r.RemotePort -ne 'Any') { $spec.RemotePort = $r.RemotePort }
        if ($r.RemoteAddress -ne 'Any') { $spec.RemoteAddress = $r.RemoteAddress.Split(',') }
        if ($r.Protocol -eq 'ICMPv4') { $spec.IcmpType = '8' }
        New-NetFirewallRule @spec | Out-Null
    }
    Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
    'quarantined'
}

if ($MyInvocation.InvocationName -ne '.') {
    Enable-Quarantine ($hubs.Split(',')) $quicPort
}
