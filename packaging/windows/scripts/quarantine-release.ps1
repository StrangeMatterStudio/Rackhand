# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param()
# Puts back exactly what quarantine saved, and removes only the rules it made (7.5.6).
$Group = 'RackhandQuarantine'
$SavedPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Rackhand\quarantine.json'
if (-not (Test-Path -LiteralPath $SavedPath)) { 'not quarantined'; exit 0 }
$saved = Get-Content -LiteralPath $SavedPath -Raw | ConvertFrom-Json
Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
foreach ($p in @($saved)) {
    Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled -DefaultInboundAction $p.DefaultInboundAction -DefaultOutboundAction $p.DefaultOutboundAction
}
Remove-Item -LiteralPath $SavedPath -Force
'released'
