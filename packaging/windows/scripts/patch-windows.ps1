# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param([string]$phase)
# The Windows Update Agent (7.5.3): `scan` lists what is pending; `install` downloads and installs it, and says whether a reboot is
# needed, which the job's reboot step decides about (policy `auto_reboot` is false for Windows by default, D67).
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$found = $searcher.Search('IsInstalled=0 and IsHidden=0 and Type=''Software''')
'{0} updates pending' -f $found.Updates.Count
foreach ($u in $found.Updates) { '  {0}' -f $u.Title }
if ($phase -eq 'scan') { exit 0 }
if ($found.Updates.Count -eq 0) { 'reboot_required=false'; exit 0 }
$collection = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $found.Updates) { if (-not $u.InstallationBehavior.CanRequestUserInput) { [void]$collection.Add($u) } }
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $collection
[void]$downloader.Download()
$installer = $session.CreateUpdateInstaller()
$installer.Updates = $collection
$result = $installer.Install()
# 2 succeeded, 3 succeeded with errors, 4 failed, 5 aborted
'install result {0}' -f $result.ResultCode
'reboot_required={0}' -f ([string]$result.RebootRequired).ToLower()
if ($result.ResultCode -ne 2 -and $result.ResultCode -ne 3) { exit 1 }
exit 0
