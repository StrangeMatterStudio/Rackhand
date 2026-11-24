# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param([string]$url)
$r = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -TimeoutSec 20
'{0} {1}' -f [int]$r.StatusCode, $r.StatusDescription
$r.Headers.GetEnumerator() | Sort-Object Key | ForEach-Object { '{0}: {1}' -f $_.Key, ($_.Value -join ', ') }
