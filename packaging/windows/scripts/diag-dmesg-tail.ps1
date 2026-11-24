# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param()
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2 } -MaxEvents 200 -ErrorAction SilentlyContinue |
    ForEach-Object { '{0:o} {1} {2}: {3}' -f $_.TimeCreated, $_.LevelDisplayName, $_.ProviderName, ($_.Message -replace '\r?\n', ' ') }
