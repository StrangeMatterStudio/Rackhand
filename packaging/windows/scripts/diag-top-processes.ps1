# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param()
'By CPU time:'
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Id, ProcessName, CPU, @{ n = 'WorkingSetMB'; e = { [int]($_.WorkingSet64 / 1MB) } } | Format-Table -AutoSize
'By memory:'
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 20 Id, ProcessName, @{ n = 'WorkingSetMB'; e = { [int]($_.WorkingSet64 / 1MB) } }, CPU | Format-Table -AutoSize
