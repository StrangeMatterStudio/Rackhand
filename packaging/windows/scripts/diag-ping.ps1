# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param([string]$target)
Test-Connection -ComputerName $target -Count 4 | Format-Table Address, Latency, Status -AutoSize
