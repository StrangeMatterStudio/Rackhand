# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param()
Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
    Format-Table LocalAddress, LocalPort, @{ n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }, OwningProcess -AutoSize
