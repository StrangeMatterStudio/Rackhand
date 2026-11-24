# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param()
Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' } |
    Format-Table DriveLetter, FileSystemLabel, FileSystem, @{ n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB, 1) } }, @{ n = 'FreeGB'; e = { [math]::Round($_.SizeRemaining / 1GB, 1) } }, HealthStatus -AutoSize
