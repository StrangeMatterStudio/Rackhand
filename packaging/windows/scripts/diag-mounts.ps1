# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param()
Get-Volume | Format-Table DriveLetter, FileSystemLabel, FileSystem, DriveType, @{ n = 'Path'; e = { $_.Path } } -AutoSize
