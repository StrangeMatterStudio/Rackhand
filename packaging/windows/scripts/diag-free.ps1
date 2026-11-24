# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param()
Get-CimInstance Win32_OperatingSystem | Select-Object @{ n = 'TotalMB'; e = { [int]($_.TotalVisibleMemorySize / 1KB) } }, @{ n = 'FreeMB'; e = { [int]($_.FreePhysicalMemory / 1KB) } } | Format-List
