# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param()
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$up = (Get-Date) - $boot
'up {0} days, {1} hours, {2} minutes (since {3:o})' -f $up.Days, $up.Hours, $up.Minutes, $boot
