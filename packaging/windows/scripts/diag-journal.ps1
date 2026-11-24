# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param([string]$unit, [string]$since, [int]$lines)
# `since` is a date, `today`, `yesterday`, or `N minutes|hours|days ago` (the schema's pattern)
function ConvertTo-Since([string]$text) {
    if ($text -eq 'today') { return (Get-Date).Date }
    if ($text -eq 'yesterday') { return (Get-Date).Date.AddDays(-1) }
    if ($text -match '^([0-9]+) (minute|hour|day)s? ago$') {
        $n = [int]$Matches[1]
        switch ($Matches[2]) {
            'minute' { return (Get-Date).AddMinutes(-$n) }
            'hour' { return (Get-Date).AddHours(-$n) }
            'day' { return (Get-Date).AddDays(-$n) }
        }
    }
    return [datetime]::Parse($text, [Globalization.CultureInfo]::InvariantCulture)
}
$start = ConvertTo-Since $since
$found = Get-WinEvent -FilterHashtable @{ LogName = 'System', 'Application'; StartTime = $start } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -eq $unit -or $_.Message -like "*$unit*" } |
    Select-Object -First $lines
$found | ForEach-Object { '{0:o} {1} {2}: {3}' -f $_.TimeCreated, $_.LevelDisplayName, $_.ProviderName, ($_.Message -replace '\r?\n', ' ') }
