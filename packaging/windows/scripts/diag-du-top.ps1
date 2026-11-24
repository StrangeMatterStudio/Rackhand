# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param([string]$path, [int]$depth)
# the size of each directory down to `depth` levels under the path, largest first, as `<size>  <path>` lines. The path has the
# hub's pattern (it starts with a slash), so a drive is its first part: `/c/Users` is `C:\Users`.
if ($path -notmatch '^/([A-Za-z])(/.*)?$') { throw 'path: use /<drive>/<folder>, such as /c/Users' }
$real = $Matches[1].ToUpper() + ':' + $(if ($Matches[2]) { $Matches[2].Replace('/', '\') } else { '\' })
function Format-Size([double]$bytes) {
    if ($bytes -ge 1TB) { return '{0:N1}T' -f ($bytes / 1TB) }
    if ($bytes -ge 1GB) { return '{0:N1}G' -f ($bytes / 1GB) }
    if ($bytes -ge 1MB) { return '{0:N1}M' -f ($bytes / 1MB) }
    return '{0:N0}K' -f ($bytes / 1KB)
}
$dirs = @(Get-Item -LiteralPath $real) + @(Get-ChildItem -LiteralPath $real -Directory -Recurse -Depth ($depth - 1) -ErrorAction SilentlyContinue)
$dirs | ForEach-Object {
    $size = (Get-ChildItem -LiteralPath $_.FullName -File -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    [pscustomobject]@{ Size = [double]$size; Path = $_.FullName }
} | Sort-Object Size -Descending | ForEach-Object { "{0}`t{1}" -f (Format-Size $_.Size), $_.Path }
