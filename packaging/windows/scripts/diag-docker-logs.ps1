# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param([string]$container, [int]$lines)
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { 'docker is not installed on this machine'; exit 1 }
docker logs --tail $lines $container 2>&1
