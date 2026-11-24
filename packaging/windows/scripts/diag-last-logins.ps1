# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param()
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object {
    $data = @{}
    ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
    '{0:o} type {1} {2}\{3} from {4}' -f $_.TimeCreated, $data['LogonType'], $data['TargetDomainName'], $data['TargetUserName'], $data['IpAddress']
}
