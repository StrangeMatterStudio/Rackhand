# Part of the Rackhand dispatcher (design 7.3.7, 7.8.3): run only through dispatch.ps1, with arguments it has checked.
param()
$searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
$result = $searcher.Search('IsInstalled=0 and IsHidden=0')
'{0} pending' -f $result.Updates.Count
foreach ($u in $result.Updates) { '{0} {1}' -f ($(if ($u.MsrcSeverity) { $u.MsrcSeverity } else { '-' })), $u.Title }
