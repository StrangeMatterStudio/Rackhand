BeforeAll {
    # the script's functions, without running it
    . (Join-Path $PSScriptRoot '..' 'scripts' 'quarantine.ps1') -hubs '192.0.2.10' -quicPort 7843
}

Describe 'Quarantine.Tests' {
    It 'rules allow only hub paths and DHCP' {
        $hubs = @('192.0.2.10', '2001:db8::10')
        $rules = @(New-QuarantineRuleSet $hubs 7843)
        # every rule is one of DHCP or between this machine and the hub: nothing is open to anyone else
        foreach ($r in $rules) {
            $dhcp = $r.Protocol -eq 'UDP' -and (($r.LocalPort -eq '68' -and $r.RemotePort -eq '67'))
            $hub = $r.RemoteAddress -eq ($hubs -join ',')
            ($dhcp -or $hub) | Should -BeTrue -Because $r.Name
            if (-not $dhcp) { $r.RemoteAddress | Should -Not -Be 'Any' -Because $r.Name }
        }
        # exactly: DHCP both ways, the probe's QUIC to the hub, the hub's SSH, the hub's ping
        ($rules | ForEach-Object { '{0} {1} {2} {3}' -f $_.Direction, $_.Protocol, $_.LocalPort, $_.RemotePort }) | Should -Be @(
            'Outbound UDP 68 67'
            'Inbound UDP 68 67'
            'Outbound UDP Any 7843'
            'Inbound TCP 22 Any'
            'Inbound ICMPv4 Any Any'
        )
        # the ones from the hub are inbound only for SSH and ping; the probe's own connection is outbound
        ($rules | Where-Object { $_.Name -eq 'probe to the hub' }).Direction | Should -Be 'Outbound'
        ($rules | Where-Object { $_.Name -eq 'hub SSH' }).LocalPort | Should -Be '22'
        # and no rule opens a port to the world: nothing but DHCP has `Any` for the remote address
        @($rules | Where-Object { $_.RemoteAddress -eq 'Any' }).Count | Should -Be 2
        # the quarantine blocks both directions by default, and the release puts back what it saved
        $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'scripts' 'quarantine.ps1') -Raw
        $source | Should -Match 'DefaultInboundAction Block -DefaultOutboundAction Block'
        $release = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'scripts' 'quarantine-release.ps1') -Raw
        $release | Should -Match 'DefaultInboundAction \$p\.DefaultInboundAction'
        $release | Should -Match 'Get-NetFirewallRule -Group \$Group'
    }
}
