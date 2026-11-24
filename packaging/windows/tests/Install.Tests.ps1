BeforeAll {
    $script:Install = Join-Path $PSScriptRoot '..' 'install.ps1'

    # the sshd_config a fresh Windows OpenSSH Server has
    $script:Default = @"
#Port 22
#AddressFamily any
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
Subsystem sftp sftp-server.exe

Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@

    # Everything the installer would do to the machine is a function, and each test replaces them with ones that record.
    function script:Use-FakeMachine([bool]$SignatureGood = $true, [string]$Assistant = 'true') {
        $script:Calls = [System.Collections.Generic.List[string]]::new()
        Mock Test-Administrator { $true }
        Mock Invoke-Download { Set-Content -LiteralPath $Path -Value 'x' }
        Mock Get-FileSha256 { $VerifySha256 }
        Mock Test-ReleaseFile { $SignatureGood }.GetNewClosure()
        Mock Install-OpenSSHServer { $Calls.Add('openssh') }
        Mock New-HubAccount { $Calls.Add("account $Name") }
        Mock Remove-HubAccount { $Calls.Add("remove $Name") }
        Mock Set-Transcription { $Calls.Add('transcription') }
        Mock Protect-Directory { }
        Mock Install-Files { $Calls.Add('files') }
        Mock Invoke-Enroll { @{ machine_id = '01JTEST'; managed = 'true'; assistant = $Assistant } }.GetNewClosure()
        Mock Install-Service { $Calls.Add("service $Name") }
        Mock Start-RackhandService { }
        Mock Restart-Sshd { $Calls.Add("sshd restart") }
        Mock Get-SshdConfig { $Default }
        Mock Set-SshdConfigText { $Calls.Add('sshd_config') }
        Mock Remove-Item { }
    }
}

Describe 'Install.Tests' {
    It 'sshd_config Match block placed before administrators block' {
        . $Install -NoRun
        $root = 'C:\Program Files\Rackhand'
        $config = Add-RackhandBlock $Default $root
        $mine = $config.IndexOf('Match User rackhand,rackhand-ai')
        $forced = $config.IndexOf('Match User rackhand' + "`r`n")
        $admins = $config.IndexOf('Match Group administrators')
        $mine | Should -BeGreaterThan 0
        $mine | Should -BeLessThan $admins
        $forced | Should -BeLessThan $admins
        # the keys come from Rackhand's folder, by account; `rackhand` is forced into the dispatcher; passwords are off
        $config | Should -Match '(?m)^\s+AuthorizedKeysFile __PROGRAMDATA__/rackhand/keys/%u'
        $config | Should -Match 'ForceCommand powershell.exe .*dispatch\.ps1"'
        $config | Should -Match '(?m)^\s+PasswordAuthentication no'
        # what was there is still there, and the administrators' own key file too
        $config | Should -Match 'Subsystem sftp sftp-server.exe'
        $config | Should -Match 'administrators_authorized_keys'
        # the dispatcher is the forced command of `rackhand` only, not of `rackhand-ai`
        $forceAt = $config.IndexOf('ForceCommand')
        $forceAt | Should -BeGreaterThan $forced
        # a second install replaces the block and doesn't add another
        $again = Add-RackhandBlock $config $root
        ([regex]::Matches($again, '# BEGIN rackhand')).Count | Should -Be 1
        $again | Should -Be $config
        # a machine that goes to monitor loses it, and nothing else
        (Remove-RackhandBlock $config) | Should -Be $Default
        # with no administrators block, it goes at the end
        $plain = "Port 22`r`n"
        (Add-RackhandBlock $plain $root) | Should -Match '(?s)^Port 22\r\n# BEGIN rackhand.*# END rackhand'
    }

    It 'bad signature stops before installing' {
        . $Install -NoRun -Ticket 'rackhand1:00' -Token 't'
        Use-FakeMachine -SignatureGood $false
        { Invoke-Install } | Should -Throw "*isn't signed by a pinned release key; nothing was installed*"
        # nothing of the machine was touched: no OpenSSH, no files, no join, no accounts, no services
        Should -Invoke Install-OpenSSHServer -Times 0 -Exactly
        Should -Invoke Install-Files -Times 0 -Exactly
        Should -Invoke Invoke-Enroll -Times 0 -Exactly
        Should -Invoke New-HubAccount -Times 0 -Exactly
        Should -Invoke Install-Service -Times 0 -Exactly
        Should -Invoke Set-SshdConfigText -Times 0 -Exactly
    }

    It 'a verifier that is not the one this installer was made with stops it before anything is checked' {
        . $Install -NoRun -Ticket 'rackhand1:00' -Token 't'
        Use-FakeMachine
        Mock Get-FileSha256 { 'not the verifier' }
        { Invoke-Install } | Should -Throw "*rackhand-verify doesn't match this installer; nothing was installed*"
        Should -Invoke Test-ReleaseFile -Times 0 -Exactly
        Should -Invoke Install-Files -Times 0 -Exactly
    }

    It 'monitor installs no OpenSSH and no accounts' {
        . $Install -NoRun -Ticket 'rackhand1:00' -Token 't' -Monitor
        Use-FakeMachine
        Invoke-Install | Should -Match 'enrolled as machine 01JTEST \(monitor\)'
        Should -Invoke Install-OpenSSHServer -Times 0 -Exactly
        Should -Invoke New-HubAccount -Times 0 -Exactly
        Should -Invoke Set-Transcription -Times 0 -Exactly
        # it still gets the probe and the helper, and a machine that was managed loses its accounts and the block
        Should -Invoke Install-Service -Times 1 -Exactly -ParameterFilter { $Name -eq 'RackhandProbe' }
        Should -Invoke Install-Service -Times 1 -Exactly -ParameterFilter { $Name -eq 'RackhandHelper' }
        Should -Invoke Remove-HubAccount -Times 1 -Exactly -ParameterFilter { $Name -eq 'rackhand' }
        Should -Invoke Remove-HubAccount -Times 1 -Exactly -ParameterFilter { $Name -eq 'rackhand-ai' }
    }

    It 'a managed machine gets all of it, in the order of 7.3.7' {
        . $Install -NoRun -Ticket 'rackhand1:00' -Token 't'
        Use-FakeMachine
        Invoke-Install | Should -Match '\(managed\)'
        $order = $Calls -join ' | '
        $order | Should -Be 'openssh | files | account rackhand | account rackhand-ai | transcription | sshd_config | sshd restart | service RackhandHelper | service RackhandProbe'
    }

    It 'without an assistant key the machine has no rackhand-ai' {
        . $Install -NoRun -Ticket 'rackhand1:00' -Token 't'
        Use-FakeMachine -Assistant 'false'
        Invoke-Install | Out-Null
        Should -Invoke New-HubAccount -Times 0 -Exactly -ParameterFilter { $Name -eq 'rackhand-ai' }
        Should -Invoke Remove-HubAccount -Times 1 -Exactly -ParameterFilter { $Name -eq 'rackhand-ai' }
    }
}
