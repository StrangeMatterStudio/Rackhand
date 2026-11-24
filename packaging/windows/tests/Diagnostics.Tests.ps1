BeforeAll {
    $script:Packaging = Join-Path $PSScriptRoot '..'
    $script:Dispatch = Join-Path $Packaging 'dispatch.ps1'
    $script:Pwsh = (Get-Process -Id $PID).Path

    # The shipped schemas with a stub in place of each script (the real ones need Windows), so what is tested is what the
    # dispatcher lets through for each diagnostic.
    $script:Root = Join-Path ([IO.Path]::GetTempPath()) ('rackhand-diag-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Path (Join-Path $Root 'scripts') | Out-Null
    Copy-Item -LiteralPath (Join-Path $Packaging 'schemas') -Destination (Join-Path $Root 'schemas') -Recurse
    foreach ($schema in Get-ChildItem (Join-Path $Root 'schemas') -Filter '*.json') {
        Set-Content -LiteralPath (Join-Path $Root "scripts/$($schema.BaseName).ps1") -Value 'param() "ran"'
    }
    # stubs take parameters by name: give each a param block of its schema's names
    foreach ($schema in Get-ChildItem (Join-Path $Root 'schemas') -Filter '*.json') {
        $names = @((Get-Content $schema.FullName -Raw | ConvertFrom-Json).params.PSObject.Properties | ForEach-Object { $_.Name })
        $block = 'param(' + (($names | ForEach-Object { '$' + $_ }) -join ', ') + ')'
        Set-Content -LiteralPath (Join-Path $Root "scripts/$($schema.BaseName).ps1") -Value "$block`n'ran'"
    }

    # a value each parameter takes, and one it must not
    $script:Fine = @{
        unit = 'Spooler'; since = '1 hours ago'; lines = '50'; name = 'Spooler'; container = 'web_1'
        path = '/c/Users'; depth = '2'; target = '192.0.2.11'; url = 'https://web.example/healthz'
        phase = 'scan'; hubs = '192.0.2.10'; quicPort = '7843'
    }

    function script:Invoke-Script([string]$Name, $Params) {
        $json = ConvertTo-Json -InputObject $Params -Compress
        $out = & $Pwsh -NoProfile -File $Dispatch -Root $Root -Command "$Name $json" 2>&1 | Out-String
        [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    }
}

AfterAll { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'Diagnostics.Tests' {
    It 'every schema has its script and every script its schema' {
        $schemas = Get-ChildItem (Join-Path $Packaging 'schemas') -Filter '*.json' | ForEach-Object BaseName | Sort-Object
        $scripts = Get-ChildItem (Join-Path $Packaging 'scripts') -Filter '*.ps1' | ForEach-Object BaseName | Sort-Object
        $scripts | Should -Be $schemas
        # and the nineteen diagnostics of 7.8.3 are among them
        @($schemas | Where-Object { $_ -like 'diag-*' }).Count | Should -Be 19
    }

    It 'each diagnostic runs through the dispatcher with its parameters and refuses a bad one' {
        foreach ($schema in Get-ChildItem (Join-Path $Packaging 'schemas') -Filter '*.json') {
            $spec = Get-Content $schema.FullName -Raw | ConvertFrom-Json
            $good = [ordered]@{}
            foreach ($p in $spec.params.PSObject.Properties) {
                $value = $Fine[$p.Name]
                $value | Should -Not -BeNullOrEmpty -Because "$($schema.BaseName) has `$($p.Name)"
                $good[$p.Name] = if ($p.Value.type -eq 'int') { [int]$value } else { $value }
            }
            $ran = Invoke-Script $schema.BaseName $good
            $ran.Code | Should -Be 0 -Because "$($schema.BaseName): $($ran.Output)"
            # the same parameter limits as the hub's: a leading dash, and a value that is off the pattern, are refused
            foreach ($p in $spec.params.PSObject.Properties) {
                $bad = [ordered]@{} + $good
                $bad[$p.Name] = '-x'
                (Invoke-Script $schema.BaseName $bad).Code | Should -Be 2 -Because "$($schema.BaseName) $($p.Name) with a dash"
                $bad[$p.Name] = 'x; calc'
                (Invoke-Script $schema.BaseName $bad).Code | Should -Be 2 -Because "$($schema.BaseName) $($p.Name) with a semicolon"
            }
            # an argument it doesn't have is refused
            $extra = [ordered]@{} + $good
            $extra['extra'] = 'x'
            (Invoke-Script $schema.BaseName $extra).Code | Should -Be 2 -Because "$($schema.BaseName) with an extra argument"
        }
    }
}
