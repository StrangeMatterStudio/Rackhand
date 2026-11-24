BeforeAll {
    $script:Dispatch = Join-Path $PSScriptRoot '..' 'dispatch.ps1'
    $script:Pwsh = (Get-Process -Id $PID).Path

    # a scripts folder of its own, with one script that leaves a mark when it runs
    $script:Root = Join-Path ([IO.Path]::GetTempPath()) ("rackhand-dispatch-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path (Join-Path $Root 'scripts'), (Join-Path $Root 'schemas') | Out-Null
    $script:Mark = Join-Path $Root 'ran.txt'
    Set-Content -LiteralPath (Join-Path $Root 'scripts/echo-args.ps1') -Value @'
param([string]$name, [int]$count, [bool]$loud)
Add-Content -LiteralPath (Join-Path $PSScriptRoot '../ran.txt') -Value "name=$name count=$count loud=$loud"
"name=$name count=$count loud=$loud"
if ($name -eq 'fail') { exit 7 }
'@
    Set-Content -LiteralPath (Join-Path $Root 'schemas/echo-args.json') -Value (@{
            script = 'echo-args'
            params = [ordered]@{
                count = @{ type = 'int'; pattern = '[1-9][0-9]{0,2}|1[0-9]{3}|2000' }
                loud  = @{ type = 'bool'; pattern = '.*' }
                name  = @{ type = 'string'; pattern = '[A-Za-z0-9@._:-]{1,16}' }
            }
        } | ConvertTo-Json -Depth 5)
    # a script without a schema is not a script the dispatcher knows
    Set-Content -LiteralPath (Join-Path $Root 'scripts/no-schema.ps1') -Value 'Add-Content -LiteralPath (Join-Path $PSScriptRoot "../ran.txt") -Value "no-schema"'

    function script:Invoke-Dispatch([string]$Command) {
        $out = & $Pwsh -NoProfile -File $Dispatch -Root $Root -Command $Command 2>&1 | Out-String
        [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    }
    function script:Mark-Count { if (Test-Path -LiteralPath $Mark) { @(Get-Content -LiteralPath $Mark).Count } else { 0 } }
}

AfterAll {
    Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Dispatch.Tests' {
    It 'refuses unknown script and extra arguments' {
        $good = '{"name":"alice","count":3,"loud":true}'
        # unknown scripts, names that are not names, and a script that has no schema: non-zero, nothing run
        foreach ($bad in @('rm-everything {}', 'echo-args2 {}', 'no-schema {}', '../echo-args {}', 'echo-args;calc {}', 'Echo-Args {}', '..\echo-args {}', 'powershell -c calc')) {
            $r = Invoke-Dispatch $bad
            $r.Code | Should -Not -Be 0 -Because $bad
        }
        Mark-Count | Should -Be 0
        (Invoke-Dispatch 'rm-everything {}').Code | Should -Be 127
        (Invoke-Dispatch '').Code | Should -Be 126
        (Invoke-Dispatch 'echo-args {"name":"a"} && calc').Code | Should -Be 126
        # an argument the schema doesn't have, or one missing
        (Invoke-Dispatch 'echo-args {"name":"alice","count":3,"loud":true,"extra":"x"}').Code | Should -Be 2
        (Invoke-Dispatch 'echo-args {"name":"alice","count":3}').Code | Should -Be 2
        (Invoke-Dispatch 'echo-args').Code | Should -Be 2
        Mark-Count | Should -Be 0
        # the same script with exactly its arguments runs, once
        $ok = Invoke-Dispatch "echo-args $good"
        $ok.Code | Should -Be 0
        $ok.Output | Should -Match 'name=alice count=3'
        Mark-Count | Should -Be 1
        # and its own exit code comes back
        (Invoke-Dispatch 'echo-args {"name":"fail","count":1,"loud":false}').Code | Should -Be 7
    }

    It 'validates args against schema' {
        $before = Mark-Count
        $cases = @(
            '{"name":"alice","count":"abc","loud":true}',   # not a number
            '{"name":"alice","count":2001,"loud":true}',    # over the pattern's limit
            '{"name":"alice","count":-1,"loud":true}',      # negative
            '{"name":"alice","count":1.5,"loud":true}',     # not whole
            '{"name":"alice","count":3,"loud":"yes"}',      # not a bool
            '{"name":42,"count":3,"loud":true}',            # not a string
            '{"name":"bad name!","count":3,"loud":true}',   # off the pattern
            '{"name":"-rf","count":3,"loud":true}',         # a leading dash, whatever the pattern says
            '{"name":"--help","count":3,"loud":true}',
            '{"name":"abcdefghijklmnopq","count":3,"loud":true}',  # one too long for the pattern
            '{"name":"a`nb","count":3,"loud":true}',        # a control character
            '{"name":null,"count":3,"loud":true}'
        )
        foreach ($c in $cases) {
            (Invoke-Dispatch "echo-args $c").Code | Should -Be 2 -Because $c
        }
        # not an object, or not JSON at all: not a request, so refused before any schema is read
        foreach ($c in @('["name"]', '"name"', '{"name":"alice","count":3,"loud":true')) {
            (Invoke-Dispatch "echo-args $c").Code | Should -Be 126 -Because $c
        }
        Mark-Count | Should -Be $before
        # values at the limits are accepted, a number can be sent as text, and a name can have what the pattern allows
        (Invoke-Dispatch 'echo-args {"name":"abcdefghijklmnop","count":2000,"loud":false}').Code | Should -Be 0
        (Invoke-Dispatch 'echo-args {"name":"a@b.c_d:e-f","count":"7","loud":true}').Code | Should -Be 0
        Mark-Count | Should -Be ($before + 2)
    }

    It 'refuses job references that are not the hub''s own' {
        foreach ($bad in @('job-status {"job":"../x/y","offset":0}', 'job-status {"job":"a/b/c","offset":0}', 'job-clean {"job":"a b/c"}', 'job-start {"job":"j/s","script":"rm-everything","args":{}}', 'job-start {"job":"x","script":"echo-args","args":{}}', 'job-status', 'job-clean not-json')) {
            (Invoke-Dispatch $bad).Code | Should -Not -Be 0 -Because $bad
        }
        # a job nobody started is `unknown`, not an error
        $r = Invoke-Dispatch 'job-status {"job":"j1/s1","offset":0}'
        $r.Code | Should -Be 0
        ($r.Output | ConvertFrom-Json).state | Should -Be 'unknown'
    }
}
