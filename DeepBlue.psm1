
Function Get-DeepBlueAnalysis {
<#
    .SYNOPSIS
        A PowerShell module for hunt teaming via Windows event logs

    .DESCRIPTION
        DeepBlueCLI can automatically determine events that are typically triggered during a majority of successful breaches,
        including use of malicious command lines including PowerShell.

    .EXAMPLE
        Get-DeepBlueAnalysis

        Processes the local Windows security event log.

    .EXAMPLE
        Get-DeepBlueAnalysis -Log System

        Processes the local Windows system event log.

    .EXAMPLE
        Get-DeepBlueAnalysis -File .\evtx\new-user-security.evtx

        Processes an evtx file.

    .LINK
        https://github.com/sans-blue-team/DeepBlueCLI

    .NOTES
        DeepBlueCLI 2.01
        Eric Conrad, Backshore Communications, LLC
        deepblue <at> backshore <dot> net
        Twitter: @eric_conrad
        http://ericconrad.com
#>

[CmdletBinding(DefaultParameterSetName='ByLogName')]
Param(
[Parameter(ParameterSetName='ByFilePath',Mandatory)]
[Alias('Path','FilePath')]
[ValidateScript({ Test-Path -Path $_ -PathType Leaf})]
[string]$File,

[Parameter(ParameterSetName='ByLogName')]
[ValidateSet('Security','System','Application','Applocker','PowerShell','Sysmon')]
[Alias('LogName')]
[string]$Log='Security',

# Passworg guessing/spraying variables:
$MaxFailedLogons = 5,  # Alert after this many failed logons
$MaxTotalSensPrivUse = 4,
[switch]$AlertAllAdmin, # To alert every admin logon
# Sysmon: Check for unsigned EXEs/DLLs. This can be very chatty..
[switch]$CheckUnsigned,
$PassSprayUniqUserMax = 6,
$PassSprayLoginMax = 6,
# Obfuscation variables:
$MinPercent = .65, # minimum percentage of alphanumeric and common symbols
$MaxBinary = .50,   # Maximum percentage of zeros and ones to detect binary encoding

[switch]$AddApplockerAllowEvents,
[switch]$AddPowerShellInfoEvents,

[Parameter()]
[ValidateRange(1,[int32]::MaxValue)]
[int32]$LastHour
)
Begin {

#region helper functions
Function Get-EventFile {
[OutputType('System.String')]
[CmdletBinding()]
Param(
[Parameter(Mandatory)]
[string]$File
)
Begin {}
Process {
    # File exists. Todo: verify it is an evtx file.

    # Get-WinEvent will generate this error for non-evtx files: "...file does not appear to be a valid log file.
    # Specify only .evtx, .etl, or .evt filesas values of the Path parameter."
    #
    # Check the LogName of the first event
    try {
        $e = Get-WinEvent -Path $File -MaxEvents 1 -ErrorAction Stop -Verbose:$false
    } catch {
        Write-Verbose "Get-WinEvent cannot read $($File) because $($_.Exception.Message)" -Verbose
    }
    Write-Verbose -Message "Input file $($File) contains a log $($e.LogName)"
    switch ($e.LogName) {
        'Security'    { 'Security'    ; break}
        'System'      { 'System'      ; break }
        'Application' { 'Application' ; break}
        'Microsoft-Windows-AppLocker/EXE and DLL'    {'Applocker' ; break}
        'Microsoft-Windows-AppLocker/MSI and Script' {'Applocker' ; break}
        'Microsoft-Windows-PowerShell/Operational' {'Powershell'; break}
        'Microsoft-Windows-Sysmon/Operational'     {'Sysmon'    ; break}
        default {
            Write-Warning -Message "[Get-EventFile] Input file $($File) that is a log $($e.LogName) is not handled"
        }
    }
}
End {}
}

# Return the Get-Winevent filter
Function New-WinEventFilter {
[OutputType('System.Collections.Hashtable')]
[CmdletBinding(SupportsShouldProcess)]
Param(
[Parameter()]
[string]$File,

[Parameter(Mandatory)]
[string]$LogName

)
Begin {
    $sys_events= @('7030','7036','7045','7040','104')
    if ($AlertAllAdmin)  {
        $sec_events= @('4672','4720','4728','4732','4756','4625','4673','4648','1102')
    } else {
        $sec_events= @('4688','4672','4720','4728','4732','4756','4625','4673','4648','1102')
    }
    $app_events=@('2')
    $applocker_events=@('8003','8004','8006','8007')
    if($AddApplockerAllowEvents) {
        $applocker_events=@('8003','8004','8006','8007','8002','8005')
    }
    $powershell_events=@('4103','4104')
    $sysmon_events=@('1','7')
}
Process {
    if ($File) {
        switch ($LogName) {
            'Security'    {$filter=@{path="$($file)";ID=$sec_events} ;break}
            'System'      {$filter=@{path="$($file)";ID=$sys_events} ;break}
            'Application' {$filter=@{path="$($file)";ID=$app_events} ;break}
            'Applocker'   {$filter=@{path="$($file)";ID=$applocker_events} ;break}
            'Powershell'  {$filter=@{path="$($file)";ID=$powershell_events} ;break}
            'Sysmon'      {$filter=@{path="$($file)";ID=$sysmon_events} ;break}
            default       {
                Throw 'Logic error 1, should not reach here...'
            }
        }
    } else {
        switch ($LogName) {
            'Security'    {$filter=@{Logname='Security';ID=$sec_events} ;break}
            'System'      {$filter=@{Logname='System';ID=$sys_events } ;break}
            'Application' {$filter=@{Logname='Application';ID=$app_events} ;break}
            'Applocker'   {$filter=@{logname='Microsoft-Windows-AppLocker/EXE and DLL','Microsoft-Windows-AppLocker/MSI and Script';ID=$applocker_events} ;break}
            'Powershell'  {$filter=@{logname='Microsoft-Windows-PowerShell/Operational';ID=$powershell_events} ;break}
            'Sysmon'      {$filter=@{logname='Microsoft-Windows-Sysmon/Operational';ID=$sysmon_events} ;break}
            default       {
                Throw 'Logic error 2, should not reach here...'
            }
        }
    }
    if ($PSCmdlet.ShouldProcess('Create filter')) {
        if ($LastHour) {
            $null = $filter.Add('StartTime',((Get-Date).AddHours(-$LastHour)))
            $filter
        } else {
            $filter
        }
    }

}
End {}
}

Function Get-SuspiciousCommand {
[CmdletBinding()]
Param(
[Parameter(Mandatory)]
[string]$CommandLine
# The following variables are created outside of the scope of this function:
# obj now is o, whitelist, servicecmd,# servicename
)
Begin {
    $text=''
    $base64=''
}
Process {
    # Check to see if command is whitelisted
    foreach ($entry in $whitelist) {
        if ($CommandLine -Match $entry.regex) {
            # Command is whitelisted, return nothing
            return
        }
    }
    if ($CommandLine.length -gt $minlength) {
        $text += "Long Command Line: greater than $minlength bytes`n"
    }
    $text += (Get-ObfuscationReport -String $CommandLine)
    $text += (Get-RegexMatch -String $CommandLine -Type 0)
    $text += (Get-CreatorText -Command $CommandLine -Creator $creator)
    # Check for base64 encoded function, decode and print if found
    # This section is highly use case specific, other methods of base64 encoding and/or compressing may evade these checks
    if ($CommandLine -Match "\-enc.*[A-Za-z0-9/+=]{100}") {
        $base64= $CommandLine -Replace '^.* \-Enc(odedCommand)? ',''
    } elseif ($CommandLine -Match ":FromBase64String\(\$") {
        Write-Verbose -Message "[Get-SuspiciousCommand] Command contains FromBase64String followed by a variable:`n$($CommandLine)`n"
    } elseif ($CommandLine -Match ':FromBase64String\(') {
        $base64 = $CommandLine -Replace "^.*:FromBase64String\(\'*",''
        $base64 = $base64 -Replace "\'.*$",''
    }
    if ($base64) {
        if ($CommandLine -Match 'Compression.GzipStream.*Decompress') {
            # Metasploit-style compressed and base64-encoded function. Uncompress it.
            $decoded = New-Object IO.MemoryStream(,[Convert]::FromBase64String($base64))
            $uncompressed = (
                New-Object IO.StreamReader(
                (New-Object IO.Compression.GzipStream($decoded,[IO.Compression.CompressionMode]::Decompress)),
                [Text.Encoding]::ASCII
                )
            ).ReadToEnd()
            $o.Decoded = $uncompressed
            $text += 'Base64-encoded and compressed function'
        } else {
            $decoded = $null
            if ($base64 -match '\s-(in|out)putFormat\s') {
                $base64 =  ($base64 -split '\s')[0]
            }
            try {
                $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
            } catch {
                Write-Warning -Message "Failed to convert from BASE64 `n$($base64)`n string because $($_.Exception.Message)"
            }
            $o.Decoded = $decoded
            $text += "Base64-encoded function`n"
            $text += (Get-ObfuscationReport -String $decoded)
            $text += (Get-RegexMatch -String $decoded -Type 0)
        }
    }
    if ($text) {
        if ($servicecmd) {
            $o.Message = 'Suspicious Service Command'
            $o.Results = "Service name: $servicename`n"
        } else {
            $o.Message = 'Suspicious Command Line'
        }
        $o.Command = $commandline
        $o.Results += $text
        $o
    }
}
End {}
}

Function Get-RegexMatch {
[CmdletBinding()]
Param (
[Parameter(Mandatory)]
[AllowEmptyString()]
[string]$String,

[Parameter(Mandatory)]
[ValidateRange(0,1)]
[int]$Type  # Type is 0 for Commands, 1 for services. Set in regexes.csv
)
Begin {
    $regextext = '' # Local variable for return output
}
Process {
    if ($String) {
        foreach ($regex in $regexes) {
            if ($regex.Type -eq $type) {
                if ($string -Match $regex.regex) {
                   $regextext += $regex.String + "`n"
                }
            }
        }
        #if ($regextext) {
        #   $regextext = $regextext.Substring(0,$regextext.Length-1) # Remove final newline.
        #}
        $regextext
    } else {
        Write-Warning -Message 'Get-RegexMatch invoked with an empty string'
    }
}
End {}
}

Function Get-ObfuscationReport {
[CmdletBinding()]
Param(
[Parameter(Mandatory)]
[AllowEmptyString()]
[string]$string
)
Begin {
    # Check for special characters in the command. Inspired by Invoke-Obfuscation: https://twitter.com/danielhbohannon/status/778268820242825216
    #
    $obfutext=''       # Local variable for return output
}
Process {
    if ($string) {
        $lowercasestring=$string.ToLower()
        $length=$lowercasestring.length
        $noalphastring = $lowercasestring -replace '[a-z0-9/\;:|.]'
        $nobinarystring = $lowercasestring -replace '[01]' # To catch binary encoding
        # Calculate the percent alphanumeric/common symbols
        if ($length -gt 0) {
            $percent=(($length-$noalphastring.length)/$length)
            # Adjust minpercent for very short commands, to avoid triggering short warnings
            if (($length/100) -lt $1:MinPercent) {
                $minpercent=($length/100)
            }
            if ($percent -lt $minpercent) {
                $percent = '{0:P0}' -f $percent      # Convert to a percent
                $obfutext += "Possible command obfuscation: only $percent alphanumeric and common symbols`n"
            }
            # Calculate the percent of binary characters
            $percent=(($nobinarystring.length-$length/$length)/$length)
            $binarypercent = 1-$percent
            if ($binarypercent -gt $MaxBinary) {
                #$binarypercent = 1-$percent
                $binarypercent = '{0:P0}' -f $binarypercent      # Convert to a percent
                $obfutext += "Possible command obfuscation: $binarypercent zeroes and ones (possible numeric or binary encoding)`n"
            }
        }
    } else {
        Write-Warning -Message 'Get-ObfuscationReport invoked with an empty string'
    }
    $obfutext
}
End {}
}

Function Get-CreatorText {
Param(
[Parameter(Mandatory)]
[String]$Command,
[Parameter()]
[string]$Creator
)
Begin {
    $creatortext = ''  # Local variable for return output
}
Process {
    if ($Creator) {
        if ($command -Match 'powershell') {
            Switch ($Creator) {
                'PSEXESVC' {
                    $creatortext = "PowerShell launched via PsExec: $Creator`n"
                    break
                }
                'WmiPrvSE' {
                    $creatortext = "PowerShell launched via WMI: $Creator`n"
                    break
                }
                default {}
            }
        }
        $creatortext
    }
}
End {}
}

#endregion

#region init variables
    # Set up the global variables
    $text = '' # Temporary scratch pad variable to hold output text
    $minlength = 1000 # Minimum length of command line to alert
    # Load cmd match regexes from csv file, ignore comments
    $regexes = @(
        @{ Type = '0' ; Regex = '^cmd.exe /c echo [a-z]{6} > \\\\.\\pipe\\[a-z]{6}$' ; String = 'Metasploit-style cmd with pipe (possible use of Meterpreter getsystem)'},
        @{ Type = '0' ; Regex = '^%SYSTEMROOT%\\[a-zA-Z]{8}\.exe$' ; String = 'Metasploit-style %SYSTEMROOT% image path (possible use of Metasploit Native upload exploit payload)'},
        @{ Type = '0' ; Regex = 'powershell.*FromBase64String.*IO.Compression.GzipStream' ; String = 'Metasploit-style base64 encoded/compressed PowerShell function (possible use of Metasploit PowerShell exploit payload)'},
        @{ Type = '0' ; Regex = 'DownloadString\(.http' ; String = 'Download via Net.WebClient DownloadString'},
        @{ Type = '0' ; Regex = 'mimikatz' ; String = 'Command referencing Mimikatz'},
        @{ Type = '0' ; Regex = 'Invoke-Mimikatz.ps' ; String = 'PowerSploit Invoke-Mimikatz.ps1'},
        @{ Type = '0' ; Regex = 'PowerSploit.*ps1' ; String = 'Use of PowerSploit'},
        @{ Type = '0' ; Regex = 'User-Agent' ; String = 'User-Agent set via command line'},
        @{ Type = '0' ; Regex = '[a-zA-Z0-9/+=]{500}' ; String = '500+ consecutive Base64 characters'},
        @{ Type = '0' ; Regex = 'powershell.exe.*Hidden.*Enc' ; String = 'Base64 encoded and hidden PowerShell command'},
        # Generic csc.exe alert, comment out if experiencing false positives
        @{ Type = '0' ; Regex = '\\csc\.exe' ; String = 'Use of C Sharp compiler csc.exe'},
        @{ Type = '0' ; Regex = '\\csc\.exe.*\\Appdata\\Local\\Temp\\[a-z0-9]{8}\.cmdline' ; String = 'PSAttack-style command via csc.exe'},
        # Generic cvtres.exe alert, comment out if experiencing false positives
        @{ Type = '0' ; Regex = '\\cvtres\.exe.*' ; String = 'Resource File To COFF Object Conversion Utility cvtres.exe'},
        @{ Type = '0' ; Regex = '\\cvtres\.exe.*\\AppData\\Local\\Temp\\[A-Z0-9]{7}\.tmp' ; String = 'PSAttack-style command via cvtres.exe'},
        @{ Type = '1' ; Regex = '^[a-zA-Z]{22}$' ; String = 'Metasploit-style service name: 22 characters'},
        @{ Type = '1' ; Regex = '^[a-zA-Z]{16}$' ; String = 'Metasploit-style service name: 16 characters'}
    ) |
    ForEach-Object {
        [PSCustomObject]$_
    }

    # Load cmd whitelist regexes from csv file, ignore comments
    # $whitelist = Get-Content ".\whitelist.txt" | Select-String '^[^#]' | ConvertFrom-Csv
    $whitelist = @(
        @{ Regex = '^"C:\\Program Files\\Google\\Chrome\\Application\\chrome\.exe"'},
        @{ Regex = '^"C:\\Program Files\\Google\\Update\\GoogleUpdate\.exe"'}
    ) | ForEach-Object {
        [PSCustomObject]$_
    }

    $failedlogons = @{} # HashTable of failed logons per user
    $totalfailedlogons = 0 # Total number of failed logons (for all accounts)
    $totalfailedaccounts = 0 # Total number of accounts with a failed logon
    # Track total Sensitive Privilege Use occurrences
    $totalsensprivuse = 0

    # Admin logon variables:
    $totaladminlogons = 0 # Total number of logons with SeDebugPrivilege

    $adminlogons = @{} # HashTable of admin logons
    $multipleadminlogons = @{} #Hashtable to track multiple admin logons per account

    # Password spray variables:
    $passspraytrack = @{}

#endregion

}
Process {

    Switch ($PSCmdlet.ParameterSetName) {
        'ByLogName' {
            $logname = $Log
            $filter = New-WinEventFilter -LogName $logname
            break
        }
        'ByFilePath' {
            $logname = Get-EventFile -File $File # -Verbose
            if ($logname) {
                $filter = New-WinEventFilter -File $file -LogName $logname
            } else {
                Write-Warning -Message 'Filter not defined because this log file is not handled'
            }
            break
        }
        default {}
    }
    if ($filter) {
        try {
            $HT = @{ FilterHashtable = $filter }
            $events = Get-WinEvent @HT -ErrorAction Stop
        } catch {
    	    Write-Warning "Get-WinEvent failed because: $($_.Exception.Message)"
        }
    } else {
        Write-Warning -Message "Did not query log file $($File)"
    }
    ForEach ($e in $events) {

        # Prepare a custom reporting object:
        $o = [PSCustomObject]@{
            Date    = $e.TimeCreated
            Log     = $logname
            EventID = $e.id
            Message = ''
            Results = ''
            Command = ''
            Decoded = ''
        }

        $xml = [xml]$e.ToXml()

        $servicecmd = 0 # CLIs via service creation get extra checks, this defaults to 0 (no extra checks)

        Switch ($logname) {
            'Security' {
                Switch ($e.id) {
                    '4688' {
                        # A new process has been created. (Command Line Logging)
                        $c = $xml.Event.EventData.Data[8].'#text'        # Process Command Line
                        $creator = $xml.Event.EventData.Data[13].'#text' # Creator Process Name
                        if ($c) {
                            Get-SuspiciousCommand -CommandLine $c
                        }
                        break
                    }
                    '4672' {
                        # Special privileges assigned to new logon (possible admin access)
                        $user = $xml.Event.EventData.Data[1].'#text'
                        $SID = $xml.Event.EventData.Data[3].'#text'
                        $privileges = $xml.Event.EventData.Data[4].'#text'
                        # Admin account with SeDebugPrivilege
                        if ($privileges -Match 'SeDebugPrivilege') {
                            # Alert for every admin logon
                            if ($AlertAllAdmin) {
                                $o.Message = 'Logon with SeDebugPrivilege (admin access)'
                                $o.Results = @"
Username: $user
Domain: $($xml.Event.EventData.Data[2].'#text')
User SID: $SID
Privileges: $privileges
"@
                                $o
                            }
                            # Track User SIDs used during admin logons (can track one account logging into multiple systems)
                            $totaladminlogons++
                            if ($adminlogons.ContainsKey($user)) {
                                $string = $adminlogons.$user
                                if (-Not ($string -Match $SID)) {
                                    # One username with multiple admin logon SIDs
                                    $multipleadminlogons.Set_Item($user,1)
                                    $string += " $SID"
                                    $adminlogons.Set_Item($user,$string)
                                }
                            } else {
                                $adminlogons.add($user,$SID)
                                #$adminlogons.$user = $SID
                            }
                            #$adminlogons.Set_Item($user,$securitysid)
                            #$adminlogons($user)+=($securitysid)
                        }
    <#
                        # This unique privilege list is used by Mimikatz 2.2.0
                        # Disabling due to false-positive with MS Exchange.
        #                If ($privileges -Match 'SeAssignPrimaryTokenPrivilege' `
        #                        -And $privileges -Match 'SeTcbPrivilege' `
        #                        -And $privileges -Match 'SeSecurityPrivilege' `
        #                        -And $privileges -Match 'SeTakeOwnershipPrivilege' `
        #                        -And $privileges -Match 'SeLoadDriverPrivilege' `
        #                        -And $privileges -Match 'SeBackupPrivilege' `
        #                        -And $privileges -Match 'SeRestorePrivilege' `
        #                        -And $privileges -Match 'SeDebugPrivilege' `
        #                        -And $privileges -Match 'SeAuditPrivilege' `
        #                        -And $privileges -Match 'SeSystemEnvironmentPrivilege' `
        #                        -And $privileges -Match 'SeImpersonatePrivilege' `
        #                        -And $privileges -Match 'SeDelegateSessionUserImpersonatePrivilege') {
        #                    $o.Message = 'Mimikatz token::elevate Privilege Use'
        #                    $o.Results = "Username: $user`n"
        #                    $o.Results += "Domain: $domain`n"
        #                    $o.Results += "User SID: $SID`n"
        #                    $pprivileges = $privileges -replace "`n",", " -replace "\s+"," "
        #                    $o.Results += "Privileges: $pprivileges"
        #                    Write-Output($o)
        #                }
                        # This unique privilege list is used by Metasploit exploit/windows/smb/psexec (v5.0.4 tested)
        #               # Disabling due to false-positive with MS Exchange Server
        #                If ($privileges -Match 'SeSecurityPrivilege' `
        #                        -And $privileges -Match 'SeBackupPrivilege' `
        #                        -And $privileges -Match 'SeRestorePrivilege' `
        #                        -And $privileges -Match 'SeTakeOwnershipPrivilege' `
        #                        -And $privileges -Match 'SeDebugPrivilege' `
        #                        -And $privileges -Match 'SeSystemEnvironmentPrivilege' `
        #                        -And $privileges -Match 'SeLoadDriverPrivilege' `
        #                        -And $privileges -Match 'SeImpersonatePrivilege' `
        #                        -And $privileges -Match 'SeDelegateSessionUserImpersonatePrivilege') {
        #                    $o.Message = 'Metasploit psexec Privilege Use'
        #                    $o.Results = "Username: $user`n"
        #                    $o.Results += "Domain: $domain`n"
        #                    $o.Results += "User SID: $SID`n"
        #                    $pprivileges = $privileges -replace "`n",", " -replace "\s+"," "
        #                    $o.Results += "Privileges: $pprivileges"
        #                    Write-Output($o)
        #                }
    #>
                        break
                    }
                    '4720' {
                        # A user account was created.
                        $user = $xml.Event.EventData.Data[0].'#text'
                        $SID = $xml.Event.EventData.Data[2].'#text'
                        $o.Message = 'New User Created'
                        $o.Results = @"
Username: $user
User SID: $SID
"@
                        $o
                        break
                    }
                    {$_ -in @('4728','4732','4756')} {
                        # A member was added to a security-enabled (global|local|universal) group.
                        $group = $xml.Event.EventData.Data[2].'#text'
                        # Check if group is Administrators, may later expand to all groups
                        if ($group -eq 'Administrators') {
                            $user = $xml.Event.EventData.Data[0].'#text'
                            $SID = $xml.Event.EventData.Data[1].'#text'
                            switch ($event.id) {
                                4728 {$o.Message = "User added to global $group group"}
                                4732 {$o.Message = "User added to local $group group"}
                                4756 {$o.Message = "User added to universal $group group"}
                            }
                            $o.Results = @"
Username: $user
User SID: $SID
"@
                            $o
                        }
                        break
                    }
                    '4625' {
                        # An account failed to log on.
                        # Requires auditing logon failures
                        # https://technet.microsoft.com/en-us/library/cc976395.aspx
                        $user = $null
                        $user = $xml.Event.EventData.Data[5].'#text'
                        if ($user) {
                            $totalfailedlogons++

                            if($failedlogons.ContainsKey($user)) {
                                $count = $failedlogons.Get_Item($user)
                                $failedlogons.Set_Item($user,$count+1)
                            } else {
                                $failedlogons.Set_Item($user,1)
                                $totalfailedaccounts++
                            }
                        }
                        break
                    }
                    '4673' {
                        # Sensitive Privilege Use (Mimikatz)
                        $totalsensprivuse++
                        # use -eq here to avoid multiple log notices
                        if ($totalsensprivuse -eq $maxtotalsensprivuse) {
                            $user = $xml.Event.EventData.Data[1].'#text'

                            $o.Message = 'Sensititive Privilege Use Exceeds Threshold'
                            $o.Results = @"
Potentially indicative of Mimikatz, multiple sensitive privilege calls have been made.
Username: $user
Domain Name: $( $xml.Event.EventData.Data[2].'#text')
"@
                            $o
                        }
                        break
                    }
                    '4648' {
                        # A logon was attempted using explicit credentials.
                        $user = $xml.Event.EventData.Data[1].'#text'
                        $hostname = $xml.Event.EventData.Data[2].'#text'
                        $targetusername = $xml.Event.EventData.Data[5].'#text'
                        # $sourceip = $xml.Event.EventData.Data[12].'#text' # sourceip var not used in code

                        # For each #4648 event, increment a counter in $passspraytrack. If that counter exceeds
                        # $passsprayloginmax, then check for $passsprayuniqusermax also exceeding threshold and raise
                        # a notice.
                        if ($null -eq $passspraytrack[$targetusername]) {
                            $passspraytrack[$targetusername] = 1
                        } else {
                            # $passspraytrack[$targetusername] += 1
                            $passspraytrack[$targetusername]++
                        }
                        if ($passspraytrack[$targetusername] -gt $passsprayloginmax) {
                            # This user account has exceedd the threshoold for explicit logins. Identify the total number
                            # of accounts that also have similar explicit login patterns.
                            $passsprayuniquser = 0
                            foreach($k in $passspraytrack.keys) {
                                if ($passspraytrack[$k] -gt $passsprayloginmax) {
                                    # $passsprayuniquser += 1
                                    $passsprayuniquser++
                                }
                            }
                            if ($passsprayuniquser -gt $passsprayuniqusermax) {
                                $users = ''
                                foreach($k in $passspraytrack.keys) {
                                    $users += $k
                                    $users += ' '
                                }
                                $o.Message = 'Distributed Account Explicit Credential Use (Password Spray Attack)'
                                $o.Results = @"
The use of multiple user account access attempts with explicit credentials is
an indicator of a password spray attack.
Target Usernames: $users
Accessing Username: $user
Accessing Host Name: $hostname
"@
                                $o
                                $passspraytrack = @{} # Reset
                            }
                        }
                        break
                    }
                    '1102' {
                        # Security 1102 Message is a blob of text that looks like this:
                        # The audit log was cleared.
                        # Subject:
                        # 	Security ID:	SEC504STUDENT\Sec504
                        # 	Account Name:	Sec504
                        # 	Domain Name:	SEC504STUDENT
                        # 	Logon ID:	0x257CD
                        $o.Message = 'Audit Log Clear'
                        $UserName = '{0}\{1}' -f $xml.Event.UserData.LogFileCleared.SubjectDomainName,
                        $xml.Event.UserData.LogFileCleared.SubjectUserName
                        $o.Results = 'The Audit log was cleared by {0}' -f $UserName
                        $o
                        break
                    }
                    default {}
                }
                break
            }
            'System' {
                switch ($e.id) {
                    '7045' {
                        # A service was installed in the system.
                        $servicename = $xml.Event.EventData.Data[0].'#text'
                        Write-Verbose -Message "Event ID 7045: Service Name $($servicename)"
                        $c = $xml.Event.EventData.Data[1].'#text'
                        # Check for suspicious service name
                        $text = (Get-RegexMatch -String $servicename -Type 1)
                        if ($text) {
                            $o.Message = 'New Service Created'
                            $o.Command = $c
                            $o.Results = @"
Service name: $servicename
$text
"@
                            $o
                        }
                        # Check for suspicious cmd
                        if ($c) {
                            $servicecmd = 1 # CLIs via service creation get extra checks
                            Get-SuspiciousCommand -CommandLine $c
                        }
                        break
                    }
                    '7030' {
                        # The ... service is marked as an interactive service.  However, the system is configured
                        # to not allow interactive services.  This service may not function properly.
                        # Check for suspicious service name
                        $servicecmd = 1 # CLIs via service creation get extra check
                        $servicename = $xml.Event.EventData.Data.'#text'
                        Write-Verbose -Message "Event ID 7030: Service Name $($servicename)"
                        $o.Message = 'Interactive service warning'
                        $o.Results = @"
Service name: $servicename
Malware (and some third party software) trigger this warning
$(Get-RegexMatch -String $servicename -Type 1)
"@
                        $o
                        break
                    }
                    '7036' {
                        # Other provider: VfpExt
                        # The  service entered the Driver load start state.
                        # The  service entered the Driver load complete state.
                        if ($xml.Event.System.Provider.Name -eq 'Service Control Manager') {
                        # The ... service entered the stopped|running state.
                        $servicename = $xml.Event.EventData.Data[0].'#text'
                        $text = (Get-RegexMatch -String $servicename -Type 1)
                        Write-Verbose -Message "Event ID 7036: Service Name $($servicename)"
                        if ($text) {
                            $o.Message = 'Suspicious Service Name'
                            $o.Results = @"
Service name: $servicename
$text
"@
                            $o
                        }
                        }
                        break
                    }
                    '7040' {
                        # The start type of the Windows Event Log service was changed from auto start to disabled.
                        $servicename = $xml.Event.EventData.Data[0].'#text'
                        Write-Verbose -Message "Event ID 7040: Service Name $($servicename)"
                        $action = $xml.Event.EventData.Data[1].'#text'
                        if ($servicename -ccontains 'Windows Event Log') {
                            $o.Results = @"
Service name: $servicename
$text
"@
                            if ($action -eq 'disabled') {
                                $o.Message = 'Event Log Service Stopped'
                                $o.Results += 'Selective event log manipulation may follow this event.'
                            } elseif ($action -eq 'auto start') {
                                $o.Message = 'Event Log Service Started'
                                $o.Results += 'Selective event log manipulation may precede this event.'
                            }
                            $o
                        }
                        break
                    }
                    '104' {
                        $UserName = '{0}\{1}' -f $xml.Event.UserData.LogFileCleared.SubjectDomainName,
                        $xml.Event.UserData.LogFileCleared.SubjectUserName
                        $o.Message = 'A Log was cleared'
                        $o.Results = "The log '$($xml.Event.UserData.LogFileCleared.Channel)' was cleared by user $($UserName)"
                        $o
                        break
                    }
                    default {}
                }
                break
            }
            'Application' {
                if (($e.id -eq 2) -and ($e.Providername -eq 'EMET')) {
                    # EMET Block
                    $o.Message = 'EMET Block'
                    if ($e.Message) {
                        # EMET Message is a blob of text that looks like this:
                        #########################################################
                        # EMET detected HeapSpray mitigation and will close the application: iexplore.exe
                        #
                        # HeapSpray check failed:
                        #   Application   : C:\Program Files (x86)\Internet Explorer\iexplore.exe
                        #   User Name     : WIN-CV6AHH1BNU9\Instructor
                        #   Session ID    : 1
                        #   PID           : 0xBA8 (2984)
                        #   TID           : 0x9E8 (2536)
                        #   Module        : mshtml.dll
                        #  Address       : 0x6FBA7512, pull out relevant parts
                        $array = $e.message -split '\n' # Split each line of the message into an array
                        $text = $array[0]
                        $application = ($array[3]).trim() -Replace '\s+:',':'
                        $command= $application -Replace '^Application: ',''
                        $user = ($array[4]).trim() -Replace '\s+:',':'
                        $o.Message = 'EMET Block'
                        $o.Command = "$command"
                        $o.Results = @"
$text
$user
"@
                    } else {
                        # If the message is blank: EMET is not installed locally.
                        # This occurs when parsing remote event logs sent from systems with EMET installed
                        $o.Message = 'Warning: EMET Message field is blank. Install EMET locally to see full details of this alert'
                    }
                    $o
                }
                break
            }
            'Applocker' {
                Switch -Regex ($e.id) {
                    '800(3|6)' {
                        # ...was allowed to run but would have been prevented from running if the AppLocker policy were enforced.
                        $o.Message = 'Applocker Warning'
                        $o.Command = "$($e.message -Replace ' was .*$','')"
                        $o.Results = $e.message
                        $o
                        break
                    }
                    '800(4|7)' {
                        # ...was prevented from running.
                        $o.Message = 'Applocker Block'
                        $o.Command = "$($e.message -Replace ' was .*$','')"
                        $o.Results = $e.message
                        $o
                        break
                    }
                    default {}
                }
                if($AddApplockerAllowEvents) {
                    Switch -Regex ($e.id) {
                        '800(2|5)' {
                            # ...was allowed to run.
                            $o.Message = 'Applocker Allow'
                            $o.Command = "$($e.message -Replace ' was .*$','')"
                            $o.Results = $e.message
                            $o
                            break
                        }
                        default {}
                    }
                }
                break
            }
            'PowerShell' {
                Switch ($e.id) {
                    '4103' {
                        $c = $xml.Event.EventData.Data[2].'#text'
                        if ($c -Match 'Host Application') {
                            # Multiline replace, remove everything before 'Host Application = '
                            $c = $c -Replace '(?ms)^.*Host.Application = ',''
                            # Remove every line after the 'Host Application = ' line.
                            $c = $c -Replace "(?ms)`n.*$",''
                            if ($c) {
                              Get-SuspiciousCommand -CommandLine $c
                            }
                        }
                        break
                    }
                    '4104' {
                        # This section requires PowerShell command logging for event 4104 , which seems to be default with
                        # Windows 10, but may not not the default with older Windows versions (which may log the script
                        # block but not the command that launched it).
                        # Caveats included because more testing of various Windows versions is needed
                        #
                        # If the command itself is not being logged:
                        # Add the following to \Windows\System32\WindowsPowerShell\v1.0\profile.ps1
                        # $LogCommandHealthEvent = $true
                        # $LogCommandLifecycleEvent = $true
                        #
                        # See the following for more information:
                        #
                        # https://logrhythm.com/blog/powershell-command-line-logging/
                        # http://hackerhurricane.blogspot.com/2014/11/i-powershell-logging-what-everyone.html
                        #
                        # Thank you: @heinzarelli and @HackerHurricane
                        #
                        # The command's path is $xml.Event.EventData.Data[4]
                        #
                        # Blank path means it was run as a commandline. CLI parsing is *much* simpler than
                        # script parsing. See Revoke-Obfuscation for parsing the script blocks:
                        #
                        # https://github.com/danielbohannon/Revoke-Obfuscation
                        #
                        # Thanks to @danielhbohannon and @Lee_Holmes
                        #
                        # This ignores scripts and grabs PowerShell CLIs
                        if (-not ($xml.Event.EventData.Data[4].'#text')) {

                            # $xml.Event.System.Level -eq 5 # Verbose
                            # Warning
                            if ($AddPowerShellInfoEvents -or ($xml.Event.System.Level -eq 3)) {

                                # if it's partial? we want to skip it
                                # <Data Name="MessageNumber">1</Data>
                                # <Data Name="MessageTotal">1</Data>
                                if ($xml.Event.EventData.Data[0].'#text' -eq $xml.Event.EventData.Data[1].'#text') {

                                    $c = $xml.Event.EventData.Data[2].'#text'
                                    if ($c) {
                                        # has scriptblock
                                        if ($c -notmatch "^-----BEGIN CMS-----`n") {
                                            Get-SuspiciousCommand -CommandLine $c
                                        } else {
                                            # it's an encrypted scriptblock
                                        }
                                    }
                                } else {
                                    # is partial
                                }
                            }
                        }
                        break
                    }
                    default {}
                }
                break
            }
            'Sysmon' {
                Switch ($e.id) {
                    '1' {
                    # Check command lines
                        $creator = $xml.Event.EventData.Data[14].'#text'
                        $c = $xml.Event.EventData.Data[4].'#text'
                        if ($c) {
                            Get-SuspiciousCommand -CommandLine $c
                        }
                        break
                    }
                    '7' {
                        # Check for unsigned EXEs/DLLs:
                        # This can be very chatty, so it's disabled.
                        # Set $checkunsigned to 1 (global variable section) to enable:
                        if ($checkunsigned) {
                            if ($xml.Event.EventData.Data[6].'#text' -eq 'false') {
                                $o.Message = 'Unsigned Image (DLL)'
                                # $hash = $xml.Event.EventData.Data[5].'#text'
                                $o.Command = "$($xml.Event.EventData.Data[4].'#text')"
                                $o.Results = "Loaded by: $($xml.Event.EventData.Data[3].'#text')"
                                $o
                             }
                         }
                        break
                    }
                    default {}
                }
                break
            }
            default {}
        } #endof logname switch
    }

    # Iterate through admin logons hashtable (key is $user)
    foreach ($u in $adminlogons.Keys) {
        $SID = $adminlogons.Get_Item($u)
        if($multipleadminlogons.$u) {
            $o.EventID = 9999
            $o.Date = $events[0].TimeCreated.AddSeconds(1)
            $o.Message = 'Multiple admin logons for one account'
            $o.Results = @"
Username: $u
User SID Access Count: $($SID.split().Count)
"@
            $o
        }
    }
    # Iterate through failed logons hashtable (key is $u)
    foreach ($u in $failedlogons.Keys) {
        $count = $failedlogons.Get_Item($u)
        if ($count -gt $maxfailedlogons) {
            $o.EventID = 9998
            $o.Date = $events[0].TimeCreated.AddSeconds(1)
            $o.Message = 'High number of logon failures for one account'
            $o.Results = @"
Username: $u
Total logon failures: $count
"@
            $o
        }
    }
    # Password spraying:
    if (($totalfailedlogons -gt $maxfailedlogons) -and ($totalfailedaccounts -gt 1)) {
        $o.Date = $events[0].TimeCreated.AddSeconds(1)
        $o.EventID = 9997
        $o.Message = 'High number of total logon failures for multiple accounts'
        $o.Results = @"
Total accounts: $totalfailedaccounts
Total logon failures: $totalfailedlogons
$($failedlogons.Keys| ForEach-Object {'{0}:{1}{2}' -f $_,$failedlogons["$($_)"],"`n" })
"@
        $o
    }

}
End {}
}
