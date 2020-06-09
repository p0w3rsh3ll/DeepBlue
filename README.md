DeepBlue module
===============

At RSA Conference 2020, in this video **[The 5 Most Dangerous New Attack Techniques and How to Counter Them](https://www.youtube.com/watch?v=xz7IFVJf3Lk&t=238s)**, Ed Skoudis presented a way to look for log anomalies - **[DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)** by Eric Conrad, et al.

## Intent

The main intent is to make this original **DeepBlueCLI - a PowerShell Module for Threat Hunting via Windows Event Logs** - from **Eric Conrad** [@eric_conrad](https://twitter.com/eric_conrad):

 * available as a PowerShell module contained in a single .psm1 file 
 * expose a single function with many parameters
 * more aligned with what PowerShell can do and other PowerShell coding style standards

Please read what the original DeepBlueCLI can do in its [README](https://github.com/sans-blue-team/DeepBlueCLI/blob/master/README.md)

<a name="Usage"/>

## Usage

<a name="Install"/>

### Install the module

Download the zip and unzip it (see known issues).

Stop and please review the content of the module, I mean the code to make sure it's trustworthy :-)

You can also verify that the SHA256 hashes of downloaded files match those stored in the catalog file:
```powershell
# Verify
$HT = @{
    CatalogFilePath = "./DeepBlue.cat"
    Path = "./"
    Detailed = $true
    FilesToSkip = 'README.md'
}
Test-FileCatalog @HT
```

Import the module
```powershell
# Import the module
Import-Module .\DeepBlue.psd1 -Force -Verbose
```

<a name="Functions"/>

### Check the command available
```powershell
Get-Command -Module DeepBlue
```
```
CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Get-DeepBlueAnalysis                               1.0.0      DeepBlue
```

<a name="Help"/>

### Find the syntax

```powershell
# View the syntax
Get-Command Get-DeepBlueAnalysis -Syntax
```
```
Get-DeepBlueAnalysis [-Log <string>] [-MaxFailedLogons <Object>] [-MaxAdminLogons <Object>] [-MaxTotalSensPrivUse <Object>] [-AlertAllAdmin] [-CheckUnsigned] [-PassSprayUniqUserMax <Object>] [-PassSprayLoginMax <Object>] [-MinPercent <Object>] [-MaxBinary <Object>] [<CommonParameters>]

Get-DeepBlueAnalysis -File <string> [-MaxFailedLogons <Object>] [-MaxAdminLogons <Object>] [-MaxTotalSensPrivUse <Object>] [-AlertAllAdmin] [-CheckUnsigned] [-PassSprayUniqUserMax <Object>] [-PassSprayLoginMax <Object>] [-MinPercent <Object>] [-MaxBinary <Object>] [<CommonParameters>]
```
The only difference is the first parameter. It reads either a 'Log' or a 'File'.

It means that the -File parameter makes this module cross-platform.

You can read any exported evtx files on a Linux or MacOS running PowerShell.

The original repo of [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) by Eric Conrad, et al. has a **[evtx](https://github.com/sans-blue-team/DeepBlueCLI/tree/master/evtx)** folder with sample files.

### View examples provided in the help
```powershell
# Get examples from the help
 Get-Help Get-DeepBlueAnalysis  -Examples
```
```
NAME
    Get-DeepBlueAnalysis

SYNOPSIS
    A PowerShell module for hunt teaming via Windows event logs


    -------------------------- EXAMPLE 1 --------------------------

    PS C:\>Get-DeepBlueAnalysis

    Processes the local Windows security event log.




    -------------------------- EXAMPLE 2 --------------------------

    PS C:\>Get-DeepBlueAnalysis -Log System

    Processes the local Windows system event log.




    -------------------------- EXAMPLE 3 --------------------------

    PS C:\>Get-DeepBlueAnalysis -File .\evtx\new-user-security.evtx

    Processes an evtx file.
```

## Issues

Defender (AMSI) detects the regular expressions as [Trojan:PowerShell/PSAttackTool.A](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=Trojan%3aPowerShell%2fPSAttackTool.A&threatid=2147729106).

You may need to create an exclusion the file, folder or process or create "allowed threats".

## Credits

* Eric Conrad [@eric_conrad](https://twitter.com/eric_conrad) 

## Todo

- [ ] Digitally sign the module files.
- [ ] Make it available on the [PowerShellGallery](https://www.powershellgallery.com/).
- [ ] Document the parameters in the Help.
- [x] Write Pester unit tests for this module.