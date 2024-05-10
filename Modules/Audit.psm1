<#
.SYNOPSIS
    Gets an abbreviated set of info about NTLMv1 logon events.
    
.DESCRIPTION
    This script queries the Windows Security eventlog for NTLMv1 logons in eventid 4624. The number of events returned is configurable. Whether null session logon events are included is configurable. It can be run against all domain controllers, a remote member server, or the localhost. If used against anything other than the localhost, WinRM is required to be listening on those remote hosts. If used against DCs, the ActiveDirectory PS module is required. 

.EXAMPLE
    Get-NtlmV1LogonEvents
    
    Gets the last 30 NTLMv1 logon events from the localhost.

.EXAMPLE
    Get-NtlmV1LogonEvents -NumEvents 100

    Gets the last 10 NTLMv1 logon events from the localhost.

.EXAMPLE
    Get-NtlmV1LogonEvents -Target clay.pottery.uw.edu

    Gets the last 30 NTLMv1 logon events from clay.pottery.uw.edu via WinRM.

.EXAMPLE
    Get-NtlmV1LogonEvents -Target DCs

    Gets the last 30 NTLMv1 logon events on each domain controller in the domain of the localhost. Leverages WinRM and ActiveDirectory PS module.

.EXAMPLE
    Get-NtlmV1LogonEvents -NullSession $false

    Gets the last 30 NTLMv1 logon events--excluding null session logons--from the localhost.
    
.PARAMETER NumEvents
    An optional parameter that overrides the default value of 30. Enter a string indicating the desired number of events to return (per host).
        
.PARAMETER Target
    An optional parameter that specifies the target computer(s). By default, the localhost is targeted. Valid values are "DCs" or any fully qualified DNS hostname that resolves. If you use this parameter, the remote computer must be able to accept WS-Man requests. You may need to do a "winrm quickconfig" on that remote computer to enable this.

.PARAMETER NullSession
    An optional parameter that enables you to filter out all null session NTLMv1 logons. By default, all NTLMv1 logons including null sessions are included. If you'd like to filter out null sessions, use this parameter. This parameter can make it much easier to find identifiable users to contact.
            
.NOTES
    Author  : Eric Kool-Brown - kool@uw.edu
    Author  : Brian Arkills - barkills@uw.edu
    Created : 04/08/2014
    
.LINK
    UWWI Documentation
        https://wiki.cac.washington.edu/display/uwwi/NTLMv1+Removal+-+problems%2C+solutions+and+workarounds
    
.LINK
    TechNet The Most Misunderstood Windows Security Setting of All Time
        http://technet.microsoft.com/en-us/magazine/2006.08.securitywatch.aspx
#>

function Get-NtlmV1LogonEvents {
    [cmdletbinding()]
    param(
        [Int64]$NumEvents = 10000030,
        [boolean]$NullSession = $true,
        [string]$Target = "."
    )
$CurentDate=Get-Date -Format "yyyy-MM-dd HH-mm-ss"
    if ($NullSession) {
        # This finds NTLM V1 logon events
        $NtLm1Filter = "Event[System[(EventID=4624)]]and Event[EventData[Data[@Name='LmPackageName']='NTLM V1']]" 
    }
    else {
        # This finds NTLM V1 logon events without null session logons
        $NtLm1Filter = "Event[System[(EventID=4624)]]and Event[EventData[Data[@Name='LmPackageName']='NTLM V1']] and Event[EventData[Data[@Name='TargetUserName']!='ANONYMOUS LOGON']]"
    }

    if ($Target -eq ".") {
        Write-Host "Querying security log for NTLM V1 events (ID 4624) on localhost"

        Get-WinEvent -Logname security -MaxEvents $NumEvents -FilterXPath $Ntlm1Filter |
            select @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},
                   @{Label='UserName';Expression={$_.Properties[5].Value}},
                   @{Label='WorkstationName';Expression={$_.Properties[11].Value}},
                   @{Label="LogonType";Expression={$_.properties[8].value}},
                   @{Label="ImpersonationLevel";Expression={$_.properties[20].value}},
                   @{Label="AuthenticationPackageName";Expression={$_.properties[10].value}},
                   @{Label="LmPackageName";Expression={$_.properties[14].value}},
                   @{Label="IpAddress";Expression={$_.properties[18].value}}
    }   
    else {
        #using winRM
        $remoteScript = {
            Get-WinEvent -Logname security -MaxEvents $Using:NumEvents -FilterXPath $Using:Ntlm1Filter |
                select @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},
                       @{Label='UserName';Expression={$_.Properties[5].Value}},
                       @{Label='WorkstationName';Expression={$_.Properties[11].Value}},
                       @{Label="LogonType";Expression={$_.properties[8].value}},
                       @{Label="ImpersonationLevel";Expression={$_.properties[20].value}},
                       @{Label="AuthenticationPackageName";Expression={$_.properties[10].value}},
                       @{Label="LmPackageName";Expression={$_.properties[14].value}},
                       @{Label="IpAddress";Expression={$_.properties[18].value}}
        }


        if ($Target -eq "DCs") {
            Import-Module ActiveDirectory
            $dcs = Get-ADDomainController -Filter * | select -expand hostname

            Write-Host "Querying security log for NTLM V1 events (ID 4624) on DCs $dcs"

            Invoke-Command -ComputerName $dcs -ScriptBlock $remoteScript | Select -Property Time,UserName,WorkstationName,LogonType,ImpersonationLevel,PSComputerName | Export-csv "..\Outputs\NTLMV1_$CurrebtDate.csv" -NoTypeInformation
        }
        else {
            Write-Host "Querying security log for NTLM V1 events (ID 4624) on remote host: $Target"

            Invoke-Command -ComputerName $Target -ScriptBlock $remoteScript | Select -Property Time,UserName,WorkstationName,LogonType,ImpersonationLevel,PSComputerName | Export-csv "..\Outputs\NTLMV1_$CurrebtDate.csv"  -NoTypeInformation
        }
    }
}
Export-ModuleMember -Function * 