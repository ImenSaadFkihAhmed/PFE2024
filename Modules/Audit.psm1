Function Get-NtlmV1LogonEvents {
   
    param(
        
    )
    $NumEvents=100
    $CurrentDate=Get-Date -Format "yyyy-MM-dd HH-mm-ss"
    $NtLm1Filter = "Event[System[(EventID=4624)]]and Event[EventData[Data[@Name='LmPackageName']='-']]"
    $Events =  Get-WinEvent -Logname security -MaxEvents $NumEvents -FilterXPath $Ntlm1Filter |
            select @{Label='Time';Expression={$_.TimeCreated.ToString('g')}},
                   @{Label='UserName';Expression={$_.Properties[5].Value}},
                   @{Label='WorkstationName';Expression={$_.Properties[11].Value}},
                   @{Label="LogonType";Expression={$_.properties[8].value}},
                   @{Label="ImpersonationLevel";Expression={$_.properties[20].value}},
                   @{Label="AuthenticationPackageName";Expression={$_.properties[10].value}},
                   @{Label="LmPackageName";Expression={$_.properties[14].value}},
                   @{Label="IpAddress";Expression={$_.properties[18].value}}
$ResMess="sucess"
$Result=0
try{
            $Events | Out-File ".\Outputs\NTLM_$CurrentDate.txt"
           }
catch { 
	$result=1
        $ResMess = "Failed "
}	

    return (New-Object -TypeName psobject -Property @{ ResultCode = $result ; ResultMesg = "" ; TaskExeLog = "" })
}
Export-ModuleMember -Function * 