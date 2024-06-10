Function Set-WindowsLapsPermissions {
    param(
        
    )
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $result = 0
     ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Try { 
            Import-Module ActiveDirectory
        } 
        Catch {
            $noError = $false
            $result = 2
            $ResMess = "AD module not available."
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ")+$ResMess
        }
    }
     if ($result -ne 2) {
       
      
            #.Loading module
            Try {
                Import-Module LAPS -ErrorAction Stop
            }
            Catch {
                $result = 2
                $ResMess = "Failed to load module LAPS."
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ")+$ResMess
            }

            #.If no critical issue, the following loop will proceed with fine delegation
            if ($result -ne 2) {
                #.Get xml data
                Try {
                    $cfgXml = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)
                }
                Catch {
                    $ResMess = "Failed to load configuration file"
                    $result = 2
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ")+$ResMess
                }
            }
            if ($result -ne 2) {
                #.Granting SelfPermission
                $Translat = $cfgXml.Settings.Translation
                $Granting = $cfgXml.Settings.LocalAdminPasswordSolution.AdmPwdSelfPermission
                foreach ($Granted in $Granting) {
                    Try {
                        $TargetOU = $Granted.Target
                        foreach ($transID in $translat.wellKnownID) {
                            $TargetOU = $TargetOU -replace $TransID.translateFrom, $TransID.translateTo
                        }
                     $re=Set-LapsADComputerSelfPermission  -Identity $TargetOU -ErrorAction Stop
                     $ResMess = "Selfpermession Success on $TargetOU"
                     $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ")+$ResMess
                    }
                    
                    Catch {
                        $result = 1
                        $ResMess = "Failed to apply Permission on $TargetOU"
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ")+$ResMess+$_
                        # Write-Host $_.Exception.Message
                        # Write-Host $TargetOU
                        # Pause
                    }
                }
                #.Getting Domain Netbios name
                $NBname = (Get-ADDomain).netBiosName

                #.Granting Password Reading Permission
                $Granting = $cfgXml.Settings.LocalAdminPasswordSolution.AdmPwdPasswordReader
                foreach ($Granted in $Granting) {
                    Try {
                        $TargetOU = $Granted.Target
                        $GrantedId = $Granted.Id
                        foreach ($transID in $translat.wellKnownID) {
                            $TargetOU = $TargetOU -replace $TransID.translateFrom, $TransID.translateTo
                            $GrantedId = $GrantedId -replace $TransID.translateFrom, $TransID.translateTo
                        }
                        Set-LapsADReadPasswordPermission -Identity:$TargetOU -AllowedPrincipals $GrantedId
                        $ResMess = "Readpermession Success on $TargetOU"
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ")+$ResMess
                    }
                    Catch {
                        $result = 1
                        $ResMess = "Failed to apply Permission on one or more OU."
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ")+$ResMess
                    
                    }
                }

                #.Granting Password Reset Permission
                $Granting = $cfgXml.Settings.LocalAdminPasswordSolution.AdmPwdPasswordReset
                foreach ($Granted in $Granting) {
                    Try {
                        $TargetOU = $Granted.Target
                        $GrantedId = $Granted.Id
                        foreach ($transID in $translat.wellKnownID) {
                            $TargetOU = $TargetOU -replace $TransID.translateFrom, $TransID.translateTo
                            $GrantedId = $GrantedId -replace $TransID.translateFrom, $TransID.translateTo
                        }
                       Set-LapsADResetPasswordPermission -Identity:$TargetOU -AllowedPrincipals $GrantedId
                        $ResMess = "Resetpermession Success on $TargetOU"
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ")+$ResMess
                    }
                    Catch {
                        $result = 1
                        $ResMess = "Failed to apply Permission on one or more OU."
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ")+$ResMess
                    }
                }
        }
    }
     $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Logs\Debug\$DbgFile -Append
    
    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}
Function UpdateSchema-WindowsLAPS {
    <#
        .Synopsis
         To be deployed, LAPS need to update the AD Schema first.
        
        .Description
         The script first update the schema, then it will install the management tool.

        .Notes
         Version: 01.00 -- contact@hardenad.net 
		 Version: 01.01 -- contact@hardenad.net 
         
         history: 21.08.22 Script creation
				  16.07.22 Update to use dynamic translation - removed debug log
    #>
    param(
        [Parameter(mandatory = $true, Position = 0)]
        [ValidateSet('ForceDcIsSchemaOwner', 'IgnoreDcIsSchemaOwner')]
        [String]
        $SchemaOwnerMode
    )

    $result = 0

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Try { 
            Import-Module ActiveDirectory
        } 
        Catch {
            $noError = $false
            $result = 2
            $ResMess = "AD module not available."
        }
    }
    ## Load Task sequence
    $xmlSkeleton = [xml](Get-Content "$PSScriptRoot\..\Configs\TasksSequence_HardenAD.xml" -Encoding utf8)
    $RootDomainDns = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Rootdomaindns%" }).translateTo

    ## Check prerequesite: running user must be member of the Schema Admins group and running computer should be Schema Master owner.
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isSchemaAdm = Get-ADGroupMember -Recursive ((Get-ADDomain -Server $RootDomainDns).DomainSID.value + "-518") -Server $RootDomainDns | Where-Object { $_.SID -eq $CurrentUser.User }

    $CurrentCptr = $env:COMPUTERNAME
    $isSchemaOwn = (Get-ADForest).SchemaMaster -eq ($currentCptr + "." + (Get-ADDomain).DnsRoot)

    ## Check if a bypass has been requested for the schema master owner condition
    if ($SchemaOwnerMode -eq 'IgnoreDcIsSchameOwner') {
        $isSchemaOwn = $true
    }

    if ($isSchemaAdm -and $isSchemaOwn) {
        ## User has suffisant right, the script will then proceed.
        ## First, we need to install the pShell add-ons to be able to update the schema.
        
        
        ## If the install is a success, then let's update the schema
        if ($result -eq 0) {
            Try {
                Import-Module LAPS -ErrorAction Stop -WarningAction Stop
                $null =Update-LapsADSchema
            }
            Catch {
                $result = 1
                $ResMess = "LAPS installed but the schema extension has failed (warning: .Net 4.0 or greater requiered)"
            }
        }
        Else {
            $result = 1
            $ResMess = "The schema extension has been canceled"
        }
    }
    Else {
        $result = 2
        $ResMess = "The user is not a Schema Admins (group membership with recurse has failed)"
    }

    ## Exit
    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}
Export-ModuleMember -Function *