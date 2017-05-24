#requires -version 3
#requires -module VMware.VimAutomation.Core

<#
.DESCRIPTION
Connects to one or more vCenter Servers and obtains the IP address for each VM.

.NOTES
    Script:          Invoke-VMNetworkReportXL.ps1
    Author:          Mike Nisk
    Organization:    vmkdaily
    Tested on:       PowerShell 5.1, PowerCLI 6.5.1
    Should Support:  PowerShell 3 or later; PowerCLI 5.x or later

.PARAMETER Computer
String. IP Address or DNS Name for one or more vCenter Server machines

.PARAMETER Credential
PSCredential. The login for your vCenter (i.e. $creds = Get-Credential)

.PARAMETER FallBackCredential
PSCredential. A secondary credential to try.
Cannot be the same user name as Credential (to prevent accidental lockouts).
Please note that using the FallBackCredential can increase delay on smaller runs.
When targeting large numbers of vCenters, the fallback feature speeds up.

.PARAMETER ReportPath
String. The full path including file extension for your output report (i.e. "c:\temp\VMReport.csv")

.PARAMETER PassThrough
Switch. Not related to authentication.  If reporting to CSV (default) then activating this switch will also return results on screen (i.e. returns the report object).

.PARAMETER AutoLaunch
Switch. Uses Invoke-Item to launch the CSV report upon completion

.PARAMETER Location
String. Optionally enter the VI Location to enumerate VMs from.  Options include folder, cluster, resource pool, etc.

.PARAMETER CredentialPath
String. Optionally enter the path to an encrypted credential file.

.PARAMETER FallBackCredentialPath
String. Optionally enter an additional path to an encrypted credential file.

Example #1 - Use pass through auth and get a VM network report saved to $report
.EXAMPLE
$report = .\Invoke-VMNetworkReportXL.ps1 -Computer vcenter01.lab.local

Example #2 - Save a credential then run report, saving it to CSV in the default location.
.EXAMPLE
$creds = Get-Credential administrator@vsphere.local
.\Invoke-VMNetworkReportXL.ps1 -Computer vcenter01.lab.local -Credential $creds -SaveReport -AutoLaunch -Verbose

Example #3 - Save report to custom location
.EXAMPLE
.\Invoke-VMNetworkReportXL.ps1 -Computer vcenter01.lab.local -ReportPath "c:\temp\VMReport.csv" -AutoLaunch

Example #4 - Save to $report variable
.EXAMPLE
PS C:\> $report = .\Invoke-VMNetworkReportXL.ps1 -Computer vcva02.lab.local -Verbose
VERBOSE: Starting Invoke-VMNetworkReportXL.ps1 at 5/24/2017 1:05:31 AM local time.
VERBOSE: ..Processing vcva02.lab.local
VERBOSE: No valid runtime credentials found
VERBOSE: ..Trying Passthrough as LAB\vmadmin
VERBOSE: Attempting to connect using SSPI
VERBOSE: Reversely resolved 'vcva02.lab.local' to 'vcva02'
VERBOSE: SSPI Kerberos: Acquired credentials for user 'LAB\vmadmin'
VERBOSE: SSPI Kerberos: Successful call to InitializeSecurityContext for target 'host/vcva02'
VERBOSE: Connected successfully using SSPI
VERBOSE: Connected to vpx api on vcva02.lab.local
VERBOSE: 5/24/2017 1:05:32 AM Get-VM Started execution
VERBOSE: 5/24/2017 1:05:33 AM Get-VM Finished execution
VERBOSE: 5/24/2017 1:05:34 AM Disconnect-VIServer Started execution
VERBOSE: 5/24/2017 1:05:34 AM Disconnect-VIServer Finished execution
VERBOSE: Ending Invoke-VMNetworkReportXL.ps1 at 5/24/2017 1:05:34 AM local time
PS C:\>
PS C:\> $report

Name                 IP Address   ParentVC
----                 ----------   --------
vcva02-tmp.lab.local 10.202.3.205 vcva02.lab.local
DC02                 10.202.3.250 vcva02.lab.local
SG01                 10.202.4.201 vcva02.lab.local
influxweb04          10.202.3.220 vcva02.lab.local
DC01                 10.202.3.240 vcva02.lab.local
JUMP01               10.202.3.249 vcva02.lab.local
vvnx01               10.202.6.248 vcva02.lab.local

PS C:\>
This example showed how to save the report to a variable.
Using this example, you can then view the report or save
to CSV by performing $report | Export-CSV <path-to-output>.csv
Alternatively, use the SaveReport parameter to save at runtime.

#>

[CmdletBinding()]
Param(

    #Computer
    [string[]]$Computer,
    
    #Main Credential
    [System.Management.Automation.Credential()][PSCredential]$Credential,
    
    #FallBack Credential
    [ValidateScript({
        
        #validation for FallBackCredential
        #first, we look at the main cred
        If($Credential){
            If(($Credential.GetNetworkCredential().UserName) -notmatch ($_.GetNetworkCredential().UserName)) {
                return $true
            }
            #prevent accidental user lockouts
            Else {
                Throw 'You cannot provide the same user name twice'
            }
        }
        Else {
            Throw 'To use FallBackCredential, the Credential parameter must also be populated!'
        }

    })]
    [System.Management.Automation.Credential()][PSCredential]$FallBackCredential,
    
    #SaveReport
    [switch]$SaveReport = $false,
    
    #Report Path
    [string]$ReportPath,
    
    #Support for Object PassThrough
    [switch]$PassThrough,
    
    #Auto Launch CSV Report
    [switch]$AutoLaunch,
    [ValidateScript({
        If(-Not(Test-Path -Path $_)) {
            return $true}
        Else {
            Throw 'Location should be VIContainer name (not a path!)'
        }
    })]

    #VI Location (i.e. Name of folder, cluster, resource pool, or datacenter)
    [string]$Location,

    #optional Credential from path (i.e. 'c:\credential.enc.xml')
    [string]$CredentialPath,
    
    #optional FallBackCredential path (i.e. 'c:\FallBackcredential.enc.xml')
    [string]$FallBackCredentialPath

)

Begin {

    ## optionally hard code path to encrypted creds
    If(-Not($CredentialPath)) {
        #The default is ''
        #Optionally, modify to something like 'c:\credential.enc.xml'
        #or use the runtime Parameters instead of hardcoded
        $CredentialPath = ''
    }
    If(-Not($FallBackCredentialPath)) {
        #The default is ''
        #Optionally, modify to something like 'c:\FallBackcredential.enc.xml')
        #or use the runtime Parameters instead of hardcoded
        $FallBackCredentialPath = ''
    }

    Write-Verbose -Message ('Starting {0} at {1} local time.' -f $MyInvocation.Mycommand, (Get-Date))

    #date for report
    $dt = Get-Date -format 'ddMMMyyyy_hhmm'
    
    #here we make SaveReport parameter optional,
    #if user populated the ReportPath parameter.
    If($ReportPath) {
        $SaveReport = $true
    }

    #default report name
    If($SaveReport) {
        if(-Not($Reportpath)) {
            [string]$Reportpath = ('{0}\VMNetworkReport-{1}.csv' -f $Env:Temp, $dt)
        }
    }

    #disconnect any current sessions
    If($Global:DefaultVIServers) {
        try{
            $null = Disconnect-VIServer -Server '*' -Confirm:$false -Force -ea 0
        }
        Catch {
          # get error record
          [Management.Automation.ErrorRecord]$e = $_

          # retrieve information about runtime error
          $info = [PSCustomObject]@{
            Exception = $e.Exception.Message
            Reason    = $e.CategoryInfo.Reason
            Target    = $e.CategoryInfo.TargetName
            Script    = $e.InvocationInfo.ScriptName
            Line      = $e.InvocationInfo.ScriptLineNumber
            Column    = $e.InvocationInfo.OffsetInLine
          }
          
          # output information.
          $info
        }
    }

    ## function to handle optional static cred feature
    Function Import-PSCredential {
     
      <#
      .DESCRIPTION
        Imports a PSCredential from an encrypted xml file on disk.
            
      .NOTES
        Script:         Import-PSCredential.ps1
        Type:           Function
        Author:         Hal Rottenberg

      .PARAMETER Path
      Path to encrypted xml credential file.
        
      .EXAMPLE
      Import-PSCredential -Path <path to cred file>

      #>

      [CmdletBinding()]
      param (
            
      [ValidateScript({Test-Path -Path $_})]
      [string]$Path = 'credentials.enc.xml' )

      Process {

          if($Path) {
              # Import credential file
              $import = Import-Clixml -Path $Path 

              # Test for valid import
              if(!$import.UserName -or !$import.EncryptedPassword) {
                  Throw 'Input is not a valid ExportedPSCredential object, exiting.'
              }
              $Username = $import.Username

              # Decrypt the password and store as a SecureString object for safekeeping
              $SecurePass = $import.EncryptedPassword | ConvertTo-SecureString

              # Build the new credential object
              $CredObj = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePass
              Write-Output -InputObject $CredObj
          }
          Else {
              Write-Warning -Message ('Problem reaching path {0}' -f $Path)
          }
      } #End process
  } #End Function
} #End Begin

Process {
    
    #handle static creds, if any
    If($CredentialPath) {
        try {
            [PSCredential]$CredentialFromPath = Import-PSCredential -Path $CredentialPath -Verbose -ea Stop
        }
        catch {
            Write-Warning -Message ('{0}' -f $_.Exception.Message)
            Write-Warning -Message ('Problem with CredentialPath {0}' -f $CredentialPath)
        }
    }

    If($FallBackCredentialPath) {
        try {
            [PSCredential]$FallBackCredentialFromPath = Import-PSCredential -Path $FallBackCredentialPath -Verbose -ea Stop
        }
        catch {
            Write-Warning -Message ('{0}' -f $_.Exception.Message)
            Write-Warning -Message ('Problem with FallBackCredentialPath {0}' -f $FallBackCredentialPath)
        }
    }

    $Report = @()
    Foreach($vc in $Computer) {

        Write-Verbose -Message ('..Processing {0}' -f $vc)
        if(Test-Connection -ComputerName $vc -Count 1 -ErrorAction Continue) {

            If($Credential) {

                ## try the main Credential
                Try {
                    $null = Connect-VIServer -Server $vc -Credential $Credential -ErrorAction Stop -WarningAction SilentlyContinue
                    Write-Verbose -Message ('Using provided Credential of {0}' -f $Credential.GetNetworkCredential().UserName)
                }
                Catch {

                    ## quietly move on to fall-back creds (if any)
                    If($FallBackCredential) {

                        Try { 
                            $null = Connect-VIServer -Server $vc -Credential $FallBackCredential -ErrorAction Stop -WarningAction SilentlyContinue
                            Write-Verbose -Message ('Using FallBackCredential of {0}' -f $FallBackCredential.GetNetworkCredential().UserName)
                        }
                        Catch {
                            Write-Warning -Message ('Error Detected! {0}' -f $_.Exception.Message)
                            Write-Warning -Message ('Problem connecting to vCenter {0} using FallBackCredential credentials' -f ($vc))
                        }
                    }
                    Else {
                        Write-Verbose -Message 'No FallBackCredential provided.'
                    }
                }
            } #End if Credential by Object

            # If we have cred files on disk
            Elseif($CredentialFromPath) {
                
                ## try the main Credential by path
                ## you can have more than one, but the first must be populated
                If($CredentialFromPath -is [PSCredential]) {

                    Try {
                        $null = Connect-VIServer -Server $vc -Credential $CredentialFromPath -ErrorAction Stop -WarningAction SilentlyContinue
                        Write-Verbose -Message ('Using provided Credential of {0}' -f $CredentialFromPath.GetNetworkCredential().UserName)
                    }
                    Catch {
                    
                        ## quietly move on to fall-back creds by path (if any)
                        ## we only try this if the primary credential by path has failed
                        If($FallBackCredentialFromPath -is [PSCredential]) {

                            Try {
                                $null = Connect-VIServer -Server $vc -Credential $FallBackCredentialFromPath -ErrorAction Stop -WarningAction SilentlyContinue
                                Write-Verbose -Message ('Using fall-back Credential of {0}' -f $FallBackCredentialFromPath.GetNetworkCredential().UserName)
                            }
                            Catch {
                                Write-Warning -Message ('Error Detected! {0}' -f $_.Exception.Message)
                                Write-Warning -Message ('Problem connecting to vCenter {0} using the provided xml cred file(s) from path.' -f ($vc))
                            }
                        }
                        Else {
                            Write-Warning -Message 'No valid Credentials by path can be found.'
                        }
                    } #End Catch
                } #End If
            } #End Elseif

            ## fallback to SSPI
            Else {

                #Our last recourse is SSPI, using the credentials that Powershell was launched as. 
                Write-Verbose -Message 'No valid runtime credentials found'
                Write-Verbose -Message "..Trying Passthrough as $($env:USERDOMAIN)\$($env:USERNAME)"
                Try {     
                    $null = Connect-VIServer -Server $vc -ErrorAction Stop -WarningAction SilentlyContinue -Force
                }
                Catch {
                    Write-Warning -Message ('Error Detected! {0}' -f $_.Exception.Message)
                    Write-Warning -Message ('Problem connecting to vCenter {0} using SSPI (pass-through)' -f ($vc))
                }
            } #End Else
            
            #if connected, ensure it's a vCenter
            $vcConn = $Global:DefaultVIServer
            If($vcConn) {
                [string]$ConType = ($vcConn).ProductLine
                If($ConType -match 'embeddedEsx') {
                    Write-Warning -Message 'vCenter Connection required!'
                    $null = Disconnect-VIServer -Confirm:$false -ErrorAction SilentlyContinue -Force
                    Throw 'Direct ESX connection not supported (VC required!)'
                }
                Else {
                    If($ConType -match 'vpx') {
                        Write-Verbose -Message ('Connected to {0} api on {1}' -f ($ConType,$vc))
                    }
                }
            }
            Else {
                Write-Warning -Message 'No vCenter Connection detected!'
                Write-Warning -Message ('Skipping {0} (connection problem)!' -f ($vc))
                throw
            }

            #handle vicontainer
            If($Location) {
                
                try{
                    $VMs = Get-VM -Location $Location -ea Stop
                }
                Catch {
                    Write-Warning -Message ('Problem enumerating VMs from VI Location {0} on {1}' -f $Location,$vc)
                    Write-Debug -Message ('{0}' -f $_.Exception.Message)
                    Write-Warning -Message ('..Skipping {0}!' -f $vc)
                    $null = Disconnect-VIServer -Server $vc -Confirm:$false -ErrorAction SilentlyContinue -Force
                    Continue #move on to next vc
                }
            }
            Else {
                $VMs = Get-VM
            }

            #main
            If($Location) {
                #if user populated location
                $VMReport = $VMs | Where-Object {$_.PowerState -eq 'PoweredOn'} | Select-Object -Property Name,@{N='IP Address';E={@($_.guest.IPAddress[0])}},@{N='Location';E={@($($Location))}}, @{N='ParentVC';E={@($Global:DefaultVIServer)}}
            }
            Else {
                #get all VMs
                $VMReport = $VMs | Where-Object {$_.PowerState -eq 'PoweredOn'} | Select-Object -Property Name,@{N='IP Address';E={@($_.guest.IPAddress[0])}},@{N='ParentVC';E={@($Global:DefaultVIServer)}}
            }
            $Report += $VMReport
            $null = Disconnect-VIServer -Server $vc -Confirm:$false -Force -ErrorAction SilentlyContinue
        }
        Else {
            Write-Warning -Message ('Skipping {0} (no ICMP)' -f ($vc))
        }
    }

    #handle report output
    If($SaveReport) {
        If($report) {
            $report | Export-Csv -NoTypeInformation -UseCulture -Path $ReportPath

            If($PassThrough) {
                return $Report
            }
        }
        Else {
            Write-Warning -Message 'No Report Data'
        }
    }
    Else {
        return $Report
    }
} #End Process

End {

    #launch report if needed
    If($SaveReport) {
        If(Test-Path -Path $ReportPath) {
            Write-Verbose -Message ('Output file is {0}' -f ($ReportPath))
            
            If($AutoLaunch) {
                Invoke-Item -Path $ReportPath
            }
            Else {
              If(-Not($PSCmdlet.MyInvocation.BoundParameters['Verbose'])){
                Write-Output -InputObject ('Output file is {0}' -f ($ReportPath))
              }
            }
        }
    }

    #completion message
    Write-Verbose -Message ('Ending {0} at {1} local time' -f $MyInvocation.Mycommand, (Get-Date))
} #End End