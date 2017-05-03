#requires -version 3

Function Invoke-ApdCheck {
    <#

    .SYNOPSIS
    This script is a Powershell wrapper for useful commands one would execute at the localcli of ESX during an NFS APD issue.
 
    .DESCRIPTION
    Connects to an ESX host using Powershell (PowerCLI not required) and runs various local commands.
    This solution is 100% SSH with no vSphere API used.  The Credentials required are for ESX (i.e root).
    We perform health checks against the system and focus on items related to NFS storage and networking.
    Health checks for Cisco Nexus 1000v are on by default but will quietly skip if no 1000v.
    We make use of the Invoke-SSH function to run all kinds of commands on ESX.

    .NOTES
    Script:       Invoke-ApdCheck.ps1
    Author:       Mike Nisk
    Prior Art:    Uses Invoke-SSH function by @lucd22 to run desired commands on ESX (function required, and included)
    Prior Art:    Uses Import-PSCredential function from @halr9000 (optional, included)
    Audience:     VMware vSphere customers using NFS Storage
    Audience:     vSphere customers experiencing 'All Paths Down (APD)' issues with NFS
    Audience:     (optional) Cisco Nexus 1000v users on vSphere
    Requires:     Powershell 3 (v5 preferred)
    Requires:     Putty / Plink (choose the Windows MSI installer since it installs to x86 by default)
    Recommend:    Save a hardcoded credential to encrypted xml (if possible), instead of having to populate the Credential parameter at runtime.
    Recommend:    As with all putty connections, please connect to the host at least once to answer yes to cache the key to your registry.
                  For example, use Invoke-SSH or run something simple like the Sync parameter of this script for a quick way to answer yes and cache the key.


    .PARAMETER Computer
    FQDN or IP of ESX host

    .PARAMETER Credential
    ESX login credentials (i.e. root).  Alternatively, you can use an encrypted cred file by editing the user options in the script.

    .PARAMETER Sync
    Writes ESX running config to the boot bank.  Without this script, ESX does this once an hour (at one minute after the hour).

    .PARAMETER CheckAll
    Run all of the checks available in this script

    .PARAMETER NfsVmk
    Name of your nfs vmkernel interface (default is vmk3)

    .PARAMETER GenerateBundle
    Activate this switch if you want a vm-support bundle generated.  Also see the PerformanceSnapshot parameter.

    .PARAMETER PerformanceSnapshot
    Integer.  Duration in Seconds to run vm-support performance snapshots, if any (Default is 0).
    For example, to gather 2 minutes of performance stats enter 120 (i.e. same as 'vm-support -p -d 120')
    Consider using the WorkingDir parameter to point this output to a datastore.  These can easily be > 1GB.
    If you run out of space in /var/tmp (default location) you will need to reboot ESX to get all logging running properly again.
    As such, try to use a remote location (i.e. -WorkingDir "/vmfs/volumes/<iso-datastore>")

    .PARAMETER Quiet
    minimalist switch.

    .PARAMETER WorkingDir
    String. Path to Datastore or folder to save ESX support bundle (default is /var/tmp).
    An example would be "/vmfs/volumes/datastore1/Logs".
    Like most Powershell, no trailing slash.

    .PARAMETER ForceOverWrite
    Switch.  Activate this switch to allow the overwrite of old logs on remote paths.  Should only used if you know what you're doing.
    By default we allow overwrite of old support logs and bundles in /var/tmp/ because that is safe.
    However, if you use the Workingdir parameter and point to a datastore (i.e. "/vmfs/volumes/datastores1"),
    then we cannot ensure that the .log and .tgz files are ok to delete.

    .PARAMETER Include1000V
    boolean.  Set this to $false to ignore 1000v checks (default is $true).
    If you don't have the vem vib installed we ignore this anyway.

    .EXAMPLE
    #Example #1 - Dot source the function and prove it works by using help
    cd <path to script>
    . .\Invoke-ApdCheck.ps1
    cd c:\
    Help Invoke-ApdCheck
    This script should be dot sourced so you can easily access it from any directory.
    All remaining examples assume you have dot sourced or can auto-load the function.
    Note: To reload the function after you have made changes, you can perform the following and then dot source again:
    Remove-Item Function:Invoke-ApdCheck

    .EXAMPLE
    #Example #2 - Get prompted for credentials
    .\Invoke-ApdCheck.ps1 -Computer esx01.lab.local -Credential (Get-Credential root) -CheckAll
    #Get prompted for ESX login at runtime, then perform the health check.

    .EXAMPLE
    #Example #3 - Save ESX credentials to a variable
    $credsESX = Get-Credential root
    .\Invoke-ApdCheck.ps1 -Computer esx01.lab.local -Credential $credsESX -CheckAll
    #save ESX credentials to a variable and then consume the creds to perform the health check.

    .EXAMPLE
    #Example #4 - Fall back to local cred file and then perform health check using the CheckAll parameter
    .\Invoke-ApdCheck.ps1 -Computer esx01.lab.local -CheckAll
    If no credentials are provided, we fall back to local encrypted xml cred file if available. The path to the cred file is set in the Begin section of the script.
    If you need to save credentials to file, see my Invoke-SaveCreds.ps1 script which is based on the @halr9000 Export-PSCredential.
    The technique of using encrypted credential files is good for running these as scheduled tasks.
    [TODO] Add a paramter to let users save creds using @halr9000's function.

    .EXAMPLE
    #Example #5 - Sync ESX boot bank
    .\Invoke-ApdCheck.ps1 -Computer esx01.lab.local -Credential $credsESX -Sync
    Save the ESX running config to the bootbank.
    This is done by default 1 minute after the hour, every hour by ESX's cron.
    However, you can run it manually here with the Sync parameter.
    It is wise to run a sync after evacuating an ESX host prior to reboot for example.

    .EXAMPLE
    #Example #6 - Generate a regular vm-support bundle
    .\Invoke-ApdCheck.ps1 -Computer esx01.lab.local -Credential $credsESX -GenerateBundle
    Generate a vm-support bundle.  You can use GenerateBundle or its alias Bundle.
    We also include 1000v logs unless user specifies otherwise (i.e. by setting the Include1000V parameter to $false).
    If user has no vem vib we ignore the 1000v tests by default.

    .EXAMPLE
    #Example #7 - Generate a vm-support bundle and save it to a remote path
    .\Invoke-ApdCheck.ps1 -Computer esx01.lab.local -Credential $credsESX -GenerateBundle -WorkingDir '/vmfs/volumes/datastore1'
    Generate a vm-support bundle and save it to the desired directory (default is /var/tmp).

    .EXAMPLE
    #Example #8 - Generate a vm-support bundle with Performance Snapshots
    .\Invoke-ApdCheck.ps1 -Computer esx01.lab.local -Credential $credsESX -GenerateBundle -PerformanceSnapshot 120
    Generate a vm-support bundle and include 2 minutes of VM 'Performance Snapshots'.
    Think esxtop, but this is a feature of vm-support that will include perf stats for VMs when creating the bundle.
    This is useful for VMware GSS when reviewing APDs or performance issues.  Be careful not to run out of space.

    .EXAMPLE
    #Example #9 - Generate a vm-support bundle in Quiet mode
    .\Invoke-ApdCheck.ps1 -Computer esx01.lab.local -Credential $credsESX -GenerateBundle -WorkingDir "/vmfs/volumes/datastore1/ISO/Logs" -Quiet
    Use a remote path to save vm-support bundle and logs, and be less chatty about it.

    .EXAMPLE
    #Example #10 - Perform a health check, but ignore 1000V
    .\Invoke-ApdCheck.ps1 -Computer esx01.lab.local -Credential $credsESX -CheckAll -Include1000V:$false
    Perform all health health checks, except for 1000v.  By default this bool is True so N1KV checks are performed.  Set to $false to ignore 1000v.
    If you don't have 1000V there is no need to turn this off; the checks will be skipped if no VEM vib is found.
    The ability to turn 1000V reporting off, is really only for people running 1000V who don't want that info for whatever reason.

    .EXAMPLE
    #Example #11 - Generate a vm-support bundle and force the overwrite of old logs in remote directory.
    .\Invoke-ApdCheck.ps1 -Computer esx01.lab.local -Bundle -IncludeSnaps 600 -Path "/vmfs/volumes/datastore1/ISO/Logs" -Quiet -ForceOverWrite
    Here we use the parameter aliases of Bundle, IncludeSnaps and Path.
    These are the same as GenerateBundle, PerformanceSnapshot, and WorkingDir respectively.
    This example also shows the hidden parameter ForceOverWrite, which deletes old log files in a remote path.
    By not providing a Credential, we fall-back to hardcoded creds. 

    #Example #12 - Add the function to your $PROFILE, then prove it works by using help
    1.  Download the function to c:\scripts\mods\Invoke-ApdCheck.ps1 #just an example folder
    2.  Run Powershell as administrator (UAC)
    3.  Run the following command:
    Test-Path $PROFILE #if the results are $true skip to step 5
    4.  If the result from above is $false, add a profile with the following:
    New-Item -Type File -Path $PROFILE -Force
    5.  Run the following command:
    ise $PROFILE #open your $PROFILE in the Powershell ISE
    6.  Enter the following to dot source the function every time Powershell starts:
    . c:\scripts\mods\Invoke-ApdCheck.ps1 #that's a dot space
    7.  Relaunch Powershell, or run the following command to reload your $PROFILE:
    & $Profile
    8.  cd c:\
    9.  Help Invoke-ApdCheck -ShowWindow

    //TODO - Better or more elegant text parsing
    //TODO - Better or more specific handling of old log deletion when using the ForceOverWrite parameter
    //TODO - [your idea here]

    #>

    [cmdletbinding(DefaultParameterSetName='none')]
    param (
    	
        #String. ESX FQDN or IP Address
        [Parameter(HelpMessage='ESX Name or IP Address', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Computer,

        #pscredential. ESX login credentials (i.e. root).  Alternatively, you can use an encrypted cred file by editing the user options in the script.
        #[Parameter(Mandatory=$true)]  #comment out to allow using hardcoded path to creds
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Credential()][PSCredential]$Credential,

        #Writes ESX running config to the boot bank.
        [Parameter(ParameterSetName = 'sync',HelpMessage='Sync the ESX bootbank', Mandatory)]
        [switch]$Sync,

        #Run all of the checks available in this script
        [Parameter(ParameterSetName = 'health',HelpMessage='Perform Health Check', Mandatory)]
        [switch]$CheckAll,

        #Name of your nfs vmkernel interface (default is vmk3)
        [Parameter(ParameterSetName = 'health')]
        [alias("vmk")]
        [string]$NfsVmk,

        #Vibs to report on in localcli syntax
        #use escape pipe syntax so it can be read in linux
        #For example "'dell\|EMC\|OpenManage\|vem\|ixgbe'"
        [Parameter(ParameterSetName = 'health')]
        [string]$Vibs,

        #Activate this switch to generate a vm-support bundle.  Also see the PerformanceSnapshot parameter.
        [Parameter(ParameterSetName = 'bundle',HelpMessage='Generate ESX Support Bundle', Mandatory)]
        [alias("Bundle")]
        [switch]$GenerateBundle,

        #Integer.  Duration in Seconds to run vm-support performance snapshots, if any (Default is 0).
        [Parameter(ParameterSetName = 'bundle')]
        [ValidateRange(0,3600)] #max 1 hour
        [alias("IncludeSnaps")]
        [int]$PerformanceSnapshot = 0,

        #minimalist switch
        [switch]$Quiet,

        #String. Path to Datastore or folder to save ESX support bundle (default is /var/tmp).
        [Parameter(ParameterSetName = 'bundle')]
        [alias("Path")]
        [string]$WorkingDir = '',

        #boolean.  Set this to $false to ignore 1000v checks (default is $true).
        [Parameter(ParameterSetName = 'health')]
        [Parameter(ParameterSetName = 'bundle')]
        [bool]$Include1000V = $true,

        #switch.  Allow log overwrite on remote paths.
        [Parameter(ParameterSetName = 'bundle')]
        [switch]$ForceOverWrite = $false
    )

    Begin {

      ## Options
      ## if runtime parameters are not populated, we use these defaults
       
      # nfs interface name
      If(!$NfsVmk) {
        [string]$NfsVmk = 'vmk3'
      }
        
      # vibs to report on
      If(!$Vibs) {
        [string]$VIBs = "'dell\|EMC\|OpenManage\|vem\|ixgbe'"
      }
        
      # WorkingDir
      #ESX default is /var/tmp.
      #The recommendation is something like '/vmfs/volumes/<datastorename>'
      #so you don't run out of space on ESX visorfs.
      If(!$WorkingDir) {
        [string]$WorkingDir = '/var/tmp'
      }

      ## Manually update your preferences here:
      $UserPref = New-Object -TypeName PSObject -Property @{
        Logging =         'on'                                #Powershell Transcript logging on or off.  Consider keeping this on.
        LogDir =          $Env:Temp                           #This is powershell logging. If this doesn't exist we go to temp
        LogName =         'ApdHealthCheck'                    #transcript logging file name (just the leaf). We add .log extension later
        PathToCredsEsx =  ''                                  #If using hardcoded credentials (i.e. 'C:\Creds\CredsESX.enc.xml')
      }

      ## Logging and reporting
      Write-Verbose -Message "Logging mode is $($UserPref.Logging)"

      ## set date format for filename output, etc.
      $dt = Get-Date -format "ddMMMyyyy_HHmm"

      ## ESX shortname to use for logs
      $StrEsxShortName = ($Computer | Split-Path -Leaf).Split(".")[0]
      
      If ($UserPref.Logging -eq 'on') {    
        
        #PowerShell transcript log name
        $logfile = "$($UserPref.LogDir)\$($UserPref.LogName)-$($StrEsxShortName)-$dt.log"
        
        #start logging, if needed
        Try {
          $null = Start-Transcript -Append -Path $logfile -ErrorAction Stop
        }
        Catch {
          Throw "Cannot start logging"
        }
      }

      Function Stop-Logging {
        If ($UserPref.Logging -eq 'on') {
    			
          ## Stop the Powershell transcript logging
          Try {
            $null = Stop-Transcript -ErrorAction Stop
            Write-Verbose -Message "Transcript logging stopped successfully"
          }
          Catch {
            Write-Warning -Message "$($_.Exception.Message)"
            Write-Verbose -Message "Problem with transcript logging (please review)"
          }

          If(Test-Path -Path $logfile) {
            Write-Verbose -Message "Log file: $logfile"
          }
          Else {
            Write-Warning -Message "Log file health unknown"
          }
        }
      }

      #region local cred file
      If(-Not($PSCmdlet.MyInvocation.BoundParameters['Credential'])) {

        Function Import-PSCredential {
            
          #Import-PSCredential function by @halr9000

          [CmdletBinding()]
          param ( [string]$Path = "credentials.enc.xml" )

          # Import credential file
          $import = Import-Clixml -Path $Path 
    	
          # Test for valid import
          if ( !$import.UserName -or !$import.EncryptedPassword ) {
            Throw "Input is not a valid ExportedPSCredential object, exiting."
          }
          $Username = $import.Username
    	
          # Decrypt the password and store as a SecureString object for safekeeping
          $SecurePass = $import.EncryptedPassword | ConvertTo-SecureString
    	
          # Build the new credential object
          $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePass
          Write-Output -InputObject $Credential
        }
        $Credential = Import-PSCredential -Path $UserPref.PathToCredsEsx
      }
      #endregion

      #region ssh function                                                                                                                                                                                                                                                                                                                #region ssh function
      If(!(Get-Command -Name Invoke-SSH -ErrorAction SilentlyContinue)) {

        ## If user does not have the @Lucd22 Invoke-SSH function,
        ## We add it here.  This requires existing putty msi installation in x86 folder

        Function Invoke-SSH {
          [CmdletBinding(DefaultParameterSetName='Command')]
          Param(
              [Parameter(Mandatory
              ,   ValueFromPipeline
              ,   ValueFromPipelineByPropertyName
              ,   HelpMessage='ip or hostname of remote computer'
              ,   ParameterSetName='Script'
              )]
              [Parameter(Mandatory
              ,   ValueFromPipeline
              ,   ValueFromPipelineByPropertyName
              ,   HelpMessage='ip or hostname of remote computer'
              ,   ParameterSetName='Command'
              )]
              [string]$Computer,

              [Parameter(ValueFromPipeline
              ,   ParameterSetName='Script'
              )]
              [Parameter(ValueFromPipeline
              ,   ParameterSetName='Command'
              )]
              [System.Management.Automation.Credential()][pscredential]$Credential,

              [Parameter(ParameterSetName='Script')]
              [Parameter(ParameterSetName='Command')]
              [string]$Username,

              [Parameter(ParameterSetName='Script')]
              [Parameter(ParameterSetName='Command')]
              [AllowEmptyString()]
              [string]$Password,

              [Parameter(Mandatory
              ,   ParameterSetName='Script'
              ,   ValueFromPipelineByPropertyName
              ,   HelpMessage='Path to shell script'
              )]
              [ValidateScript({Test-Path -Path $_})]
              [alias("PSPath","FullName")]
              [string]$FilePath,

              [Parameter(Mandatory
              ,   ParameterSetName='Command'
              ,   ValueFromRemainingArguments=$True
              ,   HelpMessage='Command to execute'
              )]
              [string]$ScriptText
          )
          Begin {
              $PLink = "${env:ProgramFiles(x86)}\PuTTY\plink.exe","plink.exe" | Get-Command -EA SilentlyContinue | Select-Object -First 1 -ExpandProperty Definition
              If (-Not $PLink) {
                  throw "PLink could not be found, please install putty!"
                  exit 1;
              }

              if ($Credential) {
                  $Cred = $Credential.GetNetworkCredential()
                  $Username = $Cred.UserName
                  $Password = $Cred.Password
              }
          }
          Process {
              switch ($PSCmdlet.ParameterSetName) {
                  "Script" {
                      & $Plink -l $Username -pw $Password $Computer -m $FilePath
                  }
                  "Command" {
                      & $Plink -l $Username -pw $Password $Computer $ScriptText
                  }
              }#End switch
          } #End process
        }#End Invoke-SSH function
      }#End if
      #endregion
    }#End Begin

    Process {
        
      ## skip 1000v checks if no vem vib exists
      $vemVib = Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "esxcli software vib list | grep cisco-vem"
      if(!$vemVib -and $Include1000V -eq $true) {
      Write-Output -InputObject "skipping 1000v health checks (vem vib not found)."
      $Include1000V = $false
      }

      ## if the user chose the Sync parameter
      If($sync) {
        ## sync boot bank
        Write-Output -InputObject "`n..Saving ESX running config to bootbank with auto-backup.sh"
        Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "sync;sync;auto-backup.sh"
        Write-Output -InputObject "bootbank sync completed at $(Get-Date) local time."
      }

      If($CheckAll) {

        Write-Output -InputObject "`nBeginning health check for host $($Computer) at $(Get-Date)"
            
        Try {
        $uptime = Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "uptime"
        }
        Catch {
          Throw "Unable to perform SSH command on host!"
        }

        ## Check for APD
        ## TODO - does this catch if more than one DS APDs?
        Write-Output -InputObject "`n..Checking for APDs"
        $ApdCheck = Invoke-SSH -Computer $computer -Credential $Credential -ScriptText "grep 'apd timeout list' /var/log/hostd.log"
        If($ApdCheck){
                
        ## Determine affected datastore and time
        $ApdDS = (($ApdCheck -split "Added ")[1] -split " ")[0]
        $ApdUTC = (Get-Date -Date ($ApdCheck -split " ")[0]).ToUniversalTime()

        ## Report the APD and time of issue
        Write-Output -InputObject "APD Timeout detected at: $($ApdUTC) (UTC)"
        Write-Output -InputObject "ESX uptime: $($uptime)"

        ## Report APD datastore and VMs
        Write-Output -InputObject "APD Datastore: $($ApdDS)"
        $ApdFS = ((Invoke-SSH -Computer $computer -Credential $Credential -ScriptText "esxcli storage filesystem list" | Select-String -Pattern $ApdDS) -split " ")[0]
        $RunningVMs = Invoke-SSH -Computer $computer -Credential $Credential -ScriptText "vscsiStats -l" | Select-String -Pattern vmfs
        if($RunningVMs -match $ApdFS) {
                    
        Write-Output -InputObject "`n## Affected VMs:"
        Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "esxcli vm process list" | Select-String -Pattern $ApdFS -Context 1,0

        }
        Else {
        Write-Output -InputObject "Apd detected, but no running VMs affected (or host already rebooted)"
        }

        ## Show Log Events
        Write-Output -InputObject "`n..Performing 'grep -i APD /var/log/hostd.log'"
        Invoke-SSH -Computer $computer -Credential $Credential -ScriptText "grep -i APD /var/log/hostd.log"
        }
        Else {
        Write-Output -InputObject "No Apd detected in current logs."
        }

        If(!$Quiet){
                
          ## Show uptime if we haven't already in the APD check
          if(-not($ApdCheck)) {
            Write-Output -InputObject "ESX uptime: $($uptime)"
          }

          ## Show ESX root free space
          Write-Output -InputObject "`n## ESX free space on root"
          Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "vdf -h" | Select-String -Pattern 'Ramdisk' -Context 0,5

          ## Check for desired VIBs
          Write-Output -InputObject "`n## Installed VIBS"
          $InstalledVibs = Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "esxcli software vib list | grep -i $($VIBs)"
          If($InstalledVibs) {
            Foreach($vib in $InstalledVibs) {
              Write-Output -InputObject "$($vib)"
            }
          }

          ## List Network Adapters
          Write-Output -InputObject "`n## ESX NICs:"
          Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "esxcfg-nics -l | grep 10000"

          ## List vmkernel interfaces
          Write-Output -InputObject "`n## VMKernel Interfaces:"
          Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "esxcfg-vmknic -l | grep IPv4"

          ## List NIC PCI, Device, Vendor, etc.
          Write-Output -InputObject "`n## PCI Info for 10Gb NICs:"
          [string[]]$StrVmnicNames = Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "esxcfg-nics -l | grep 10000" | ForEach-Object {
            ($_ -split " ")[0]
          }

          ## lspci
          $StrVmnicNames | ForEach-Object {
            Write-Output -InputObject "`n## `'lspci -vv | grep -A2 $_'"
            Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "lspci -vv | grep -A2 $_"
          }

          ## list pNIC TSO Setting (requires ESX 5.5 or greater)
            Write-Output -InputObject "`n## `'esxcli network nic tso get'"
            $StrVmnicNames | ForEach-Object {
            Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "esxcli network nic tso get -n $_" | Select-String -Pattern vmnic
          }

          ## NFS Section
          Write-Output -InputObject "`n## 'esxcli storage nfs list'"
          Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "esxcli storage nfs list"

          Write-Output -InputObject "`n## 'esxcfg-nas -l'"
          $EsxNasList = Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "esxcfg-nas -l"
          $StrEsxNasList = $EsxNasList | Out-String
          Write-Output -InputObject "$($StrEsxNasList)"

          ## Obtain NAS Remote Host IPs (i.e. the IP for each volume on the array)
          [string[]]$NasIPList = $EsxNasList | ForEach-Object {
            ($_ -split " ")[4]
            }
            $NasIPList = $NasIPList | Select-Object -Unique
            $NasIPList = $NasIPList -replace " ",","

            Write-Output -InputObject "`n## NAS Remote Targets:"
            $NasIPList

            ## ping nfs remote targets using jumbo frames from the NFS vmkernel interface
            Foreach ($ip in $NasIPList) {
              [ipaddress]$ip = $ip
              If(($ip) -and ($ip -is [ipaddress])) {
                Write-Output -InputObject "`n..Performing `'vmkping -I $($NfsVmk) -d -s 8972 $($ip)`'"
                Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "vmkping -I $NfsVmk -d -s 8972 $ip"
              }
            }

          ## Check the current settings for NFS.MaxQueueDepth
          Write-Output -InputObject "`nMax Queue Depth for NFS:"
          Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "esxcfg-advcfg -g /NFS/MaxQueueDepth"

          ## Check the Firmware version of the NICs
          Write-Output -InputObject "`n## NIC Firmware:"
          $StrVmnicNames | ForEach-Object {
            Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "ethtool -i $_ | grep firmware"
          }

          If($Include1000V) {
            ## Show the 1000v version
            Write-Output -InputObject "`n..Checking 1000v Version:"
            Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "vemcmd show version"

            Write-Output -InputObject "`n..Confirming that VEM is not headless"
            Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "vemcmd show card | grep Headless"

            ## vem status
            Write-Output -InputObject "`n..Checking vem status"
            $vemStatus = Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "vem status" | Select-String -Pattern 'DVS Name' -Context 0,2
            $vemStatus = $vemStatus -replace "MTU"," MTU"
            $vemStatus = $vemStatus -replace "1500","[VSM]" #vSphere VDS always shows 1500 for N1KV so hide that.
            Write-Output -InputObject "$($vemStatus)"
                
            ## VEM to VSM health check
            Write-Output -InputObject "`n..Checking health of VEM to VSM communication"
            $Primary_VSM_MAC = ((Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "vemcmd show card | grep 'Primary VSM MAC'") -split " : ")[1]
            Write-Output -InputObject "Primary VSM MAC Address:`n$Primary_VSM_MAC"
            $vemHealth = Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "vem-health check $Primary_VSM_MAC" | Select-String -Pattern 'VEM' -Context 0,6
            Write-Output -InputObject "$($vemHealth)"
          } #End If 1000v
        } #End If Not Quiet
      } #End If CheckAll

      If($GenerateBundle) {

          ## Confirm access to datastore in case user is not choosing the default of /var/tmp
          $testLogDir = Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "ls -lh $WorkingDir"
          If(!$testLogDir) {
            Write-Warning -Message "Cannot find requested path. Try saving somewhere else!"
            Throw "Invalid WorkingDir selected."
          }

          ## list all log files
          If($ForceOverWrite) {
            [string[]]$oldBundles = Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "ls -lh $WorkingDir/" | Select-String -Pattern '.log','.tgz'
          }
          Else {
            [string[]]$oldBundles = Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "ls -lh /var/tmp/" | Select-String -Pattern '.log','.tgz'
          }
            
          ## remove old logs
          If($oldBundles){
            Write-Output -InputObject "`n## Old Support Logs:"
            foreach($item in $oldBundles) {
              Write-Output -InputObject "$($item)"
            }
            Write-Output -InputObject "`n..Removing old logs"
            Write-Output -InputObject "Press CTRL + C to Cancel`n"
            Start-Sleep -Seconds 5

            If($ForceOverWrite){
              Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "rm $WorkingDir/vem*.log"
              Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "rm $WorkingDir/cisco*.tgz"
              Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "rm $WorkingDir/esx-$StrEsxShortName-*.tgz"
              Write-Output -InputObject "Old support logs removed from $($WorkingDir)/"
            }
            Else{
              Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "rm /var/tmp/*.log"
              Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "rm /var/tmp/*.tgz"
              Write-Output -InputObject "Old support logs removed from /var/tmp."
            }
          }
          Else {
            Write-Output -InputObject "No logs to clean in $($WorkingDir)"
          }

          If(!$Quiet){
            ## echo session info to screen
            Write-Output -InputObject "Logs will be saved to $($WorkingDir)"
            Write-Output -InputObject "Using $(Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "vm-support --version")"
            Start-Sleep -Seconds 4
          }
            
          If($Include1000V -eq $true){

            If(!$Quiet) {
            Write-Output -InputObject "`nNetwork Ports (vmkernel and VM):"
            Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "vemcmd show port"
            }

            Write-Output -InputObject "`n..Gathering 1000v logs"
            Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "cp /var/log/vemdpa.log $WorkingDir/vemdpa-$($StrEsxShortName)-$($dt).log"
            Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "/bin/vem-support -t $WorkingDir all"
          }

          ## regular vm-support
          if($PerformanceSnapshot -lt 1){
            Write-Output -InputObject "`n..Gathering ESX Support Bundle for $($StrEsxShortName) at $(Get-Date)"
            Write-Output -InputObject "Press CTRL + C to cancel"
            Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "/bin/vm-support -w $WorkingDir"
          }

          Else {
                
            ## vm-support with performance snapshots
            Write-Output -InputObject "`nPreparing to gather performance snapshots (duration $($PerformanceSnapshot) seconds)."
            Write-Output -InputObject "`nExpected run times:"
            $PerfSnapETA = [math]::round(($PerformanceSnapshot /60),2)
            $expectedRuntime = [math]::round(((240 + $PerformanceSnapshot)/60),2)
            Write-Output -InputObject "  vm-support `t`t ~4.00 min(s)"
            Write-Output -InputObject "  performance snapshots ~$($PerfSnapETA) min(s)."
                
            ## Generate vm-support and include performance snapshots
            Write-Output -InputObject "`n..Gathering ESX Support Bundle for $($StrEsxShortName) at $(Get-Date)"
            Invoke-SSH -Computer $Computer -Credential $Credential -ScriptText "/bin/vm-support -p -d $PerformanceSnapshot -w $WorkingDir"

            ## Predict runtimes
            If($expectedRuntime -gt 4.50) {
            $expectedCompletionTime = (Get-Date).AddMinutes(($expectedRuntime))
            Write-Output -InputObject "`nThis will take a while.  Recommend coming back at $($expectedCompletionTime)"
            Write-Output -InputObject "Press CTRL + C to cancel`n"
            Start-Sleep -Seconds 5
            }
          }
                
          ## completion message for both support bundle types here
          Write-Output -InputObject "Generate Support Bundle for $($StrEsxShortName) completed at $(Get-Date) local time."

      } #End If Generate Bundle
    } #End Process

    End {
      ## completion message (unless just syncing bootbanks)
      If(-Not($Sync)) {
      Write-Output -InputObject "`nScript Complete.`n"
      Stop-Logging
      } #End If
    } #End End
} #End Function
