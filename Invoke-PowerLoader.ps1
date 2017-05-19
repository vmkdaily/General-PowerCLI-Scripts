Function Invoke-PowerLoader {

    <#
    .DESCRIPTION
      Imports PowerCLI Modules and/or Loads the PowerCLI Snapins as appropriate.
      This function understands both snapins and modules so it supports loading
      of PowerCLI versions 5.0 to 6.5+

    .NOTES
      Script:         Invoke-PowerLoader.ps1
      Based on:       http://wahlnetwork.com/2015/04/13/powercli-modules-snapins/
      Type:           Function
      Author:         Mike Nisk
      Organization:   vmkdaily
        
    .EXAMPLE
    Invoke-PowerLoader

    ABOUT MODULE AUTOLOADING
      Once you upgrade to PowerCLI 6.5.1, the VMware.PowerCLI module will be autoloaded
      upon first use for the given runtime session.  As such, there is no need for this
      function after upgrading to 6.5.1 and later.  It doesn't hurt anything to load
      it manually with this function, it is simply not needed on PowerCLI 6.5.1 and later.
    
   APPENDIX - How to upgrade to PowerCLI 6.5.1
      This is not required for the function herein.  In fact, I show you this upgrade technique
      so that you do not need a PowerCLI loader in the future.

      #prepare
      Upgrade Powershell to 5.1  #https://msdn.microsoft.com/en-us/powershell/wmf/5.1/install-configure
      Uninstall PowerCLI from Control Panel > Add/Remove Programs  #or Start > Run > appwiz.cpl
      Remove-Item 'C:\Program Files (x86)\VMware\Infrastructure\PowerCLI' #do not delete parent folders
      Find-Module -Name VMware.PowerCLI #this gets your nuget setup if needed (i.e. to allow access to the PowerShell Gallery)
      
      #install
      Install-Module -Name VMware.PowerCLI -Scope AllUsers -AllowClobber -Force     #this is All Users
      -or-
      Install-Module -Name VMware.PowerCLI -Scope CurrentUser -AllowClobber -Force  #this is Current User Only

      Note: The allow clobber is needed for PowerCLI to win
      any conflicts against HyperV cmdlets that use the same names.

    #>

    [CmdletBinding()]
    Param() #none

    Begin {
        $vMods = Get-Module -Name VMware* -ListAvailable -Verbose:$false
    }

    Process {

        If($vMods) {
            foreach ($mod in $vMods) {
            Import-Module -Name $mod -ErrorAction Stop -Verbose:$false
          }
          Write-Verbose -Message 'PowerCLI 6.x Module(s) imported'
        }
        Else {
          If(!(Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue)) {
            Try {
              Add-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction Stop
              Write-Msg -InputMessage 'PowerCLI 5.x Snapin added; recommend upgrading to PowerCLI 6.x'
            }
            Catch {
              Write-Warning -Message ('{0}' -f $_.Exception.Message)
              Write-Warning -Message 'Could not load PowerCLI!'
              Throw 'PowerCLI 5.0 or later required'
            }
          }
        }
    }
    End {
      Remove-Variable -Name vMods -Confirm:$false
    } #End End
} #End Function
        
#Load PowerCLI (supports 5.0 to 6.5+)
Invoke-PowerLoader