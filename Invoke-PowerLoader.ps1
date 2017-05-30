Function Invoke-PowerLoader {

    <#
    .DESCRIPTION
      Imports PowerCLI Modules and/or Adds the PowerCLI Snapins as appropriate.
      This function understands both snapins and modules so it supports loading
      of PowerCLI versions 5.0 to 6.5.1 and later.

    .NOTES
      Script:         Invoke-PowerLoader.ps1
      Based on:       http://wahlnetwork.com/2015/04/13/powercli-modules-snapins/
      Type:           Function
      Author:         Mike Nisk
      Organization:   vmkdaily
    
    
    .EXAMPLE
    Invoke-PowerLoader
    This example, with no parameters, quietly loads PowerCLI

    .EXAMPLE
    Invoke-PowerLoader -Quiet:$false
    This example returns the `Welcome to PowerCLI` message

    #>

    [CmdletBinding()]
    Param([bool]$Quiet = $true)

    Process {

      #handle PowerCLI 6.5.1+ if using quiet mode
      If((Get-Module -Name VMware.PowerCLI -ListAvailable) -and ($Quiet -eq $true)) {
        $SkipLoader = $true
        $vMods = $null
      } #End If
      Else {
        #normal module loader, PowerCLI 6.3 to 6.5+ (includes welcome message)
        $vMods = Get-Module -Name VMware* -ListAvailable -Verbose:$false
      } #End Else

      #If we don't seem to have PSGallery version, move on
      If(-Not($SkipLoader)) {

        #load PowerCLI 6.3 to 6.5
        If($vMods) {
            foreach ($mod in $vMods) {
            Import-Module -Name $mod -ErrorAction Stop -Verbose:$false
          } #End Foreach
          Write-Verbose -Message 'PowerCLI 6.x Module(s) imported'
        } #End If
        Else {
          #fall-back to PSSnapin if needed
          If(!(Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue)) {
            Try {
              Add-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction Stop
              Write-Verbose -Message 'PowerCLI 5.x Snapin added; recommend upgrading to PowerCLI 6.x'
            } #End Try
            Catch {
              Write-Warning -Message ('{0}' -f $_.Exception.Message)
              Write-Warning -Message 'Could not load PowerCLI!'
              Throw 'PowerCLI 5.0 or later required'
            } #End Catch
          } #End If snapins
        } #End Else vMods
      } #End if SkipLoader
    } #End Process
    End {
      Remove-Variable -Name vMods -Confirm:$false
    } #End End
} #End Function