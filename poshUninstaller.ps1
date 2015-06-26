<#
.SYNOPSIS
	A script to automate removals of multiple versions of the same product automatically.   
	
.DESCRIPTION
	This script will automatically remove a list of MSIs generated from a given query.  See the full help for usage examples.
	
	Known Issues:
	   - Limited support for error handling, will be implemented in v1.0
	   - Non-MSI uninstallations are buggy... proceed at your own risk
	
	Makes use of code provided by Reddit user: /u/pouncer11 and various other suggestions from Google.  I tried to attribute where appropriate, but if I missed you please reach out to me via the contact info below:
	   Written By: Nathan Ziehnert
	   E-mail: nathan@z-nerd.com
	   Twitter: @theznerd

.PARAMETER applications
	An array of application strings.  These are automatically matched in RegEx so there is no need to use wildcards.

.PARAMETER publishers
	An array of approved publishers to be removed.  Useful if multiple publishers have similar product names.

.PARAMETER exclusionApplications
	An array of applications to exclude from the uninstallation.
	
.PARAMETER exclusionVersions
	An array of versions to exclude from the uninstallation.
	
.PARAMETER exclusionPublishers
	An array of publishers to exclude from the uninstallation.
	
.PARAMETER logging
	A switch to turn logging on or off for the individual removals

.PARAMETER logFilePath
	A string that includes the directory you wish to drop logs in, with NO trailing backslash

.PARAMETER msiCustomArguments
	A quote encapsulated string of custom arguments needed to uninstall an MSI application (not normally needed)

.PARAMETER nonMSICustomArguments
	A quote encapsulated string of custom arguments needed to uninstall a non-MSI application (perhaps /quiet or /silent)

.PARAMETER nonMSISupport
	A switch to attempt to run the uninstall command if the uninstaller is not an MSI.  Logging is not supported unless the argument is passed through nonMSICustomArguments

.PARAMETER WhatIf
	A switch to not actually run the uninstalls, but list out the applications that would be removed - use in conjunction with verbose

.LINK
	http://z-nerd.com/

.EXAMPLE
	.\poshUninstaller.ps1 -applications "Java 8 Update 45"

.EXAMPLE 
	.\poshUninstaller.ps1 -applications "Java" -exclusionPublishers "Microsoft" -exclusionApplications "JDK"

.EXAMPLE
	.\poshUninstaller.ps1 -applications "Java","Flash" -exclusionPublishers "Microsoft","Sothink" -exclusionApplications "JDK" -logging -logFilePath "C:\install_logs"
#>

[CmdletBinding()]
Param(
	[Parameter(Mandatory=$true)]
	[array]$applications,
	
	[Parameter(Mandatory=$false)]
	[array]$publishers,
	
	[Parameter(Mandatory=$false)]
	[array]$exclusionApplications,
	
	[Parameter(Mandatory=$false)]
	[array]$exclusionVersions,
	
	[Parameter(Mandatory=$false)]
	[array]$exclusionPublishers,
	
	[Parameter(Mandatory=$false)]
	[string]$msiCustomArguments,
	
	[Parameter(Mandatory=$false)]
	[string]$nonMSICustomArguments,
	
	[Parameter(Mandatory=$false)]
	[switch]$nonMSISupport,
	
	[Parameter(Mandatory=$false)]
	[switch]$logging,
	
	[Parameter(Mandatory=$false)]
	[switch]$WhatIf,
	
	[Parameter(Mandatory=$false)]
	[string]$logFilePath = "$env:TEMP"
)

#region RightsAndSystemChecks
	#Check for admin rights...
	If(-not (
		[Security.Principal.WindowsPrincipal] `
		[Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
			[Security.Principal.WindowsBuiltInRole] "Administrator")
		)
	{
		#We want to throw an error so that the script terminates
		throw "This script requires administrative rights to function properly.  Please re-run this script as an Administrator."
	}

	#32/64 bit system check
	if([System.IntPtr]::Size -eq 4){
		$x64 = $false
	}elseif([System.IntPtr]::Size -eq 8){
		$x64 = $true
	}else{
		Write-Warning "Error in determining OS Architecture... Defaulting to 32-Bit." 
		$x64 = $false
	}
#endregion RightsAndSystemChecks

Function Get-PUApplications {	
	#Let's start scanning the uninstall folders...
	if($x64){
		$UninstallPath = @(
			"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
		)
	}else{
		$UninstallPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
	}
	Write-Verbose "Registry paths set."
	Write-Verbose "Collecting list of applications to remove"
	
	#Get the items... still not happy with this command yet
	$itemsToRemove = Get-ItemProperty $UninstallPath | Where-Object {($_.DisplayName -match ($applications -join "|")) -and ((-not $publishers) -or $_.Publisher -match ($publishers -join "|")) -and ((-not $exclusionPublishers) -or $_.Publisher -notmatch ($exclusionPublishers -join "|")) -and ((-not $exclusionVersions) -or $_.DisplayVersion -notmatch ($exclusionVersions -join "|")) -and ((-not $exclusionApplications) -or $_.DisplayName -notmatch ($exclusionApplications -join "|"))} | Select-Object DisplayName, Publisher, DisplayVersion, UninstallString | Sort-Object DisplayName
	
	Write-Verbose "Collection complete"	
	
	$itemsToRemove
}

Function Remove-PUApplications($appsToRemove){
	#Let's start the fun!
	if(-not $appsToRemove){
		Write-Warning "Nothing to uninstall."
		exit
	}
	
	#much of the following is a rework of the work done by /u/pouncer11, modified to include support for non-MSI based installations
	Write-Verbose "Applications To Remove: "
	foreach($appToRemove in $appsToRemove){
		Write-Verbose "    $($appToRemove.DisplayName): ($($appToRemove.UninstallString))"
	}
	foreach($appToRemove in $appsToRemove){
		$uninstallGUID = $appToRemove.UninstallString -replace '.*({.*}).*','$1'
		
		if($uninstallGUID -match '[0-9a-z]{8}-([0-9a-z]{4}-){3}[0-9a-z]{12}'){
        	if(-not $WhatIf){
				Write-Verbose "Beginning removal of $($appToRemove.DisplayName)"
				if($logging){
					Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/X `"$($uninstallGUID)`" /qn $msiCustomArguments REBOOT=ReallySuppress /norestart /l*vx `"$logFilePath\$($appToRemove.DisplayName)_$($appToRemove.DisplayVersion)_REMOVE.log`"" -Wait -WorkingDirectory $pwd
				}else{
					Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList "/X `"$($uninstallGUID)`" /qn $msiCustomArguments REBOOT=ReallySuppress /norestart" -Wait -WorkingDirectory $pwd
				}
				Write-Verbose "Removal of $($appToRemove.DisplayName) complete"
			}else{
				Write-Verbose "Removal of $($appToRemove.DisplayName) WOULD take place"	
			}
        }else{
			if($nonMSISupport){
				if(-not $WhatIf){
					Write-Verbose "Attempting removal of $($appToRemove.DisplayName)"
					Start-Process -FilePath "$($appToRemove.UninstallString)" -ArgumentList "$nonMSICustomArguments" -Wait -WorkingDirectory $pwd
					Write-Verbose "Removal of $($appToRemove.DisplayName) complete"
				}else{
					Write-Verbose "Removal of $($appToRemove.DisplayName) WOULD take place"
				}
			}else{
				if(-not $WhatIf){
					Write-Warning "Not a Valid GUID for '$($appToRemove.DisplayName)' must be manually uninstalled, or you must run the command ."
				}else{
					Write-Verbose "Removal of $($appToRemove.DisplayName) would NOT take place, because Non-MSI support is not turned on"
				}
			}
		}
	}
}

#well... now the real fun actually begins
Remove-PUApplications (Get-PUApplications)
