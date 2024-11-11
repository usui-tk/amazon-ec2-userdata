########################################################################################################################
#.SYNOPSIS
#
#   Amazon EC2 Decision Script - 2nd Decision
#
#.DESCRIPTION
#
#   Uses option settings to Windows Server Configuration
#
#.NOTES
#
#   Target Windows Server OS Version and Processor Architecture (64bit Only)
#
#      -  6.1 : Windows Server 2008 R2 (Microsoft Windows Server 2008 R2 SP1 [Datacenter Edition])
#               [Windows_Server-2008-R2_SP1-Japanese-64Bit-Base-YYYY.MM.DD]
#               [Windows_Server-2008-R2_SP1-English-64Bit-Base-YYYY.MM.DD]
#
#      -  6.2 : Windows Server 2012 (Microsoft Windows Server 2012 [Standard Edition])
#               [Windows_Server-2012-RTM-Japanese-64Bit-Base-YYYY.MM.DD]
#               [Windows_Server-2012-RTM-English-64Bit-Base-YYYY.MM.DD]
#
#      -  6.3 : Windows Server 2012 R2 (Microsoft Windows Server 2012 R2 [Standard Edition])
#               [Windows_Server-2012-R2_RTM-Japanese-64Bit-Base-YYYY.MM.DD]
#               [Windows_Server-2012-R2_RTM-English-64Bit-Base-YYYY.MM.DD]
#
#      - 10.0 : Windows Server 2016 (Microsoft Windows Server 2016 [Datacenter Edition])
#               [Windows_Server-2016-Japanese-Full-Base-YYYY.MM.DD]
#               [Windows_Server-2016-English-Full-Base-YYYY.MM.DD]
#
#      - 10.0 : Windows Server 2019 (Microsoft Windows Server 2019 [Datacenter Edition])
#               [Windows_Server-2019-Japanese-Full-Base-YYYY.MM.DD]
#               [Windows_Server-2019-English-Full-Base-YYYY.MM.DD]
#
#      - 10.0 : Windows Server 2022 (Microsoft Windows Server 2022 [Datacenter Edition])
#               [Windows_Server-2022-Japanese-Full-Base-YYYY.MM.DD]
#               [Windows_Server-2022-English-Full-Base-YYYY.MM.DD]
#
#      - 10.0 : Windows Server 2025 (Microsoft Windows Server 2025 [Datacenter Edition])
#               [Windows_Server-2025-Japanese-Full-Base-YYYY.MM.DD]
#               [Windows_Server-2025-English-Full-Base-YYYY.MM.DD]
#
########################################################################################################################


#-----------------------------------------------------------------------------------------------------------------------
# User Define Parameter
#-----------------------------------------------------------------------------------------------------------------------

# Set Script Parameter for Directory Name (User Defined)
Set-Variable -Name TEMP_DIR -Scope Script "$Env:SystemRoot\Temp"

# Set Script Parameter for Log File Name (User Defined)
Set-Variable -Name USERDATA_LOG -Scope Script "$TEMP_DIR\userdata.log"

# Set Script Parameter for 3rd-Bootstrap Script (User Defined)
Set-Variable -Name BOOTSTRAP_URL_MODERN -Scope Script -Value "https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_WindowsServer-Modern.ps1"
Set-Variable -Name BOOTSTRAP_URL_LEGACY -Scope Script -Value "https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_WindowsServer-Regacy.ps1"
Set-Variable -Name BOOTSTRAP_SCRIPT -Scope Script -Value "3rd-Bootstrap_WindowsServer.ps1"


########################################################################################################################
#
# Windows Bootstrap Common function
#
########################################################################################################################


function Format-Message {
	param([string]$message)

	$timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss.fffffff zzz"
	"$timestamp - $message"
} # end function Format-Message


function Write-Log {
	param([string]$message, $log = $USERDATA_LOG)

	Format-Message $message | Out-File $log -Append -Force
} # end function Write-Log


function Write-LogSeparator {
	param([string]$message)
	Write-Log "#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
	Write-Log ("#   Script Executetion Step : " + $message)
	Write-Log "#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
} # end function Write-LogSeparator


########################################################################################################################
#
# Start of script
#
########################################################################################################################

#-----------------------------------------------------------------------------------------------------------------------
# Preparation for script execution
#-----------------------------------------------------------------------------------------------------------------------

Set-Variable -Name ScriptFullPath -Scope Script -Value ($MyInvocation.InvocationName)
Write-Log "# Script Execution 2nd-Decision Script [START] : $ScriptFullPath"

Set-Location -Path $TEMP_DIR

#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Decision
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Decision"

#Get OS Infomation & Language
$Local:OSLanguage = ([CultureInfo]::CurrentCulture).IetfLanguageTag
$Local:OSversion = (Get-CimInstance Win32_OperatingSystem | Select-Object Version).Version
$Local:OSBuildNumber = (Get-CimInstance Win32_OperatingSystem | Select-Object BuildNumber).BuildNumber

Write-Log ("# [Windows Infomation] OS Version : " + ($OSversion) + " - OS Language : " + ($OSLanguage))

# Bootstrap Script Executite
if ($OSversion -match "^6.1.*") {
	# Log Separator
	Write-LogSeparator "# [Bootstrap Script] : Microsoft Windows Server 2008 R2"
	Write-Log ("# [Bootstrap Script] : " + ($BOOTSTRAP_URL_LEGACY))
	Invoke-WebRequest -Uri $BOOTSTRAP_URL_LEGACY -OutFile $BOOTSTRAP_SCRIPT
	Write-Log "# Script Execution 2nd-Decision Script [COMPLETE] : $ScriptFullPath"
	powershell.exe -ExecutionPolicy Bypass "$TEMP_DIR\$BOOTSTRAP_SCRIPT" -SkipNetworkProfileCheck
}
elseif ($OSversion -match "^6.2.*") {
	# Log Separator
	Write-LogSeparator "# [Bootstrap Script] : Microsoft Windows Server 2012"
	Write-Log ("# [Bootstrap Script] : " + ($BOOTSTRAP_URL_LEGACY))
	Invoke-WebRequest -Uri $BOOTSTRAP_URL_LEGACY -UseBasicParsing -OutFile $BOOTSTRAP_SCRIPT
	Write-Log "# Script Execution 2nd-Decision Script [COMPLETE] : $ScriptFullPath"
	powershell.exe -ExecutionPolicy Bypass "$TEMP_DIR\$BOOTSTRAP_SCRIPT" -SkipNetworkProfileCheck
}
elseif ($OSversion -match "^6.3.*") {
	# Log Separator
	Write-LogSeparator "# [Bootstrap Script] : Microsoft Windows Server 2012 R2"
	Write-Log ("# [Bootstrap Script] : " + ($BOOTSTRAP_URL_LEGACY))
	Invoke-WebRequest -Uri $BOOTSTRAP_URL_LEGACY -UseBasicParsing -OutFile $BOOTSTRAP_SCRIPT
	Write-Log "# Script Execution 2nd-Decision Script [COMPLETE] : $ScriptFullPath"
	powershell.exe -ExecutionPolicy Bypass "$TEMP_DIR\$BOOTSTRAP_SCRIPT" -SkipNetworkProfileCheck
}
elseif ($OSversion -match "^10.0.*") {
	switch ($OSBuildNumber) {
		'14393' {
			# Log Separator
			Write-LogSeparator "# [Bootstrap Script] : Microsoft Windows Server 2016"
			Write-Log ("# [Bootstrap Script] : " + ($BOOTSTRAP_URL_MODERN))
			Invoke-WebRequest -Uri $BOOTSTRAP_URL_MODERN -UseBasicParsing -OutFile $BOOTSTRAP_SCRIPT
			Write-Log "# Script Execution 2nd-Decision Script [COMPLETE] : $ScriptFullPath"
			powershell.exe -ExecutionPolicy Bypass "$TEMP_DIR\$BOOTSTRAP_SCRIPT" -SkipNetworkProfileCheck
		}
		'17763' {
			# Log Separator
			Write-LogSeparator "# [Bootstrap Script] : Microsoft Windows Server 2019"
			Write-Log ("# [Bootstrap Script] : " + ($BOOTSTRAP_URL_MODERN))
			Invoke-WebRequest -Uri $BOOTSTRAP_URL_MODERN -UseBasicParsing -OutFile $BOOTSTRAP_SCRIPT
			Write-Log "# Script Execution 2nd-Decision Script [COMPLETE] : $ScriptFullPath"
			powershell.exe -ExecutionPolicy Bypass "$TEMP_DIR\$BOOTSTRAP_SCRIPT" -SkipNetworkProfileCheck
		}
		'20348' {
			# Log Separator
			Write-LogSeparator "# [Bootstrap Script] : Microsoft Windows Server 2022"
			Write-Log ("# [Bootstrap Script] : " + ($BOOTSTRAP_URL_MODERN))
			Invoke-WebRequest -Uri $BOOTSTRAP_URL_MODERN -UseBasicParsing -OutFile $BOOTSTRAP_SCRIPT
			Write-Log "# Script Execution 2nd-Decision Script [COMPLETE] : $ScriptFullPath"
			powershell.exe -ExecutionPolicy Bypass "$TEMP_DIR\$BOOTSTRAP_SCRIPT" -SkipNetworkProfileCheck
		}
		'26100' {
			# Log Separator
			Write-LogSeparator "# [Bootstrap Script] : Microsoft Windows Server 2025"
			Write-Log ("# [Bootstrap Script] : " + ($BOOTSTRAP_URL_MODERN))
			Invoke-WebRequest -Uri $BOOTSTRAP_URL_MODERN -UseBasicParsing -OutFile $BOOTSTRAP_SCRIPT
			Write-Log "# Script Execution 2nd-Decision Script [COMPLETE] : $ScriptFullPath"
			powershell.exe -ExecutionPolicy Bypass "$TEMP_DIR\$BOOTSTRAP_SCRIPT" -SkipNetworkProfileCheck
		}
		default {
			# Log Separator
			Write-LogSeparator "# [Bootstrap Script] : Microsoft Windows Server (UnKnown Modern OS)"
			Write-Log ("# [Bootstrap Script] : " + ($BOOTSTRAP_URL_MODERN))
			Invoke-WebRequest -Uri $BOOTSTRAP_URL_MODERN -UseBasicParsing -OutFile $BOOTSTRAP_SCRIPT
			Write-Log "# Script Execution 2nd-Decision Script [COMPLETE] : $ScriptFullPath"
			powershell.exe -ExecutionPolicy Bypass "$TEMP_DIR\$BOOTSTRAP_SCRIPT" -SkipNetworkProfileCheck
		}
	}
}
else {
	Write-Log ("# [Warning] No Target - Windows NT Version Information : " + $OSversion)
}
