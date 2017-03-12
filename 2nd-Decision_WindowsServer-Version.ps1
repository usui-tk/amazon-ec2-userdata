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
#      -  6.2 : Windows Server 2012 (Microsoft Windows Server 2012 [])
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
########################################################################################################################


#-----------------------------------------------------------------------------------------------------------------------
# User Define Parameter
#-----------------------------------------------------------------------------------------------------------------------

# Set Script Parameter for Directory Name (User Defined)
Set-Variable -Name TEMP_DIR -Scope Script "$Env:SystemRoot\Temp"

# Set Script Parameter for Log File Name (User Defined)
Set-Variable -Name USERDATA_LOG -Scope Script "$TEMP_DIR\userdata.log"
Set-Variable -Name TRANSCRIPT_LOG -Scope Script "$TEMP_DIR\userdata-transcript-2nd.log"

# Set Script Parameter for 3rd-Bootstrap Script (User Defined)

Set-Variable -Name BOOTSTRAP_URL -Scope Script -Value "https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/3rd-Bootstrap_WindowsServer.ps1"
Set-Variable -Name BOOTSTRAP_SCRIPT -Scope Script -Value "3rd-Bootstrap_WindowsServer.ps1"


########################################################################################################################
#
# Windows Bootstrap Common function
#
########################################################################################################################


function Format-Message
{
    param([string]$message)
    
    $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss.fffffff zzz"
    "$timestamp - $message"
} # end function Format-Message


function Write-Log
{
    param([string]$message, $log=$USERDATA_LOG)
    
    Format-Message $message | Out-File $log -Append -Forc
} # end function Write-Log


function Write-LogSeparator
{
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

Start-Transcript -Path "$TRANSCRIPT_LOG" -Append -Force

Set-Variable -Name ScriptFullPath -Scope Script -Value ($MyInvocation.InvocationName)
Write-Log "# Script Execution 2nd-Decision Script [START] : $ScriptFullPath"

Set-Location -Path $TEMP_DIR

Get-ExecutionPolicy -List
Set-StrictMode -Version Latest

#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Decision
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Decision"

#Get OS Infomation & Language
$Local:OSLanguage = ([CultureInfo]::CurrentCulture).IetfLanguageTag
$Local:OSversion = (Get-CimInstance Win32_OperatingSystem | Select-Object Version).Version

Write-Log ("# [Windows Infomation] OS Version : " + ($OSversion) + " - OS Language : "  + ($OSLanguage))

# Bootstrap Script Executite
if ($OSversion -match "^6.*|^10.*") {
    Write-Log ("# [Bootstrap Script]  : " + ($BOOTSTRAP_URL))
    Invoke-WebRequest -Uri $BOOTSTRAP_URL -OutFile $BOOTSTRAP_SCRIPT
    powershell.exe -ExecutionPolicy Bypass .\$BOOTSTRAP_SCRIPT -SkipNetworkProfileCheck
} else {
    Write-Log ("# [Warning] No Target - Windows NT Version Information : " + $OSversion)
}

