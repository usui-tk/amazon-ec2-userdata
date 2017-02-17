########################################################################################################################
#.SYNOPSIS
#
#   Amazon EC2 Bootstrap Script - 3rd Bootstrap
#
#.DESCRIPTION
#
#   Uses option settings to Windows Server Configuration
#
#.NOTES
#
#   Target Windows Server OS Version
#      - 10.0 : Windows Server 2016
#
########################################################################################################################


#-----------------------------------------------------------------------------------------------------------------------
# User Define Parameter
#-----------------------------------------------------------------------------------------------------------------------
$BASE_DIR           = "$Env:SystemDrive\EC2-Bootstrap"
$TOOL_DIR           = "$BASE_DIR\Tools"
$LOGS_DIR           = "$BASE_DIR\Logs"

$TEMP_DIR           = "$Env:SystemRoot\Temp"

$USERDATA_LOG       = "$TEMP_DIR\userdata.log"
$TRANSCRIPT_LOG     = "$LOGS_DIR\userdata-transcript-3rd.log"


########################################################################################################################
#
# Service-specific Functionality
#
########################################################################################################################

function Format-Message {
  param([string]$message)

  $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss.fffffff zzz"
  "$timestamp - $message"
} # end function Format-Message

function Log {
  param([string]$message, $log=$USERDATA_LOG)

  Format-Message $message | Out-File $log -Append -Force
} # end function Log

function Create-Directory {
  param([string]$dir)
  
  if (!(Test-Path -Path $dir)) {
    Log "# Creating directory : $dir"
    New-Item -Path $dir -ItemType Directory -Force
  }
} # end function Create-Directory

function Update-SysprepAnswerFile($answerFile)
{
    [xml] $document = Get-Content $answerFile -Encoding UTF8

    $ns = New-Object System.Xml.XmlNamespaceManager($document.NameTable)
    $ns.AddNamespace("u", $document.DocumentElement.NamespaceURI)

    $settings = $document.SelectSingleNode("//u:settings[@pass='oobeSystem']", $ns)

    $international = $settings.SelectSingleNode("u:component[@name='Microsoft-Windows-International-Core']", $ns)
    $shell = $settings.SelectSingleNode("u:component[@name='Microsoft-Windows-Shell-Setup']", $ns)

    $international.SystemLocale = "ja-JP"
    $international.UserLocale = "ja-JP"

    $shell.TimeZone = "Tokyo Standard Time"

    $document.Save($answerFile)
} # end function Update-SysprepAnswerFile


########################################################################################################################
#
# Start of script
#
########################################################################################################################

#-----------------------------------------------------------------------------------------------------------------------
# Timezone Setting
#-----------------------------------------------------------------------------------------------------------------------

Get-TimeZone
Set-TimeZone -Id "Tokyo Standard Time"
Start-Sleep -Seconds 5
Get-TimeZone

#-----------------------------------------------------------------------------------------------------------------------
# Preparation for script execution
#-----------------------------------------------------------------------------------------------------------------------

Create-Directory $BASE_DIR
Create-Directory $TOOL_DIR
Create-Directory $LOGS_DIR

Start-Transcript -Path "$TRANSCRIPT_LOG" -Append -Force

Log "# Script Execution 3rd-Bootstrap Script [START] : $MyInvocation.MyCommand.Path"

Set-Location -Path $BASE_DIR

Set-StrictMode -Version Latest

Get-ExecutionPolicy

#-----------------------------------------------------------------------------------------------------------------------
# Amazon EC2 System Define Parameter
#-----------------------------------------------------------------------------------------------------------------------

# Set AWS Instance Metadata
Set-Variable -Name AZ -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/placement/availability-zone)
Set-Variable -Name Region -Value (Invoke-RestMethod -Uri http://169.254.169.254/latest/dynamic/instance-identity/document).region
Set-Variable -Name InstanceId -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/instance-id)
Set-Variable -Name InstanceType -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/instance-type)
Set-Variable -Name PrivateIp -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/local-ipv4)
Set-Variable -Name AmiId -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/ami-id)

# Set IAM Role & STS Information
Set-Variable -Name RoleArn -Value ((Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/iam/info").Content | ConvertFrom-Json).InstanceProfileArn
Set-Variable -Name RoleName -Value ($RoleArn -split "/" | select -Index 1)

Set-Variable -Name StsCredential -Value ((Invoke-WebRequest -Uri ("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + $RoleName)).Content | ConvertFrom-Json)
Set-Variable -Name StsAccessKeyId -Value $StsCredential.AccessKeyId
Set-Variable -Name StsSecretAccessKey -Value $StsCredential.SecretAccessKey
Set-Variable -Name StsToken -Value $StsCredential.Token

# Set AWS Account ID
Set-Variable -Name AwsAccountId -Value ((Invoke-WebRequest "http://169.254.169.254/latest/dynamic/instance-identity/document").Content | ConvertFrom-Json).accountId

# Set Config File
Set-Variable -Name SysprepFile -Value "C:\Program Files\Amazon\Ec2ConfigService\sysprep2008.xml"
Set-Variable -Name EC2ConfigFile -Value "C:\Program Files\Amazon\Ec2ConfigService\Settings\Config.xml"
Set-Variable -Name CWLogsFile -Value "C:\Program Files\Amazon\Ec2ConfigService\Settings\AWS.EC2.Windows.CloudWatch.json"

# Set Log File
Set-Variable -Name SSMAgentLogFile -Value "C:\ProgramData\Amazon\SSM\Logs\amazon-ssm-agent.log"

# Logging AWS Instance Metadata
Log "# Display AWS Instance Metadata [Region] : $Region"
Log "# Display AWS Instance Metadata [Availability Zone] : $AZ"
Log "# Display AWS Instance Metadata [Instance ID] : $InstanceId"
Log "# Display AWS Instance Metadata [Instance Type] : $InstanceType"
Log "# Display AWS Instance Metadata [VPC Private IP Address] : $PrivateIp"
Log "# Display AWS Instance Metadata [Amazon Machine Images] : $AmiId"
Log "# Display AWS Instance Metadata [EC2 - Instance Profile ARN] : $RoleArn"
Log "# Display AWS Instance Metadata [EC2 - IAM Role Name] : $RoleName"


#-----------------------------------------------------------------------------------------------------------------------
# Amazon EC2 Information [AMI & Instance & EBS Volume]
#-----------------------------------------------------------------------------------------------------------------------

# Setting AWS Tools for Windows PowerShell
Set-DefaultAWSRegion -Region $Region
$__DefaultAWSRegion = Get-DefaultAWSRegion
Log "# Display Default Region at AWS Tools for Windows Powershell : $__DefaultAWSRegion"

# Get AMI Information
if ($RoleName) {
    Log "# Get AMI Information"
    Get-EC2Image -ImageId $AmiId | ConvertTo-Json
}

# Get EC2 Instance Information
if ($RoleName) {
    Log "# Get EC2 Instance Information"
    Get-EC2Instance -Filter @{Name = "instance-id"; Values = $InstanceId} | ConvertTo-Json
}

# Get EC2 Instance attached EBS Volume Information
if ($RoleName) {
    Log "# Get EC2 Instance attached EBS Volume Information"
    Get-EC2Volume | Where-Object { $_.Attachments.InstanceId -eq $InstanceId} | ConvertTo-Json
}

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
if ($RoleName) {
    if ($InstanceType -match "^x1.*|^p2.*|^r4.*|^m4.16xlarge") {
        # Get EC2 Instance Attribute(Elastic Network Adapter Status)
        Log "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
        Get-EC2Instance -Filter @{Name = "instance-id"; Values = $InstanceId} | Select-Object -ExpandProperty "Instances"
        # Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EnaSupport
    } elseif ($InstanceType -match "^c3.*|^c4.*|^d2.*|^i2.*|^m4.*|^r3.*") {
        # Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
        Log "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
        Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute sriovNetSupport
    } else {
        Log "# Instance type of None [Network Interface Performance Attribute]"
    }
}

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
if ($RoleName) {
    if ($InstanceType -match "^c1.*|^c3.*|^c4.*|^d2.*|^g2.*|^i2.*|^m1.*|^m2.*|^m3.*|^m4.*|^p2.*|^r3.*|^r4.*|^x1.*") {
        # Get EC2 Instance Attribute(EBS-optimized instance Status)
        Log "# Get EC2 Instance Attribute(EBS-optimized instance Status)"
        Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EbsOptimized
    } else {
        Log "# Instance type of None [Storage Interface Performance Attribute]"
    }
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration
#-----------------------------------------------------------------------------------------------------------------------

# Setting System Locale
$__WinSystemLocale = Get-WinSystemLocale
Log "# Display Windows System Locale [Before] : $__WinSystemLocale"
Set-WinSystemLocale -SystemLocale ja-JP
Log "# Display Windows System Locale [After] : $__WinSystemLocale"

$__WinHomeLocation = Get-WinHomeLocation
Log "# Display Windows Home Location [Before] : $__WinHomeLocation"
Set-WinHomeLocation -GeoId 0x7A
Log "# Display Windows Home Location [After] : $__WinHomeLocation"

$__WinCultureFromLanguageListOptOut = Get-WinCultureFromLanguageListOptOut
Log "# Make the date and time [format] the same as the display language [Before] : $__WinCultureFromLanguageListOptOut"
Set-WinCultureFromLanguageListOptOut -OptOut $False
Log "# Make the date and time [format] the same as the display language [After] : $__WinCultureFromLanguageListOptOut"

# Setting Japanese UI Language
$__WinUILanguageOverride = Get-WinUILanguageOverride
Log "# Override display language [Before] : $__WinUILanguageOverride"
Set-WinUILanguageOverride ja-JP
Log "# Override display language [After] : $__WinUILanguageOverride"


# Change Windows Update Policy
#$AUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
#$AUSettings.NotificationLevel         = 3      # Automatic Updates prompts users to approve updates & before downloading or installing
#$AUSettings.ScheduledInstallationDay  = 1      # Every Sunday
#$AUSettings.ScheduledInstallationTime = 3      # AM 3:00
#$AUSettings.IncludeRecommendedUpdates = $True  # Enabled
#$AUSettings.FeaturedUpdatesEnabled    = $True  # Enabled
#$AUSettings.Save()

Start-Sleep -Seconds 5

# Enable Microsoft Update
$SMSettings = New-Object -ComObject Microsoft.Update.ServiceManager -Strict 
$SMSettings.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
$SMSettings.Services

Start-Sleep -Seconds 5

# Update Sysprep Answer Files
Get-Content $SysprepFile

Update-SysprepAnswerFile $SysprepFile

Get-Content $SysprepFile

# Change Windows Folder Option Policy
Set-Variable -Name RegistryFolderOption -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

Set-ItemProperty -Path $RegistryFolderOption -name 'Hidden' -value '1' -force                                  # [Check] Show hidden files, folders, or drives
Set-ItemProperty -Path $RegistryFolderOption -name 'HideFileExt' -value '0' -force                             # [UnCheck] Hide extensions for known file types
New-ItemProperty -Path $RegistryFolderOption -name 'PersistBrowsers' -value '1' -propertyType "DWord" -force   # [Check] Restore previous folders windows

# Change Display Desktop Icon Policy
Set-Variable -Name RegistryDesktopIcon -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
Set-Variable -Name RegistryDesktopIconSetting -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"

New-Item -Path $RegistryDesktopIcon
New-Item -Path $RegistryDesktopIconSetting

New-ItemProperty -Path $RegistryDesktopIconSetting -name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -value '0' -propertyType "DWord" -force  #[CLSID] : My Computer
New-ItemProperty -Path $RegistryDesktopIconSetting -name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -value '0' -propertyType "DWord" -force  #[CLSID] : Control Panel
New-ItemProperty -Path $RegistryDesktopIconSetting -name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -value '0' -propertyType "DWord" -force  #[CLSID] : User's Files
New-ItemProperty -Path $RegistryDesktopIconSetting -name '{645FF040-5081-101B-9F08-00AA002F954E}' -value '0' -propertyType "DWord" -force  #[CLSID] : Recycle Bin
New-ItemProperty -Path $RegistryDesktopIconSetting -name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -value '0' -propertyType "DWord" -force  #[CLSID] : Network

# Test Connecting to the Internet (Google Public DNS:8.8.8.8)
if (Test-Connection -ComputerName 8.8.8.8 -Count 1) {
    # Change NetConnectionProfile
    Get-NetConnectionProfile -IPv4Connectivity Internet
    Set-NetConnectionProfile -InterfaceAlias (Get-NetConnectionProfile -IPv4Connectivity Internet).InterfaceAlias -NetworkCategory Private
    Start-Sleep -Seconds 5
    Get-NetConnectionProfile -IPv4Connectivity Internet
}

# Disable IPv6 Binding
Get-NetAdapterBinding

if (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "Amazon Elastic Network Adapter" }) {
    Log "# Disable-NetAdapterBinding(IPv6) : Amazon Elastic Network Adapter"
    Disable-NetAdapterBinding -InterfaceDescription "Amazon Elastic Network Adapter" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "Intel(R) 82599 Virtual Function" }) {
    Log "# Disable-NetAdapterBinding(IPv6) : Intel(R) 82599 Virtual Function"
    Disable-NetAdapterBinding -InterfaceDescription "Intel(R) 82599 Virtual Function" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "AWS PV Network Device #0" }) {
    Log "# Disable-NetAdapterBinding(IPv6) : AWS PV Network Device"
    Disable-NetAdapterBinding -InterfaceDescription "AWS PV Network Device #0" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} else {
    Log "# Disable-NetAdapterBinding(IPv6) : No Target Device"
}

Get-NetAdapterBinding

# Change System PowerPlan (High Performance)
$HighPowerBase64 = "6auY44OR44OV44Kp44O844Oe44Oz44K5"                       # A string of "high performance" was Base64 encoded in Japanese
$HighPowerByte = [System.Convert]::FromBase64String($HighPowerBase64)       # Conversion from base64 to byte sequence
$HighPowerString = [System.Text.Encoding]::UTF8.GetString($HighPowerByte)   # To convert a sequence of bytes into a string of UTF-8 encoding

Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Select-Object ElementName, IsActive, Description

if (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq $HighPowerString }) {
    Log "# Change System PowerPlan : $HighPowerString"
    $HighPowerObject = Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq $HighPowerString }
    $HighPowerObject.Activate()
    Start-Sleep -Seconds 5
} elseif (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq "High performance" }) {
    Log "# Change System PowerPlan : High performance"
    (Get-WmiObject -Name root\cimv2\power -Class Win32_PowerPlan -Filter 'ElementName = "High performance"').Activate()
    Start-Sleep -Seconds 5
} else {
    Log "# Change System PowerPlan : No change"
}

Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Select-Object ElementName, IsActive, Description


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Update (Amazon EC2 Systems Manager Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Package Update System Utility (Amazon EC2 Systems Manager Agent)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/systems-manager-managedinstances.html#sysman-install-managed-win
Log "# Package Download System Utility (Amazon EC2 Systems Manager Agent)"
$AmazonSSMAgentUrl = "https://amazon-ssm-" + ${Region} + ".s3.amazonaws.com/latest/windows_amd64/AmazonSSMAgentSetup.exe"
Invoke-WebRequest -Uri $AmazonSSMAgentUrl -OutFile "$TOOL_DIR\AmazonSSMAgentSetup.exe"
Start-Process -FilePath "$TOOL_DIR\AmazonSSMAgentSetup.exe" -ArgumentList @('ALLOWEC2INSTALL=YES', '/install', '/norstart', '/log C:\EC2-Bootstrap\Logs\AmazonSSMAgentSetup.log', '/quiet') -Wait | Out-Null
Start-Sleep -Seconds 120

Get-Service -Name AmazonSSMAgent

$AmazonSSMAgentStatus = (Get-WmiObject Win32_Service -filter "Name='AmazonSSMAgent'").StartMode

if ($AmazonSSMAgentStatus -ne "Auto") {
    Log "# Service Startup Type Change [AmazonSSMAgent] $AmazonSSMAgentStatus -> Auto"
    Set-Service -Name "AmazonSSMAgent" -StartupType Automatic
    Log "# Service Startup Type Staus [AmazonSSMAgent] $AmazonSSMAgentStatus"
}

# Clear Log File
Clear-Content $SSMAgentLogFile

# Get Amazon SSM Agent Service Status
Restart-Service -Name AmazonSSMAgent
Start-Sleep -Seconds 30
Get-Service -Name AmazonSSMAgent

Get-Content $SSMAgentLogFile


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (System Utility)
#-----------------------------------------------------------------------------------------------------------------------

# Package Download System Utility (Sysinternals Suite)
# https://technet.microsoft.com/ja-jp/sysinternals/bb842062.aspx
Log "# Package Download System Utility (Sysinternals Suite)"
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SysinternalsSuite.zip' -OutFile "$TOOL_DIR\SysinternalsSuite.zip"

# Package Download System Utility (System Explorer)
# http://systemexplorer.net/
Log "# Package Download System Utility (System Explorer)"
Invoke-WebRequest -Uri 'http://systemexplorer.net/download/SystemExplorerSetup.exe' -OutFile "$TOOL_DIR\SystemExplorerSetup.exe"

# Package Download System Utility (7-zip)
# http://www.7-zip.org/
Log "# Package Download System Utility (7-zip)"
Invoke-WebRequest -Uri 'http://www.7-zip.org/a/7z1604-x64.exe' -OutFile "$TOOL_DIR\7z1604-x64.exe"

# Package Download System Utility (EC2Config)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/UsingConfig_Install.html
# Log "# Package Download System Utility (EC2Config)"
# Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Config/EC2Install.zip' -OutFile "$TOOL_DIR\EC2Install.zip"

# Package Download System Utility (EC2Launch)
# http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2launch.html
Log "# Package Download System Utility (EC2Launch)"
Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Launch/latest/EC2-Windows-Launch.zip' -OutFile "$TOOL_DIR\EC2-Windows-Launch.zip"
Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Launch/latest/install.ps1' -OutFile "$TOOL_DIR\EC2-Windows-Launch-install.ps1"

# Package Download System Utility (AWS-CLI - 64bit)
# https://aws.amazon.com/jp/cli/
Log "# Package Download System Utility (AWS-CLI - 64bit)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/aws-cli/AWSCLI64.msi' -OutFile "$TOOL_DIR\AWSCLI64.msi"

# Package Download System Utility (AWS Tools for Windows PowerShell)
# https://aws.amazon.com/jp/powershell/
Log "# Package Download System Utility (AWS Tools for Windows PowerShell)"
Invoke-WebRequest -Uri 'http://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi' -OutFile "$TOOL_DIR\AWSToolsAndSDKForNet.msi"

# Package Download System Utility (AWS Diagnostics for Windows Server)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/Windows-Server-Diagnostics.html
Log "# Package Download System Utility (AWS Diagnostics for Windows Server)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ec2-downloads-windows/AWSDiagnostics/AWSDiagnostics.zip' -OutFile "$TOOL_DIR\AWSDiagnostics.zip"

# Package Download System Utility (Amazon Inspector Agent)
# https://docs.aws.amazon.com/ja_jp/inspector/latest/userguide/inspector_working-with-agents.html#inspector-agent-windows
Log "# Package Download System Utility (Amazon Inspector Agent)"
Invoke-WebRequest -Uri 'https://d1wk0tztpsntt1.cloudfront.net/windows/installer/latest/AWSAgentInstall.exe' -OutFile "$TOOL_DIR\AWSAgentInstall.exe"

# Package Download System Utility (AWS CodeDeploy agent)
# http://docs.aws.amazon.com/ja_jp/codedeploy/latest/userguide/how-to-run-agent-install.html#how-to-run-agent-install-windows
Log "# Package Download System Utility (AWS CodeDeploy agent)"
$AWSCodeDeployAgentUrl = "https://aws-codedeploy-" + ${Region} + ".s3.amazonaws.com/latest/codedeploy-agent.msi"
Invoke-WebRequest -Uri $AWSCodeDeployAgentUrl -OutFile "$TOOL_DIR\codedeploy-agent.msi"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Monitoring Service Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Package Download Monitoring Service Agent (Zabix Agent)
# http://www.zabbix.com/download
Log "# Package Download Monitoring Service Agent (Zabix Agent)"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/2.2.14/zabbix_agents_2.2.14.win.zip' -OutFile "$TOOL_DIR\zabbix_agents_2.2.14.win.zip"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/3.0.4/zabbix_agents_3.0.4.win.zip' -OutFile "$TOOL_DIR\zabbix_agents_3.0.4.win.zip"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/3.2.0/zabbix_agents_3.2.0.win.zip' -OutFile "$TOOL_DIR\zabbix_agents_3.2.0.win.zip"

# Package Download Monitoring Service Agent (Datadog Agent)
# http://docs.datadoghq.com/ja/guides/basic_agent_usage/windows/
Log "# Package Download Monitoring Service Agent (Datadog Agent)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ddagent-windows-stable/ddagent-cli.msi' -OutFile "$TOOL_DIR\ddagent-cli.msi"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Security Service Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Package Download Security Service Agent (Deep Security Agent)
# http://esupport.trendmicro.com/ja-jp/enterprise/dsaas/top.aspx
Log "# Package Download Security Service Agent (Deep Security Agent)"
Invoke-WebRequest -Uri 'https://app.deepsecurity.trendmicro.com/software/agent/Windows/x86_64/agent.msi' -OutFile "$TOOL_DIR\DSA_agent.msi"

# Package Download Security Service Agent (Alert Logic Universal Agent)
# https://docs.alertlogic.com/requirements/system-requirements.htm#reqsAgent
Log "# Package Download Security Service Agent (Alert Logic Universal Agent)"
Invoke-WebRequest -Uri 'https://scc.alertlogic.net/software/al_agent-LATEST.msi' -OutFile "$TOOL_DIR\al_agent-LATEST.msi"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Storage & Network Driver)
#-----------------------------------------------------------------------------------------------------------------------

# Package Download Amazon Windows Paravirtual Drivers
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/xen-drivers-overview.html
Log "# Package Download Amazon Windows Paravirtual Drivers"
Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/Drivers/AWSPVDriverSetup.zip' -OutFile "$TOOL_DIR\PROWinx64.exe"

# Package Download Intel Network Driver (Windows Server 2008 R2)
# https://downloadcenter.intel.com/ja/download/18725/
# Log "# Package Download Intel Network Driver (Windows Server 2008 R2)"
# Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/18725/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"

# Package Download Intel Network Driver (Windows Server 2012)
# https://downloadcenter.intel.com/ja/download/21694/
# Log "# Package Download Intel Network Driver (Windows Server 2012)"
# Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/21694/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"

# Package Download Intel Network Driver (Windows Server 2012 R2)
# https://downloadcenter.intel.com/ja/download/23073/
# Log "# Package Download Intel Network Driver (Windows Server 2012 R2)"
# Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/23073/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"

# Package Download Intel Network Driver (Windows Server 2016)
# https://downloadcenter.intel.com/ja/download/26092/
Log "# Package Download Intel Network Driver (Windows Server 2016)"
Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/26092/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"

# Package Download Amazon Elastic Network Adapter Driver
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/enhanced-networking-ena.html
Log "# Package Download Amazon Elastic Network Adapter Driver"
Invoke-WebRequest -Uri 'http://ec2-windows-drivers.s3.amazonaws.com/ENA.zip' -OutFile "$TOOL_DIR\ENA.zip"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Installation (Application)
#-----------------------------------------------------------------------------------------------------------------------

# Package Install Modern Web Browser (Google Chrome 64bit)
Log "# Package Install Modern Web Browser (Google Chrome 64bit)"
Invoke-WebRequest -Uri 'https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi' -OutFile "$TOOL_DIR\googlechrome.msi"
Start-Process -FilePath "$TOOL_DIR\googlechrome.msi" -ArgumentList @("/quiet", "/log C:\EC2-Bootstrap\Logs\ChromeSetup.log") -Wait | Out-Null
Start-Sleep -Seconds 120

# Package Install Text Editor (Visual Studio Code)
Log "# Package Install Text Editor (Visual Studio Code)"
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?LinkID=623230' -OutFile "$TOOL_DIR\VSCodeSetup-stable.exe"
Start-Process -FilePath "$TOOL_DIR\VSCodeSetup-stable.exe" -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/LOG=C:\EC2-Bootstrap\Logs\VSCodeSetup.log") | Out-Null
Start-Sleep -Seconds 120

#-----------------------------------------------------------------------------------------------------------------------
# Collect Logging Data Files
#-----------------------------------------------------------------------------------------------------------------------

# Stop Transcript Logging
Stop-Transcript

Log "# Script Execution 3rd-Bootstrap Script [COMPLETE] : $MyInvocation.MyCommand.Path"

# Save Script Files
Copy-Item -Path "$TEMP_DIR\*.ps1" -Destination $BASE_DIR

# Save Configuration Files
Copy-Item -Path $SysprepFile -Destination $BASE_DIR
Copy-Item -Path $EC2LaunchFile -Destination $BASE_DIR
# Copy-Item -Path $CWLogsFile -Destination $BASE_DIR
Copy-Item "C:\ProgramData\Amazon\EC2-Windows\Launch\Config\*.json" $BASE_DIR

# Save Logging Files
Copy-Item -Path $USERDATA_LOG -Destination $LOGS_DIR 
Copy-Item -Path "C:\ProgramData\Amazon\EC2-Windows\Launch\Log\*.log" -Destination $LOGS_DIR 
Copy-Item -Path $SSMAgentLogFile -Destination $LOGS_DIR 
Copy-Item -Path "$TEMP_DIR\*.tmp" -Destination $LOGS_DIR 


#-----------------------------------------------------------------------------------------------------------------------
# Hostname rename & Instance Reboot
#-----------------------------------------------------------------------------------------------------------------------

# Setting Hostname
Rename-Computer $PrivateIp.Replace(".", "-") -Force

# EC2 Instance Reboot
Restart-Computer -Force
