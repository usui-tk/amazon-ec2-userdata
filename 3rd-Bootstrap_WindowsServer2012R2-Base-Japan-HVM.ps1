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
#      - 6.3 : Windows Server 2012 R2
#
########################################################################################################################


#-----------------------------------------------------------------------------------------------------------------------
# User Define Parameter
#-----------------------------------------------------------------------------------------------------------------------
$BASE_DIR           = "$Env:SystemDrive\EC2-Bootstrap"
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

  $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss.fffffff"
  "$timestamp - $message"
} # end function Format-Message

function Log {
  param([string]$message, $log=$USERDATA_LOG)

  Format-Message $message | Out-File $log -Append -Force
} # end function Log

function Create-Directory {
  param([string]$dir)
  
  If (!(Test-Path -Path $dir)) {
    Log "Creating directory: $dir"
    New-Item -Path $dir -ItemType Directory -Force
  }
} # end function Create-Directory

function Set-TimeZone {
  [CmdletBinding(SupportsShouldProcess = $True)]
  param( 
    [Parameter(ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $True, Mandatory = $False)]
    [ValidateSet("Dateline Standard Time","UTC-11","Hawaiian Standard Time","Alaskan Standard Time","Pacific Standard Time (Mexico)","Pacific Standard Time","US Mountain Standard Time","Mountain Standard Time (Mexico)","Mountain Standard Time","Central America Standard Time","Central Standard Time","Central Standard Time (Mexico)","Canada Central Standard Time","SA Pacific Standard Time","Eastern Standard Time","US Eastern Standard Time","Venezuela Standard Time","Paraguay Standard Time","Atlantic Standard Time","Central Brazilian Standard Time","SA Western Standard Time","Pacific SA Standard Time","Newfoundland Standard Time","E. South America Standard Time","Argentina Standard Time","SA Eastern Standard Time","Greenland Standard Time","Montevideo Standard Time","Bahia Standard Time","UTC-02","Mid-Atlantic Standard Time","Azores Standard Time","Cape Verde Standard Time","Morocco Standard Time","UTC","GMT Standard Time","Greenwich Standard Time","W. Europe Standard Time","Central Europe Standard Time","Romance Standard Time","Central European Standard Time","W. Central Africa Standard Time","Namibia Standard Time","Jordan Standard Time","GTB&nbsp;Standard Time","Middle East Standard Time","Egypt Standard Time","Syria Standard Time","E. Europe Standard Time","South Africa Standard Time","FLE&nbsp;Standard Time","Turkey Standard Time","Israel Standard Time","Arabic Standard Time","Kaliningrad Standard Time","Arab Standard Time","E. Africa Standard Time","Iran Standard Time","Arabian Standard Time","Azerbaijan Standard Time","Russian Standard Time","Mauritius Standard Time","Georgian Standard Time","Caucasus Standard Time","Afghanistan Standard Time","Pakistan Standard Time","West Asia Standard Time","India Standard Time","Sri Lanka Standard Time","Nepal Standard Time","Central Asia Standard Time","Bangladesh Standard Time","Ekaterinburg Standard Time","Myanmar Standard Time","SE Asia Standard Time","N. Central Asia Standard Time","China Standard Time","North Asia Standard Time","Singapore Standard Time","W. Australia Standard Time","Taipei Standard Time","Ulaanbaatar Standard Time","North Asia East Standard Time","Tokyo Standard Time","Korea Standard Time","Cen. Australia Standard Time","AUS Central Standard Time","E. Australia Standard Time","AUS Eastern Standard Time","West Pacific Standard Time","Tasmania Standard Time","Yakutsk&nbsp;Standard Time","Central Pacific Standard Time","Vladivostok Standard Time","New Zealand Standard Time","UTC+12","Fiji Standard Time","Magadan&nbsp;Standard Time","Tonga Standard Time","Samoa Standard Time")]
    [ValidateNotNullOrEmpty()]
    [string]$TimeZone = "Tokyo Standard Time"
  ) 

  $process = New-Object System.Diagnostics.Process 
  $process.StartInfo.WindowStyle = "Hidden" 
  $process.StartInfo.FileName = "tzutil.exe" 
  $process.StartInfo.Arguments = "/s `"$TimeZone`"" 
  $process.Start() | Out-Null 
} # end function Set-TimeZone


########################################################################################################################
#
# Start of script
#
########################################################################################################################

#-----------------------------------------------------------------------------------------------------------------------
# Timezone Setting
#-----------------------------------------------------------------------------------------------------------------------

Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
Set-TimeZone "Tokyo Standard Time"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"

Start-Sleep -Seconds 5


#-----------------------------------------------------------------------------------------------------------------------
# Preparation for script execution
#-----------------------------------------------------------------------------------------------------------------------

Create-Directory $BASE_DIR
Create-Directory $LOGS_DIR

Start-Transcript -Path "$TRANSCRIPT_LOG" -Append -Force

Set-Location -Path $BASE_DIR

Set-StrictMode -Version Latest

Get-ExecutionPolicy
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force
Get-ExecutionPolicy


#-----------------------------------------------------------------------------------------------------------------------
# Amazon EC2 System Define Parameter
#-----------------------------------------------------------------------------------------------------------------------

# Set AWS Instance MetaData
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

# Set Setting File
Set-Variable -Name SysprepSettingsFile -Value "C:\Program Files\Amazon\Ec2ConfigService\sysprep2008.xml"
Set-Variable -Name EC2SettingsFile -Value "C:\Program Files\Amazon\Ec2ConfigService\Settings\Config.xml"
Set-Variable -Name CWLogsSettingsFile -Value "C:\Program Files\Amazon\Ec2ConfigService\Settings\AWS.EC2.Windows.CloudWatch.json"

# Get System & User Variables
Get-Variable | Export-Csv -Encoding default bootstrap-variable.csv


#-----------------------------------------------------------------------------------------------------------------------
# Amazon EC2 Information [AMI & Instance & EBS Volume]
#-----------------------------------------------------------------------------------------------------------------------

# Setting AWS Tools for Windows PowerShell
Set-DefaultAWSRegion -Region $Region
Get-DefaultAWSRegion

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

# Setting SystemLocale
Get-WinSystemLocale
Set-WinSystemLocale -SystemLocale ja-JP
Get-WinSystemLocale

Get-WinHomeLocation
Set-WinHomeLocation -GeoId 0x7A
Get-WinHomeLocation

Get-WinCultureFromLanguageListOptOut
Set-WinCultureFromLanguageListOptOut -OptOut $False
Get-WinCultureFromLanguageListOptOut

# Setting Japanese UI
Get-WinUILanguageOverride
Set-WinUILanguageOverride ja-JP
Get-WinUILanguageOverride

# Change Windows Update Policy
$AUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
$AUSettings.NotificationLevel         = 3      # Automatic Updates prompts users to approve updates & before downloading or installing
$AUSettings.ScheduledInstallationDay  = 1      # Every Sunday
$AUSettings.ScheduledInstallationTime = 5      # AM 5:00
$AUSettings.IncludeRecommendedUpdates = $True  # Enabled
$AUSettings.FeaturedUpdatesEnabled    = $True  # Enabled
$AUSettings.Save()

Start-Sleep -Seconds 5

# Enable Microsoft Update
$SMSettings = New-Object -ComObject Microsoft.Update.ServiceManager -Strict 
$SMSettings.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
$SMSettings.Services

Start-Sleep -Seconds 5

# Enable EC2config EventLog Output
Get-Content $EC2SettingsFile

$xml1 = [xml](Get-Content $EC2SettingsFile)
$xmlElement1 = $xml1.get_DocumentElement()
$xmlElementToModify1 = $xmlElement1.Plugins

foreach ($element in $xmlElementToModify1.Plugin)
{
    if ($element.name -eq "Ec2EventLog")
    {
        $element.State="Enabled"
    }
}
$xml1.Save($EC2SettingsFile)

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
    Write-Output "Disable-NetAdapterBinding(IPv6) : Amazon Elastic Network Adapter"
    Disable-NetAdapterBinding -InterfaceDescription "Amazon Elastic Network Adapter" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "Intel(R) 82599 Virtual Function" }) {
    Write-Output "Disable-NetAdapterBinding(IPv6) : Intel(R) 82599 Virtual Function"
    Disable-NetAdapterBinding -InterfaceDescription "Intel(R) 82599 Virtual Function" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "AWS PV Network Device #0" }) {
    Write-Output "Disable-NetAdapterBinding(IPv6) : AWS PV Network Device"
    Disable-NetAdapterBinding -InterfaceDescription "AWS PV Network Device #0" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} else {
    Write-Output "Disable-NetAdapterBinding(IPv6) : No Target Device"
}

Get-NetAdapterBinding

# Change System PowerPlan (High Performance)
$HighPowerBase64 = "6auY44OR44OV44Kp44O844Oe44Oz44K5"                       # A string of "high performance" was Base64 encoded in Japanese
$HighPowerByte = [System.Convert]::FromBase64String($HighPowerBase64)       # Conversion from base64 to byte sequence
$HighPowerString = [System.Text.Encoding]::UTF8.GetString($HighPowerByte)   # To convert a sequence of bytes into a string of UTF-8 encoding

Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Select-Object ElementName, IsActive, Description

if (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq $HighPowerString }) {
    Write-Output "Change System PowerPlan : $HighPowerString"
    $HighPowerObject = Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq $HighPowerString }
    $HighPowerObject.Activate()
    Start-Sleep -Seconds 5
} elseif (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq "High performance" }) {
    Write-Output "Change System PowerPlan : High performance"
    (Get-WmiObject -Name root\cimv2\power -Class Win32_PowerPlan -Filter 'ElementName = "High performance"').Activate()
    Start-Sleep -Seconds 5
} else {
    Write-Output "Change System PowerPlan : No change"
}

Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Select-Object ElementName, IsActive, Description


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (System Utility)
#-----------------------------------------------------------------------------------------------------------------------

# Package Download System Utility (Sysinternals Suite)
# https://technet.microsoft.com/ja-jp/sysinternals/bb842062.aspx
Log "# Package Download System Utility (Sysinternals Suite)"
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SysinternalsSuite.zip' -OutFile "$BASE_DIR\SysinternalsSuite.zip"

# Package Download System Utility (System Explorer)
# http://systemexplorer.net/
Log "# Package Download System Utility (System Explorer)"
Invoke-WebRequest -Uri 'http://systemexplorer.net/download/SystemExplorerSetup.exe' -OutFile "$BASE_DIR\SystemExplorerSetup.exe"

# Package Download System Utility (Tera Term)
# https://ja.osdn.net/projects/ttssh2/
Log "# Package Download System Utility (Tera Term)"
Invoke-WebRequest -Uri 'https://ja.osdn.net/dl/ttssh2/teraterm-4.93.exe' -OutFile "$BASE_DIR\TeraTermSetup.exe"

# Package Download System Utility (AWS-CLI)
# https://aws.amazon.com/jp/cli/
Log "# Package Download System Utility (AWS-CLI)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/aws-cli/AWSCLI64.msi' -OutFile "$BASE_DIR\AWSCLI64.msi"

# Package Download System Utility (AWS Diagnostics for Windows Server)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/Windows-Server-Diagnostics.html
Log "# Package Download System Utility (AWS Diagnostics for Windows Server)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ec2-downloads-windows/AWSDiagnostics/AWSDiagnostics.zip' -OutFile "$BASE_DIR\AWSDiagnostics.zip"

# Package Download System Utility (Amazon Inspector Agent)
# https://docs.aws.amazon.com/ja_jp/inspector/latest/userguide/inspector_working-with-agents.html#inspector-agent-windows
Log "# Package Download System Utility (Amazon Inspector Agent)"
Invoke-WebRequest -Uri 'https://d1wk0tztpsntt1.cloudfront.net/windows/installer/latest/AWSAgentInstall.exe' -OutFile "$BASE_DIR\AWSAgentInstall.exe"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Monitoring Service Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Package Download Monitoring Service Agent (Zabix Agent)
# http://www.zabbix.com/download
Log "# Package Download Monitoring Service Agent (Zabix Agent)"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/2.2.14/zabbix_agents_2.2.14.win.zip' -OutFile "$BASE_DIR\zabbix_agents_2.2.14.win.zip"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/3.0.4/zabbix_agents_3.0.4.win.zip' -OutFile "$BASE_DIR\zabbix_agents_3.0.4.win.zip"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/3.2.0/zabbix_agents_3.2.0.win.zip' -OutFile "$BASE_DIR\zabbix_agents_3.2.0.win.zip"

# Package Download Monitoring Service Agent (Datadog Agent)
# http://docs.datadoghq.com/ja/guides/basic_agent_usage/windows/
Log "# Package Download Monitoring Service Agent (Datadog Agent)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ddagent-windows-stable/ddagent-cli.msi' -OutFile "$BASE_DIR\ddagent-cli.msi"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Network Driver)
#-----------------------------------------------------------------------------------------------------------------------

# Package Download Intel Network Driver
# https://downloadcenter.intel.com/ja/download/23073/
Log "# Package Download Intel Network Driver"
Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/23073/eng/PROWinx64.exe' -OutFile "$BASE_DIR\PROWinx64.exe"

# Package Download Amazon Elastic Network Adapter Driver
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/enhanced-networking-ena.html
Log "# Package Download Amazon Elastic Network Adapter Driver"
Invoke-WebRequest -Uri 'http://ec2-windows-drivers.s3.amazonaws.com/ENA.zip' -OutFile "$BASE_DIR\ENA.zip"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Installation (Application)
#-----------------------------------------------------------------------------------------------------------------------

# Package Install Text Editor (Visual Studio Code)
Log "# Package Install Text Editor (Visual Studio Code)"
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?LinkID=623230' -OutFile "$BASE_DIR\VSCodeSetup-stable.exe"
Start-Process -FilePath "$BASE_DIR\VSCodeSetup-stable.exe" -ArgumentList '/verysilent /suppressmsgboxes /LOG=C:\EC2-Bootstrap\Logs\VSCodeSetup.log' | Out-Null
Start-Sleep -Seconds 120

# Package Install Modern Web Browser (Google Chrome 64bit)
Log "# Package Install Modern Web Browser (Google Chrome 64bit)"
Invoke-WebRequest -Uri 'https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi' -OutFile "$BASE_DIR\googlechrome.msi"
Start-Process -FilePath "$BASE_DIR\googlechrome.msi" -ArgumentList '/quiet /log C:\EC2-Bootstrap\Logs\ChromeSetup.log' | Out-Null
Start-Sleep -Seconds 120


#-----------------------------------------------------------------------------------------------------------------------
# Collect Logging Data Files
#-----------------------------------------------------------------------------------------------------------------------

# Stop Transcript Logging
Stop-Transcript

# Save Script Files
Copy-Item -Path "C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1" -Destination $BASE_DIR
Copy-Item -Path "$TEMP_DIR\*.ps1" -Destination $BASE_DIR

# Save Configuration Files
Copy-Item -Path $SysprepSettingsFile -Destination $BASE_DIR
Copy-Item -Path $EC2SettingsFile -Destination $BASE_DIR
Copy-Item -Path $CWLogsSettingsFile -Destination $BASE_DIR

# Save Logging Files
Copy-Item -Path $USERDATA_LOG -Destination $LOGS_DIR 
Copy-Item -Path "C:\Program Files\Amazon\Ec2ConfigService\Logs\Ec2ConfigLog.txt" -Destination $LOGS_DIR 
Copy-Item -Path "C:\ProgramData\Amazon\SSM\Logs\amazon-ssm-agent.log" -Destination $LOGS_DIR 
Copy-Item -Path "$TEMP_DIR\*.tmp" -Destination $LOGS_DIR 


#-----------------------------------------------------------------------------------------------------------------------
# Hostname rename & Instance Reboot
#-----------------------------------------------------------------------------------------------------------------------

# Setting Hostname
Rename-Computer $PrivateIp.Replace(".", "-") -Force

# EC2 Instance Reboot
Restart-Computer -Force
