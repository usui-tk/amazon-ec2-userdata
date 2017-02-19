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

function Format-Message
{
    param([string]$message)
    
    $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss.fffffff zzz"
    "$timestamp - $message"
} # end function Format-Message

function Write-Log
{
    param([string]$message, $log=$USERDATA_LOG)
    
    Format-Message $message | Out-File $log -Append -Force
} # end function Write-Log

function Write-Log-Separator
{
      param([string]$message)
      Write-Log "#-------------------------------------------------------------------------------"
      Write-Log ("#        Script Executetion Step : " + $message)
      Write-Log "#-------------------------------------------------------------------------------"
} # end function Write-Log-Separator

function Create-Directory
{
    param([string]$dir)

    if (!(Test-Path -Path $dir)) {
        Write-Log "# Creating directory : $dir"
        New-Item -Path $dir -ItemType Directory -Force
    }
} # end function Create-Directory

function Get-AMIInfo
{
    Set-Variable __AMIInfoKey -Option Constant -Scope Local -Value "HKLM:\SOFTWARE\Amazon\MachineImage"
    if (Test-Path $__AMIInfoKey) {
        $__AMIInfoRegistry = Get-ItemProperty -Path $__AMIInfoKey -ErrorAction SilentlyContinue
        $AMI_OriginalVersion = $__AMIInfoRegistry.AMIVersion
        $AMI_OriginalName = $__AMIInfoRegistry.AMIName

        # Write the information to the Log Files
        Write-Log "# [AMI] Windows - AMI Origin Version : $AMI_OriginalVersion"
        Write-Log "# [AMI] Windows - AMI Origin Name : $AMI_OriginalName"
    }
} # end function Get-AMIInfo

function Get-Ec2ConfigVersion
{
    # Get EC2Config Version
    $__EC2Config_Infomation = $(Get-WmiObject -Class Win32_Product | Select Name,Version | Where-Object { $_.Name -eq "EC2ConfigService" })
    $Ec2ConfigVersion = $__EC2Config_Infomation.Version

    # Write the information to the Log Files
    if ($Ec2ConfigVersion) {
        Write-Log "# [Windows] Amazon EC2Config Version : $Ec2ConfigVersion"
    }
} # end Get-Ec2ConfigVersion

function Get-Ec2LaunchVersion
{
    Set-Variable Ec2LaunchModuleConfig -Option Constant -Scope Local -Value "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"

    # Get EC2Launch Version from "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"
    if (Test-Path $Ec2LaunchModuleConfig) {
        $__EC2Launch_ModuleVersion = Select-String -Path $Ec2LaunchModuleConfig -Pattern "ModuleVersion"
        $Ec2LaunchVersion = $($__EC2Launch_ModuleVersion -match '(\d\.\d.\d)' | Out-Null; $Matches[1])

        # Write the information to the Log Files
        if ($Ec2LaunchVersion) {
            Write-Log "# [Windows] Amazon EC2Launch Version : $Ec2LaunchVersion"
        }
    }
} # end Get-Ec2LaunchVersion

function Get-SSMAgentVersion
{
    Set-Variable __SSMAgentInfoRegistry -Option Constant -Scope Local -Value "HKLM:\SYSTEM\CurrentControlSet\Services\AmazonSSMAgent"
    Set-Variable __SSMAgentUninstallRegistry -Option Constant -Scope Local -Value "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B1A3AC35-A431-4C8C-9D21-E2CA92047F76}"

    $SSM_AgentVersion = ""

    if (Test-Path $__SSMAgentInfoRegistry) {
        $__SSMAgentService = Get-ItemProperty -Path $__SSMAgentInfoRegistry -ErrorAction SilentlyContinue
        $SSM_AgentVersion = $__SSMAgentService.Version
    }

    if (-not $SSM_AgentVersion -and (Test-Path $__SSMAgentUninstallRegistry)) {
        $__SSMAgentService = Get-ItemProperty -Path $__SSMAgentUninstallRegistry -ErrorAction SilentlyContinue
        $SSM_AgentVersion = $__SSMAgentService.DisplayVersion
    }

    # Write the information to the Log Files
    if ($SSM_AgentVersion) {
        Write-Log "# [Windows] Amazon SSM Agent Version : $SSM_AgentVersion"
    }
} # end function Get-SSMAgentVersion

function Get-WindowsDriverInfo
{
    $win_drivers = Get-WindowsDriver -Online | Where-Object { $_.OriginalFileName -like '*xenvbd*' -or $_.ClassName -eq 'Net' -and `
         ($_.ProviderName -eq 'Amazon Inc.' -or $_.ProviderName -eq 'Citrix Systems, Inc.' -or $_.ProviderName -like 'Intel*' -or $_.ProviderName -eq 'Amazon Web Services, Inc.') }
    $pnp_drivers = Get-CimInstance -ClassName Win32_PnPEntity | Where-Object { $_.Service -eq 'xenvbd' -or `
         $_.Manufacturer -like 'Intel*' -or $_.Manufacturer -eq 'Citrix Systems, Inc.' -or $_.Manufacturer -eq 'Amazon Inc.' -or $_.Manufacturer -eq 'Amazon Web Services, Inc.' }
    
    foreach ($win_driver in $win_drivers)
    {
        foreach ($pnp_driver in $pnp_drivers)
        {
            if ($pnp_driver.Service -and $win_driver.OriginalFileName -like ("*{0}*" -f $pnp_driver.Service)) 
                {
                    # Write the information to the Log Files
                    Write-Log ("# [Windows] AWS Driver Information : {0} v{1} " -f $pnp_driver.Name, $win_driver.Version)
                }
        }
    }    
} # end function Get-WindowsDriverInfo

function Get-WindowsOSInfo
{
    #--------------------------------------------------------------------------------------
    # Windows Server OS Version Tables (Windows NT Version Tables)
    #--------------------------------------------------------------------------------------
    #   - Windows Server 2003    : 5.2
    #   - Windows Server 2003 R2 : 5.2
    #   - Windows Server 2008    : 6.0
    #   - Windows Server 2008 R2 : 6.1
    #   - Windows Server 2012    : 6.2
    #   - Windows Server 2012 R2 : 6.3
    #   - Windows Server 2016    : 10.0
    #--------------------------------------------------------------------------------------

    Set-Variable windowInfoKey -Option Constant -Scope Local -Value "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    Set-Variable fullServer -Option Constant -Scope Local -Value "Full"
    Set-Variable nanoServer -Option Constant -Scope Local -Value "Nano"
    Set-Variable serverCore -Option Constant -Scope Local -Value "Server Core"
    Set-Variable serverOptions -Option Constant -Scope Local -Value @{ 0 = "Undefined"; 12 = $serverCore; 13 = $serverCore;
        14 = $serverCore; 29 = $serverCore; 39 = $serverCore; 40 = $serverCore; 41 = $serverCore; 43 = $serverCore;
        44 = $serverCore; 45 = $serverCore; 46 = $serverCore; 63 = $serverCore; 143 = $nanoServer; 144 = $nanoServer;
        147 = $serverCore; 148 = $serverCore; }
    
    $productName = ""
    $installOption = ""
    $osVersion = ""
    $osBuildLabEx = ""


    # Get ProductName and BuildLabEx from HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    if (Test-Path $windowInfoKey) {
        $windowInfo = Get-ItemProperty -Path $windowInfoKey
        $productName = $windowInfo.ProductName
        $osBuildLabEx = $windowInfo.BuildLabEx

        if ($windowInfo.CurrentMajorVersionNumber -and $windowInfo.CurrentMinorVersionNumber) {
            $osVersion = ("{0}.{1}" -f $windowInfo.CurrentMajorVersionNumber, $windowInfo.CurrentMinorVersionNumber)
        }
    }

    # Get Version and SKU from Win32_OperatingSystem
    $osInfo = Get-CimInstance Win32_OperatingSystem | Select-Object Version, OperatingSystemSKU
    $osSkuNumber = [int]$osInfo.OperatingSystemSKU
    if (-not $osVersion -and $osInfo.Version) {
        $osVersionSplit = $osInfo.Version.Split(".")
        if ($osVersionSplit.Count -gt 1) {
            $osVersion = ("{0}.{1}" -f $osVersionSplit[0], $osVersionSplit[1])
        } elseif ($osVersionSplit.Count -eq 1) {
            $osVersion = ("{0}.0" -f $osVersionSplit[0])
        }
    }

    if ($serverOptions[$osSkuNumber]) {
        $installOption = $serverOptions[$osSkuNumber]
    } else {
        $installOption = $fullServer
    }

    # Write the information to the Log Files
    Write-Log ("# [Windows] Microsoft Windows NT version : {0}" -f $osVersion)
    Write-Log ("# [Windows] Windows Server OS Product Name : {0}" -f $productName)
    Write-Log ("# [Windows] Windows Server OS Install Option : {0}" -f $installOption)
    Write-Log ("# [Windows] Windows Server OS Version : {0}" -f $osVersion)
    Write-Log ("# [Windows] Windows Server Build Lab Ex : {0}" -f $osBuildLabEx)

    Write-Log ("# [Windows] Windows Server OS Language : {0}" -f ([CultureInfo]::CurrentCulture).IetfLanguageTag)
    Write-Log ("# [Windows] Windows Server OS TimeZone : {0}" -f ([TimeZoneInfo]::Local).StandardName)
    Write-Log ("# [Windows] Windows Server OS Offset : {0}" -f ([TimeZoneInfo]::Local).GetUtcOffset([DateTime]::Now))

} # end function Get-WindowsOSInfo

function Set-TimeZone
{
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

function Update-SysprepAnswerFile($SysprepAnswerFile)
{
    [xml] $__SysprepXMLDocument = Get-Content $SysprepAnswerFile -Encoding UTF8

    $__SysprepNamespace = New-Object System.Xml.XmlNamespaceManager($__SysprepXMLDocument.NameTable)
    $__SysprepNamespace.AddNamespace("u", $__SysprepXMLDocument.DocumentElement.NamespaceURI)

    $__SysprepSettings = $__SysprepXMLDocument.SelectSingleNode("//u:settings[@pass='oobeSystem']", $__SysprepNamespace)

    $__Sysprep_Node_International = $__SysprepSettings.SelectSingleNode("u:component[@name='Microsoft-Windows-International-Core']", $__SysprepNamespace)
    $__Sysprep_Node_Shell = $__SysprepSettings.SelectSingleNode("u:component[@name='Microsoft-Windows-Shell-Setup']", $__SysprepNamespace)

    $__Sysprep_Node_International.SystemLocale = "ja-JP"
    $__Sysprep_Node_International.UserLocale = "ja-JP"

    $__Sysprep_Node_Shell.TimeZone = "Tokyo Standard Time"

    $__SysprepXMLDocument.Save($SysprepAnswerFile)
} # end function Update-SysprepAnswerFile


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
Create-Directory $TOOL_DIR
Create-Directory $LOGS_DIR

Start-Transcript -Path "$TRANSCRIPT_LOG" -Append -Force

Set-Variable -Name ScriptFullPath -Value $MyInvocation.InvocationName
Write-Log "# Script Execution 3rd-Bootstrap Script [START] : $ScriptFullPath"

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


#-----------------------------------------------------------------------------------------------------------------------
# Logging Amazon EC2 System & Windows Server OS Parameter
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-Log-Separator "Logging Amazon EC2 System & Windows Server OS Parameter"

# Logging AWS Instance Metadata
Write-Log "# [AWS] Region : $Region"
Write-Log "# [AWS] Availability Zone : $AZ"
Write-Log "# [AWS] Instance ID : $InstanceId"
Write-Log "# [AWS] Instance Type : $InstanceType"
Write-Log "# [AWS] VPC Private IP Address : $PrivateIp"
Write-Log "# [AWS] Amazon Machine Images ID : $AmiId"
Write-Log "# [AWS] EC2 - Instance Profile ARN : $RoleArn"
Write-Log "# [AWS] EC2 - IAM Role Name : $RoleName"

# Logging Windows Server OS Parameter [AMI]
Get-AMIInfo

# Logging Windows Server OS Parameter [Windows OS Information]
Get-WindowsOSInfo

# Logging Windows Server OS Parameter [Windows OS Driver Information]
Get-WindowsDriverInfo

# Logging Windows Server OS Parameter [EC2 Bootstrap Application Information]
if ($osVersion) {
    if ($osVersion -match "^5.*|^6.*") {
        Get-Ec2ConfigVersion
    } elseif ($InstanceType -match "^10.0") {
        Get-Ec2LaunchVersion
    } else {
        Write-Log "# No Target EC2 Bootstrap Applicaiton"
    }
}

# Logging Windows Server OS Parameter [EC2 System Manager (SSM) Agent Information]
Get-SSMAgentVersion


#-----------------------------------------------------------------------------------------------------------------------
# Amazon EC2 Information [AMI & Instance & EBS Volume]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-Log-Separator "Amazon EC2 Information [AMI & Instance & EBS Volume]"

# Setting AWS Tools for Windows PowerShell
Set-DefaultAWSRegion -Region $Region
$__DefaultAWSRegion = Get-DefaultAWSRegion
Write-Log "# Display Default Region at AWS Tools for Windows Powershell : $__DefaultAWSRegion"

# Get AMI Information
if ($RoleName) {
    Write-Log "# Get AMI Information"
    Get-EC2Image -ImageId $AmiId | ConvertTo-Json
}

# Get EC2 Instance Information
if ($RoleName) {
    Write-Log "# Get EC2 Instance Information"
    Get-EC2Instance -Filter @{Name = "instance-id"; Values = $InstanceId} | ConvertTo-Json
}

# Get EC2 Instance attached EBS Volume Information
if ($RoleName) {
    Write-Log "# Get EC2 Instance attached EBS Volume Information"
    Get-EC2Volume | Where-Object { $_.Attachments.InstanceId -eq $InstanceId} | ConvertTo-Json
}

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
if ($RoleName) {
    if ($InstanceType -match "^x1.*|^p2.*|^r4.*|^m4.16xlarge") {
        # Get EC2 Instance Attribute(Elastic Network Adapter Status)
        Write-Log "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
        Get-EC2Instance -Filter @{Name = "instance-id"; Values = $InstanceId} | Select-Object -ExpandProperty "Instances"
        # Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EnaSupport
    } elseif ($InstanceType -match "^c3.*|^c4.*|^d2.*|^i2.*|^m4.*|^r3.*") {
        # Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
        Write-Log "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
        Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute sriovNetSupport
    } else {
        Write-Log "# Instance type of None [Network Interface Performance Attribute]"
    }
}

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
if ($RoleName) {
    if ($InstanceType -match "^c1.*|^c3.*|^c4.*|^d2.*|^g2.*|^i2.*|^m1.*|^m2.*|^m3.*|^m4.*|^p2.*|^r3.*|^r4.*|^x1.*") {
        # Get EC2 Instance Attribute(EBS-optimized instance Status)
        Write-Log "# Get EC2 Instance Attribute(EBS-optimized instance Status)"
        Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EbsOptimized
    } else {
        Write-Log "# Instance type of None [Storage Interface Performance Attribute]"
    }
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-Log-Separator "Windows Server OS Configuration"

# Setting System Locale
$__WinSystemLocale = Get-WinSystemLocale
Write-Log "# Display Windows System Locale [Before] : $__WinSystemLocale"
Set-WinSystemLocale -SystemLocale ja-JP
Write-Log "# Display Windows System Locale [After] : $__WinSystemLocale"

$__WinHomeLocation = Get-WinHomeLocation
Write-Log ("# Display Windows Home Location [Before] : " + $__WinHomeLocation.HomeLocation)
Set-WinHomeLocation -GeoId 0x7A
Write-Log ("# Display Windows Home Location [After] : " + $__WinHomeLocation.HomeLocation)

$__WinCultureFromLanguageListOptOut = Get-WinCultureFromLanguageListOptOut
Write-Log "# Make the date and time [format] the same as the display language [Before] : $__WinCultureFromLanguageListOptOut"
Set-WinCultureFromLanguageListOptOut -OptOut $False
Write-Log "# Make the date and time [format] the same as the display language [After] : $__WinCultureFromLanguageListOptOut"

# Setting Japanese UI Language
$__WinUILanguageOverride = Get-WinUILanguageOverride
Write-Log ("# Override display language [Before] : " + $__WinUILanguageOverride.DisplayName)
Set-WinUILanguageOverride -Language ja-JP
Write-Log ("# Override display language [After] : " + $__WinUILanguageOverride.DisplayName)

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
Get-Content $EC2ConfigFile

$__EC2ConfigXMLDocument = [xml](Get-Content $EC2ConfigFile)
$__EC2Config_Node_Ec2EventLog = $__EC2ConfigXMLDocument.SelectSingleNode("//Plugins/Plugin[Name='Ec2EventLog']/State")
$__EC2Config_Node_Ec2EventLog.'#text' = "Enabled"
$__EC2ConfigXMLDocument.Save($EC2ConfigFile)

Get-Content $EC2ConfigFile

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
    Write-Log "# Disable-NetAdapterBinding(IPv6) : Amazon Elastic Network Adapter"
    Disable-NetAdapterBinding -InterfaceDescription "Amazon Elastic Network Adapter" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "Intel(R) 82599 Virtual Function" }) {
    Write-Log "# Disable-NetAdapterBinding(IPv6) : Intel(R) 82599 Virtual Function"
    Disable-NetAdapterBinding -InterfaceDescription "Intel(R) 82599 Virtual Function" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "AWS PV Network Device #0" }) {
    Write-Log "# Disable-NetAdapterBinding(IPv6) : AWS PV Network Device"
    Disable-NetAdapterBinding -InterfaceDescription "AWS PV Network Device #0" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} else {
    Write-Log "# Disable-NetAdapterBinding(IPv6) : No Target Device"
}

Get-NetAdapterBinding

# Change System PowerPlan (High Performance)
$HighPowerBase64 = "6auY44OR44OV44Kp44O844Oe44Oz44K5"                       # A string of "high performance" was Base64 encoded in Japanese
$HighPowerByte = [System.Convert]::FromBase64String($HighPowerBase64)       # Conversion from base64 to byte sequence
$HighPowerString = [System.Text.Encoding]::UTF8.GetString($HighPowerByte)   # To convert a sequence of bytes into a string of UTF-8 encoding

Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Select-Object ElementName, IsActive, Description

if (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq $HighPowerString }) {
    Write-Log "# Change System PowerPlan : $HighPowerString"
    $HighPowerObject = Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq $HighPowerString }
    $HighPowerObject.Activate()
    Start-Sleep -Seconds 5
} elseif (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq "High performance" }) {
    Write-Log "# Change System PowerPlan : High performance"
    (Get-WmiObject -Name root\cimv2\power -Class Win32_PowerPlan -Filter 'ElementName = "High performance"').Activate()
    Start-Sleep -Seconds 5
} else {
    Write-Log "# Change System PowerPlan : No change"
}

Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Select-Object ElementName, IsActive, Description


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Update (Amazon EC2 Systems Manager Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-Log-Separator "Package Update System Utility (Amazon EC2 Systems Manager Agent)"

# Package Update System Utility (Amazon EC2 Systems Manager Agent)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/systems-manager-managedinstances.html#sysman-install-managed-win
Write-Log "# Package Download System Utility (Amazon EC2 Systems Manager Agent)"
$AmazonSSMAgentUrl = "https://amazon-ssm-" + ${Region} + ".s3.amazonaws.com/latest/windows_amd64/AmazonSSMAgentSetup.exe"
Invoke-WebRequest -Uri $AmazonSSMAgentUrl -OutFile "$TOOL_DIR\AmazonSSMAgentSetup.exe"

Get-SSMAgentVersion

Start-Process -FilePath "$TOOL_DIR\AmazonSSMAgentSetup.exe" -ArgumentList @('ALLOWEC2INSTALL=YES', '/install', '/norstart', '/log C:\EC2-Bootstrap\Logs\AmazonSSMAgentSetup.log', '/quiet') -Wait | Out-Null
Start-Sleep -Seconds 120

Get-Service -Name AmazonSSMAgent

$AmazonSSMAgentStatus = (Get-WmiObject Win32_Service -filter "Name='AmazonSSMAgent'").StartMode

if ($AmazonSSMAgentStatus -ne "Auto") {
    Write-Log "# Service Startup Type Change [AmazonSSMAgent] $AmazonSSMAgentStatus -> Auto"
    Set-Service -Name "AmazonSSMAgent" -StartupType Automatic
    Write-Log "# Service Startup Type Staus [AmazonSSMAgent] $AmazonSSMAgentStatus"
}

Get-SSMAgentVersion

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

# Log Separator
Write-Log-Separator "Custom Package Download (System Utility)"

# Package Download System Utility (Sysinternals Suite)
# https://technet.microsoft.com/ja-jp/sysinternals/bb842062.aspx
Write-Log "# Package Download System Utility (Sysinternals Suite)"
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SysinternalsSuite.zip' -OutFile "$TOOL_DIR\SysinternalsSuite.zip"

# Package Download System Utility (System Explorer)
# http://systemexplorer.net/
Write-Log "# Package Download System Utility (System Explorer)"
Invoke-WebRequest -Uri 'http://systemexplorer.net/download/SystemExplorerSetup.exe' -OutFile "$TOOL_DIR\SystemExplorerSetup.exe"

# Package Download System Utility (7-zip)
# http://www.7-zip.org/
Write-Log "# Package Download System Utility (7-zip)"
Invoke-WebRequest -Uri 'http://www.7-zip.org/a/7z1604-x64.exe' -OutFile "$TOOL_DIR\7z1604-x64.exe"

# Package Download System Utility (Wireshark)
# https://www.wireshark.org/download.html
Write-Log "# Package Download System Utility (Wireshark)"
Invoke-WebRequest -Uri 'https://1.as.dl.wireshark.org/win64/Wireshark-win64-2.2.4.exe' -OutFile "$TOOL_DIR\Wireshark-win64-2.2.4.exe"

# Package Download System Utility (Microsoft Message Analyzer)
# https://blogs.technet.microsoft.com/messageanalyzer/
Write-Log "# Package Download System Utility (Microsoft Message Analyzer)"
Invoke-WebRequest -Uri 'https://download.microsoft.com/download/2/8/3/283DE38A-5164-49DB-9883-9D1CC432174D/MessageAnalyzer64.msi' -OutFile "$TOOL_DIR\MessageAnalyzer64.msi"

# Package Download System Utility (AWS Directory Service PortTest Application)
# http://docs.aws.amazon.com/ja_jp/workspaces/latest/adminguide/connect_verification.html
Write-Log "# Package Download System Utility (AWS DirectoryServicePortTest Application)"
Invoke-WebRequest -Uri 'http://docs.aws.amazon.com/directoryservice/latest/admin-guide/samples/DirectoryServicePortTest.zip' -OutFile "$TOOL_DIR\DirectoryServicePortTest.zip"

# Package Download System Utility (EC2Config)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/UsingConfig_Install.html
if ($osVersion -match "^5.*|^6.*") {
    Write-Log "# Package Download System Utility (EC2Config)"
    Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Config/EC2Install.zip' -OutFile "$TOOL_DIR\EC2Install.zip"
}

# Package Download System Utility (EC2Launch)
# http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2launch.html
if ($osVersion -match "^10.0") {
    # Get EC2 Bootstrap Application[EC2Config] Information
    Write-Log "# Package Download System Utility (EC2Launch)"
    Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Launch/latest/EC2-Windows-Launch.zip' -OutFile "$TOOL_DIR\EC2-Windows-Launch.zip"
    Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Launch/latest/install.ps1' -OutFile "$TOOL_DIR\EC2-Windows-Launch-install.ps1"
}

# Package Download System Utility (AWS-CLI - 64bit)
# https://aws.amazon.com/jp/cli/
Write-Log "# Package Download System Utility (AWS-CLI - 64bit)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/aws-cli/AWSCLI64.msi' -OutFile "$TOOL_DIR\AWSCLI64.msi"

# Package Download System Utility (AWS Tools for Windows PowerShell)
# https://aws.amazon.com/jp/powershell/
Write-Log "# Package Download System Utility (AWS Tools for Windows PowerShell)"
Invoke-WebRequest -Uri 'http://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi' -OutFile "$TOOL_DIR\AWSToolsAndSDKForNet.msi"

# Package Download System Utility (AWS Diagnostics for Windows Server)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/Windows-Server-Diagnostics.html
Write-Log "# Package Download System Utility (AWS Diagnostics for Windows Server)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ec2-downloads-windows/AWSDiagnostics/AWSDiagnostics.zip' -OutFile "$TOOL_DIR\AWSDiagnostics.zip"

# Package Download System Utility (Amazon Inspector Agent)
# https://docs.aws.amazon.com/ja_jp/inspector/latest/userguide/inspector_working-with-agents.html#inspector-agent-windows
Write-Log "# Package Download System Utility (Amazon Inspector Agent)"
Invoke-WebRequest -Uri 'https://d1wk0tztpsntt1.cloudfront.net/windows/installer/latest/AWSAgentInstall.exe' -OutFile "$TOOL_DIR\AWSAgentInstall.exe"

# Package Download System Utility (AWS CodeDeploy agent)
# http://docs.aws.amazon.com/ja_jp/codedeploy/latest/userguide/how-to-run-agent-install.html#how-to-run-agent-install-windows
Write-Log "# Package Download System Utility (AWS CodeDeploy agent)"
$AWSCodeDeployAgentUrl = "https://aws-codedeploy-" + ${Region} + ".s3.amazonaws.com/latest/codedeploy-agent.msi"
Invoke-WebRequest -Uri $AWSCodeDeployAgentUrl -OutFile "$TOOL_DIR\codedeploy-agent.msi"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Monitoring Service Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-Log-Separator "Custom Package Download (Monitoring Service Agent)"

# Package Download Monitoring Service Agent (Zabix Agent)
# http://www.zabbix.com/download
Write-Log "# Package Download Monitoring Service Agent (Zabix Agent)"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/2.2.14/zabbix_agents_2.2.14.win.zip' -OutFile "$TOOL_DIR\zabbix_agents_2.2.14.win.zip"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/3.0.4/zabbix_agents_3.0.4.win.zip' -OutFile "$TOOL_DIR\zabbix_agents_3.0.4.win.zip"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/3.2.0/zabbix_agents_3.2.0.win.zip' -OutFile "$TOOL_DIR\zabbix_agents_3.2.0.win.zip"

# Package Download Monitoring Service Agent (Datadog Agent)
# http://docs.datadoghq.com/ja/guides/basic_agent_usage/windows/
Write-Log "# Package Download Monitoring Service Agent (Datadog Agent)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ddagent-windows-stable/ddagent-cli.msi' -OutFile "$TOOL_DIR\ddagent-cli.msi"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Security Service Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-Log-Separator "Custom Package Download (Security Service Agent)"

# Package Download Security Service Agent (Deep Security Agent)
# http://esupport.trendmicro.com/ja-jp/enterprise/dsaas/top.aspx
Write-Log "# Package Download Security Service Agent (Deep Security Agent)"
Invoke-WebRequest -Uri 'https://app.deepsecurity.trendmicro.com/software/agent/Windows/x86_64/agent.msi' -OutFile "$TOOL_DIR\DSA-Windows-Agent_x86-64.msi"

# Package Download Security Service Agent (Alert Logic Universal Agent)
# https://docs.alertlogic.com/requirements/system-requirements.htm#reqsAgent
Write-Log "# Package Download Security Service Agent (Alert Logic Universal Agent)"
Invoke-WebRequest -Uri 'https://scc.alertlogic.net/software/al_agent-LATEST.msi' -OutFile "$TOOL_DIR\al_agent-LATEST.msi"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (NVIDIA GPU Driver & CUDA Toolkit)
#-----------------------------------------------------------------------------------------------------------------------

#=======================================================================================================================
# NVIDIA API Lookup
#=======================================================================================================================
#
# Request Format:
#  http://www.nvidia.com/Download/processDriver.aspx?psid=[value]&pfid=[value]&osid=[value]&lid=[value]&lang=ru
#   psid - Index Series
#   pfid - index of the family
#   osid - index OS
#   lid  - the index language
#
# Steps:
#  Find the ID type of products from xml-specification at:
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1
#  Substitute the value found in the "ParentID" query on xml-specification product line at:
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=[value]
#    Obtain "psid".
#  Substitute the value "psid" in "ParentID" query on xml-specification product family at:
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=[value]
#    Obtain "pfid"
#  Find the ID of the operating system from the xml-spec at:
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=4
#    Obtain "osid".
#  Find a language identifier of the xml-spec at:
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=5
#    Obtain the "lid".
#
#=======================================================================================================================
#
#  NVIDIA GRID K520 GPU Parameter
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1
#    -> GRID : 9
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=9
#    -> [psid] GRID Series : 94
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=94
#    -> [pfid] GRID K520 : 704
#
#=======================================================================================================================
#
#  NVIDIA Tesla K80
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1
#    -> Tesla : 7
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=7
#    -> [psid] K-Series : 91
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=91
#    -> [pfid] Tesla K80 : 762
#
#=======================================================================================================================
#
#  Windows Server OS [osid]
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=4
#    -> Windows Server 2003       : 15
#    -> Windows Server 2003 x64   : 8
#    -> Windows Server 2008       : 16
#    -> Windows Server 2008 x64   : 17
#    -> Windows Server 2008 R2 64 : 21
#    -> Windows Server 2012       : 32
#    -> Windows Server 2012 R2 64 : 44
#    -> Windows Server 2016       : 74
#
#=======================================================================================================================
#
#  Language Identifier [lid]
#   http://www.nvidia.ru/Download/API/lookupValueSearch.aspx?TypeID=5
#    -> English (US) : 1
#    -> Japanese     : 7
#
#=======================================================================================================================

# Log Separator
Write-Log-Separator "Custom Package Download (NVIDIA GPU Driver & CUDA Toolkit)"

# Package Download NVIDIA Tesla K80 GPU Driver (for EC2 P2 Instance Family)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/accelerated-computing-instances.html
if ($InstanceType -match "^p2.*") {
    Write-Log "# Package Download NVIDIA Tesla K80 GPU Driver (for EC2 P2 Instance Family)"
    if ($osVersion) {
        if ($osVersion -match "^6.1") {
            # [Windows Server 2008 R2]
            $K80_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=91&pfid=762&osid=21&lid=1&whql=1&lang=en-us&ctk=0'
            $K80_driverversion = $($K80_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K80_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K80_driverversion} + "/" + ${K80_driverversion} + "-tesla-desktop-winserver2008-2012r2-64bit-international-whql.exe"
            Invoke-WebRequest -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2008R2.exe"
        } elseif ($osVersion -match "^6.3") {
            # [Windows Server 2012 R2]
            $K80_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=91&pfid=762&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $K80_driverversion = $($K80_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K80_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K80_driverversion} + "/" + ${K80_driverversion} + "-tesla-desktop-winserver2008-2012r2-64bit-international-whql.exe"
            Invoke-WebRequest -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2012R2.exe"
        } elseif ($osVersion -match "^10.0") {
            # [Windows Server 2016]
            $K80_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=91&pfid=762&osid=74&lid=1&whql=1&lang=en-us&ctk=0'
            $K80_driverversion = $($K80_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K80_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K80_driverversion} + "/" + ${K80_driverversion} + "-tesla-desktop-winserver2016-international-whql.exe"
            Invoke-WebRequest -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2016.exe"
        } else {
            # [No Target Server OS]
            Write-Log ("# [NVIDIA Tesla K80 GPU Driver] No Target Server OS Version : " + $osVersion)
        }
    } else {
        # [Undefined Server OS]
        Write-Log "# [NVIDIA Tesla K80 GPU Driver] Undefined Server OS"
    }
}


# Package Download NVIDIA GRID K520 GPU Driver (for EC2 G2 Instance Family)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/accelerated-computing-instances.html
if ($InstanceType -match "^g2.*") {
    Write-Log "# Package Download NVIDIA GRID K520 GPU Driver (for EC2 G2 Instance Family)"
    if ($osVersion) {
        if ($osVersion -match "^6.1") {
            # [Windows Server 2008 R2]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=21&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">R.*\((.*)\)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "-quadro-tesla-grid-winserv2008-2008r2-2012-64bit-international-whql.exe"
            Invoke-WebRequest -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2008R2.exe"
        } elseif ($osVersion -match "^6.2") {
            # [Windows Server 2012]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=32&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">R.*\((.*)\)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "-quadro-tesla-grid-winserv2008-2008r2-2012-64bit-international-whql.exe"
            Invoke-WebRequest -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2012.exe"
        } elseif ($osVersion -match "^6.3") {
            # [Windows Server 2012 R2]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">R.*\((.*)\)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "-quadro-tesla-grid-winserv2008-2008r2-2012-64bit-international-whql.exe"
            Invoke-WebRequest -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2012R2.exe"
        } else {
            # [No Target Server OS]
            Write-Log ("# [NVIDIA GRID K520 GPU Driver] No Target Server OS Version : " + $osVersion)
        }
    } else {
        # [Undefined Server OS]
        Write-Log "# [NVIDIA GRID K520 GPU Driver] Undefined Server OS"
    }
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Storage & Network Driver)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-Log-Separator "Custom Package Download (Storage & Network Driver)"

# Package Download Amazon Windows Paravirtual Drivers
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/xen-drivers-overview.html
Write-Log "# Package Download Amazon Windows Paravirtual Drivers"
Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/Drivers/AWSPVDriverSetup.zip' -OutFile "$TOOL_DIR\AWSPVDriverSetup.zip"

# Package Download Intel Network Driver
if ($osVersion) {
    if ($osVersion -match "^6.1") {
        # [Windows Server 2008 R2]
        # https://downloadcenter.intel.com/ja/download/18725/
        # Package Download Intel Network Driver (Windows Server 2008 R2)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2008 R2)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/18725/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"
    } elseif ($osVersion -match "^6.2") {
        # [Windows Server 2012]
        # https://downloadcenter.intel.com/ja/download/21694/
        # Package Download Intel Network Driver (Windows Server 2012)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2012)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/21694/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"
    } elseif ($osVersion -match "^6.3") {
        # [Windows Server 2012 R2]
        # https://downloadcenter.intel.com/ja/download/23073/
        # Package Download Intel Network Driver (Windows Server 2012 R2)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2012 R2)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/23073/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"
    } elseif ($osVersion -match "^10.0") {
        # [Windows Server 2016]
        # https://downloadcenter.intel.com/ja/download/26092/
        # Package Download Intel Network Driver (Windows Server 2016)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2016)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/26092/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"
    } else {
        # [No Target Server OS]
        Write-Log ("# [Intel Network Driver] No Target Server OS Version : " + $osVersion)
    }
} else {
    # [Undefined Server OS]
    Write-Log "# [Intel Network Driver] Undefined Server OS"
}

# Package Download Amazon Elastic Network Adapter Driver
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/enhanced-networking-ena.html
Write-Log "# Package Download Amazon Elastic Network Adapter Driver"
Invoke-WebRequest -Uri 'http://ec2-windows-drivers.s3.amazonaws.com/ENA.zip' -OutFile "$TOOL_DIR\ENA.zip"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Installation (Application)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-Log-Separator "Custom Package Installation (Application)"

# Package Install Modern Web Browser (Google Chrome 64bit)
Write-Log "# Package Install Modern Web Browser (Google Chrome 64bit)"
Invoke-WebRequest -Uri 'https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi' -OutFile "$TOOL_DIR\googlechrome.msi"
Start-Process -FilePath "$TOOL_DIR\googlechrome.msi" -ArgumentList @("/quiet", "/log C:\EC2-Bootstrap\Logs\ChromeSetup.log") -Wait | Out-Null

# Package Install Text Editor (Visual Studio Code)
Write-Log "# Package Install Text Editor (Visual Studio Code)"
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?LinkID=623230' -OutFile "$TOOL_DIR\VSCodeSetup-stable.exe"
Start-Process -FilePath "$TOOL_DIR\VSCodeSetup-stable.exe" -ArgumentList @("/verysilent", "/suppressmsgboxes", "/LOG=C:\EC2-Bootstrap\Logs\VSCodeSetup.log") | Out-Null
Start-Sleep -Seconds 120


#-----------------------------------------------------------------------------------------------------------------------
# Collect Logging Data Files
#-----------------------------------------------------------------------------------------------------------------------

# Stop Transcript Logging
Stop-Transcript

Write-Log "# Script Execution 3rd-Bootstrap Script [COMPLETE] : $ScriptFullPath"

# Save Script Files
Copy-Item -Path "C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1" -Destination $BASE_DIR
Copy-Item -Path "$TEMP_DIR\*.ps1" -Destination $BASE_DIR

# Save Configuration Files
Copy-Item -Path $SysprepFile -Destination $BASE_DIR
Copy-Item -Path $EC2ConfigFile -Destination $BASE_DIR
Copy-Item -Path $CWLogsFile -Destination $BASE_DIR

# Save Logging Files
Copy-Item -Path $USERDATA_LOG -Destination $LOGS_DIR 
Copy-Item -Path "C:\Program Files\Amazon\Ec2ConfigService\Logs\Ec2ConfigLog.txt" -Destination $LOGS_DIR 
Copy-Item -Path $SSMAgentLogFile -Destination $LOGS_DIR 
Copy-Item -Path "$TEMP_DIR\*.tmp" -Destination $LOGS_DIR 


#-----------------------------------------------------------------------------------------------------------------------
# Hostname rename & Instance Reboot
#-----------------------------------------------------------------------------------------------------------------------

# Setting Hostname
Rename-Computer $PrivateIp.Replace(".", "-") -Force

# EC2 Instance Reboot
Restart-Computer -Force
