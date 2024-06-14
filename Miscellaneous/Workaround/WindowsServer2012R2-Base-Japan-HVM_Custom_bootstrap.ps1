<powershell>

# Set TimeCounter
$StartTime = Get-Date

#-------------------------------------------------------------------------------
Write-Output "#1-0 Execution Time taken[WorkingDirectorySettings]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  

# Make Directory
Set-Variable -Name WorkingDirectoryPath -Value "C:\EC2-Bootstrap"
New-Item -ItemType Directory -Path $WorkingDirectoryPath -Force
Set-Location -Path $WorkingDirectoryPath

# Start Logging
# Start-Transcript -Append -Force -Path $WorkingDirectoryPath\bootstrap.log

Write-Output "#1-0 Execution Time taken[WorkingDirectorySettings]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  

#-------------------------------------------------------------------------------
Write-Output "#1-1 Execution Time taken[Initial parameters]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  

# Get Powershell execution policy
Write-Output "# Get Powershell execution policy"
Get-ExecutionPolicy

# Load Module (AWS Tools for Windows PowerShell)
Write-Output "# Load Module (AWS Tools for Windows PowerShell)"
Import-Module 'C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.psd1'
Get-Module -Name AWSPowerShell
Get-AWSPowerShellVersion -ListServices | Export-Csv -Encoding default $WorkingDirectoryPath\AWSPowerShell-ListServices.csv

# Get PowerShell Version
Write-Output "# Get PowerShell Version"
$PSVersionTable

# Get Windows Environment Variables
Write-Output "# Get Windows Environment Variables"
Get-ChildItem env: | Export-Csv -Encoding default $WorkingDirectoryPath\windows-environment-variable.csv

# Get Windows Update agent Version
(Get-ItemProperty C:\Windows\System32\wuaueng.dll).VersionInfo.FileVersion

# Set AWS Instance MetaData
Set-Variable -Name AZ -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/placement/availability-zone)
Set-Variable -Name Region -Value (Invoke-RestMethod -Uri http://169.254.169.254/latest/dynamic/instance-identity/document).region
Set-Variable -Name InstanceId -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/instance-id)
Set-Variable -Name InstanceType -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/instance-type)
Set-Variable -Name PrivateIp -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/local-ipv4)

Set-Variable -Name RoleArn -Value ((Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/iam/info").Content | ConvertFrom-Json).InstanceProfileArn
Set-Variable -Name RoleName -Value ($RoleArn -split "/" | select -Index 1)

Set-Variable -Name StsCredential -Value ((Invoke-WebRequest -Uri ("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + $RoleName)).Content | ConvertFrom-Json)
Set-Variable -Name StsAccessKeyId -Value $StsCredential.AccessKeyId
Set-Variable -Name StsSecretAccessKey -Value $StsCredential.SecretAccessKey
Set-Variable -Name StsToken -Value $StsCredential.Token

# Set Setting File
Set-Variable -Name SysprepSettingsFile -Value "C:\Program Files\Amazon\Ec2ConfigService\sysprep2008.xml"
Set-Variable -Name EC2SettingsFile -Value "C:\Program Files\Amazon\Ec2ConfigService\Settings\Config.xml"
Set-Variable -Name CWLogsSettingsFile -Value "C:\Program Files\Amazon\Ec2ConfigService\Settings\AWS.EC2.Windows.CloudWatch.json"

# Get System & User Variables
Write-Output "# Get System & User Variables"
Get-Variable | Export-Csv -Encoding default $WorkingDirectoryPath\bootstrap-variable.csv

# Test of administrative privileges
Set-Variable -Name CheckAdministrator -Value (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

if ($CheckAdministrator -eq $true){
    Write-Output "[Infomation] UserData scripts run with the privileges of the administrator"
} else {
    Write-Output "[Warning] UserData scripts run with the privileges of the non-administrator"
}

# Test Connecting to the Internet (Google Public DNS:8.8.8.8)
While (-Not (Test-Connection -ComputerName 8.8.8.8 -Count 1 -ErrorAction SilentlyContinue))
{
    Start-Sleep -Seconds 5
}


#-------------------------------------------------------------------------------
Write-Output "#1-2 Execution Time taken[SystemSettings]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  

# Setting Timezone
tzutil.exe /g
tzutil.exe /s "Tokyo Standard Time"
tzutil.exe /g


# Setting SystemLocale
Set-WinSystemLocale -SystemLocale ja-JP
Get-WinSystemLocale

Set-WinHomeLocation -GeoId 0x7A
Get-WinHomeLocation

Set-WinCultureFromLanguageListOptOut -OptOut $False
Get-WinCultureFromLanguageListOptOut


# Setting Japanese UI
Set-WinUILanguageOverride ja-JP
Get-WinUILanguageOverride


# Update PowerShell Helper
Update-Help -UICulture en-US -Force


# Setting AWS Tools for Windows PowerShell (Region Setting)
Set-DefaultAWSRegion -Region $Region
Get-DefaultAWSRegion


# Enable EC2config EventLog Output
Write-Output "# Before EC2config Settings File"
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

Write-Output "# After EC2config Settings File"
Get-Content $EC2SettingsFile


# Change Windows Update Policy (from Microsoft.Update.AutoUpdate Object & PowerShell registry Edit)
Write-Host "# Change Windows Update Policy (from Microsoft.Update.AutoUpdate Object & PowerShell registry Edit)"

Set-Variable -Name RegistryWindowsUpdate -Value "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
Set-Variable -Name RegistryMicrosoftUpdate -Value "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RequestedAppCategories\7971f918-a847-4430-9279-4a52d1efe18d"

Get-ChildItem -Path $RegistryWindowsUpdate -Recurse | ConvertTo-Json > $WorkingDirectoryPath\WindowsUpdate-Policy_Before.json

$AUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
$AUSettings.NotificationLevel         = 3      # Automatic Updates prompts users to approve updates & before downloading or installing
$AUSettings.ScheduledInstallationDay  = 1      # Every Sunday
$AUSettings.ScheduledInstallationTime = 3      # AM 3:00
$AUSettings.IncludeRecommendedUpdates = $True  # Enabled
$AUSettings.FeaturedUpdatesEnabled    = $True  # Enabled
$AUSettings.Save()
Start-Sleep -Seconds 5

# New-Item -Path $RegistryMicrosoftUpdate
# New-ItemProperty -Path $RegistryMicrosoftUpdate -name 'RegisteredWithAU' -value '1' -propertyType "DWord" -force
# Start-Sleep -Seconds 3

Get-ChildItem -Path $RegistryWindowsUpdate -Recurse | ConvertTo-Json > $WorkingDirectoryPath\WindowsUpdate-Policy_After.json


# Change Windows Folder Option Policy (from PowerShell registry Edit)
Write-Host "# Change Windows Folder Option Policy (from PowerShell registry Edit)"

Set-Variable -Name RegistryFolderOption -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

Get-ChildItem -Path $RegistryFolderOption -Recurse | ConvertTo-Json > $WorkingDirectoryPath\WindowsFolderOption-Policy_Before.json

Set-ItemProperty -Path $RegistryFolderOption -name 'Hidden' -value '1' -force                                  # [Check] Show hidden files, folders, or drives
Set-ItemProperty -Path $RegistryFolderOption -name 'HideFileExt' -value '0' -force                             # [UnCheck] Hide extensions for known file types
New-ItemProperty -Path $RegistryFolderOption -name 'PersistBrowsers' -value '1' -propertyType "DWord" -force   # [Check] Restore previous folders windows

Get-ChildItem -Path $RegistryFolderOption -Recurse | ConvertTo-Json > $WorkingDirectoryPath\WindowsFolderOption-Policy_After.json


# Change Display Desktop Icon Policy (from PowerShell registry Edit)
Write-Host "# Change Display Desktop Icon Policy (from PowerShell registry Edit)"

Set-Variable -Name RegistryDesktopIcon -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
Set-Variable -Name RegistryDesktopIconSetting -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"

New-Item -Path $RegistryDesktopIcon
New-Item -Path $RegistryDesktopIconSetting

New-ItemProperty -Path $RegistryDesktopIconSetting -name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -value '0' -propertyType "DWord" -force  #[CLSID] : My Computer
New-ItemProperty -Path $RegistryDesktopIconSetting -name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -value '0' -propertyType "DWord" -force  #[CLSID] : Control Panel
New-ItemProperty -Path $RegistryDesktopIconSetting -name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -value '0' -propertyType "DWord" -force  #[CLSID] : User's Files
New-ItemProperty -Path $RegistryDesktopIconSetting -name '{645FF040-5081-101B-9F08-00AA002F954E}' -value '0' -propertyType "DWord" -force  #[CLSID] : Recycle Bin
New-ItemProperty -Path $RegistryDesktopIconSetting -name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -value '0' -propertyType "DWord" -force  #[CLSID] : Network

Get-ChildItem -Path $RegistryDesktopIcon -Recurse | ConvertTo-Json > $WorkingDirectoryPath\DisplayDesktopIcon-Policy_After.json


# Change System PowerPlan (High Performance)
$HighPowerBase64 = "6auY44OR44OV44Kp44O844Oe44Oz44K5"                        # A string of "high performance" was Base64 encoded in Japanese
$HighPowerByte = [System.Convert]::FromBase64String( $HighPowerBase64 )      # Conversion from base64 to byte sequence
$HighPowerString = [System.Text.Encoding]::UTF8.GetString( $HighPowerByte )  # To convert a sequence of bytes into a string of UTF-8 encoding

Write-Output "# Before Windows System Power Plan Information"
Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Select-Object ElementName, IsActive | Format-Table -AutoSize

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

Write-Output "# After Windows System Power Plan Information"
Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Select-Object ElementName, IsActive | Format-Table -AutoSize


# Disable IPv6 Binding
Get-NetAdapterBinding

if (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "Intel(R) 82599 Virtual Function" }) {
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


# Setting Hostname
Rename-Computer $InstanceId -Force


#-------------------------------------------------------------------------------
Write-Output "#1-3 Execution Time taken[EC2 Instance Parameters]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  

# Get EC2 Instance Information
(Get-EC2Instance -Instance $InstanceId).RunningInstance[0]

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
if ($InstanceType -match "^x1.*") {
    # Get EC2 Instance Attribute(Elastic Network Adapter Status)
    Write-Output "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
    Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EnaSupport
    Start-Sleep -Seconds 3
} elseif ($InstanceType -match "^c3.*|^c4.*|^d2.*|^i2.*|^m4.*|^r3.*") {
    # Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
    Write-Output "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
    Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute sriovNetSupport
    Start-Sleep -Seconds 3
} else {
    Write-Output "Instance type of None [Network Interface Performance Attribute]"
}

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
if ($InstanceType -match "^c1.*|^c3.*|^c4.*|^d2.*|^g2.*|^i2.*|^m1.*|^m2.*|^m3.*|^m4.*|^r3.*") {
    # Get EC2 Instance Attribute(EBS-optimized instance Status)
    Write-Output "# Get EC2 Instance Attribute(EBS-optimized instance Status)"
    Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EbsOptimized
    Start-Sleep -Seconds 3
} else {
    Write-Output "Instance type of None [Storage Interface Performance Attribute]"
}


#-------------------------------------------------------------------------------
Write-Output "#1-4 Execution Time taken[EC2 Instance Configuratons]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  

# Update Amazon Windows EC2Config Service from SSM-Agent
$UpdateEC2ConfigCommand = Send-SSMCommand -InstanceId $InstanceId -DocumentName "AWS-UpdateEC2Config"
Start-Sleep -Seconds 60
Get-SSMCommandInvocation -CommandId $UpdateEC2ConfigCommand.CommandId -Details $true -InstanceId $InstanceId | select -ExpandProperty CommandPlugins


# Configure Windows Update Policy(Disable Windows automatic update) from SSM-Agent
# $configureWindowsUpdateCommand = Send-SSMCommand -InstanceId $InstanceId -DocumentName 'AWS-ConfigureWindowsUpdate' -Parameters @{'updateLevel'='NeverCheckForUpdates'}
# Start-Sleep -Seconds 30
# Get-SSMCommandInvocation -Details $true -CommandId $configureWindowsUpdateCommand.CommandId | select -ExpandProperty CommandPlugins



# Update Intel NIC Driverfrom SSM-Agent
# (https://downloadcenter.intel.com/ja/download/23073/)
 Set-Variable -Name IntelNicDriverUrl -Value ("https://downloadmirror.intel.com/23073/eng/PROWinx64.exe")
# $installIntelNicDriver = Send-SSMCommand -InstanceId $InstanceId -DocumentName AWS-InstallApplication -Parameter @{'source'=$IntelNicDriverUrl; 'parameters'='/norestart /quiet /log C:\EC2-Bootstrap\InstallLog-IntelNicDriver.txt'}
# Start-Sleep -Seconds 60
# Get-SSMCommandInvocation -Details $true -CommandId $installIntelNicDriver.CommandId | select -ExpandProperty CommandPlugins


# Install AWS CLI from SSM-Agent
# AWS-CLI (https://aws.amazon.com/jp/cli/)
Set-Variable -Name AwsCliUrl -Value ("https://s3.amazonaws.com/aws-cli/AWSCLI64.msi")
# $installAwsCli = Send-SSMCommand -InstanceId $InstanceId -DocumentName AWS-InstallApplication -Parameter @{'source'=AwsCliUrl; 'parameters'='/norestart /quiet /log C:\EC2-Bootstrap\InstallLog-AWS-CLI.txt'}
# Start-Sleep -Seconds 30
# Get-SSMCommandInvocation -Details $true -CommandId $installAwsCli.CommandId | select -ExpandProperty CommandPlugins


# Install AWS CodeDeploy Agent from SSM-Agent
# AWS CodeDeploy Agent (http://docs.aws.amazon.com/codedeploy/latest/userguide/how-to-run-agent.html#how-to-run-agent-install-windows)
Set-Variable -Name CodeDeployAgentUrl -Value ("https://aws-codedeploy-" + $Region + ".s3-" +  $Region + ".amazonaws.com/latest/codedeploy-agent.msi")
# $installAwsCodeDeployAgent = Send-SSMCommand -InstanceId $InstanceId -DocumentName AWS-InstallApplication -Parameter @{'source'=$CodeDeployAgentUrl; 'parameters'='/norestart /quiet /log C:\EC2-Bootstrap\InstallLog-AWS-CodeDeploy-Agent.txt'}
# Start-Sleep -Seconds 60
# Get-SSMCommandInvocation -Details $true -CommandId $installAwsCodeDeployAgent.CommandId | select -ExpandProperty CommandPlugins
# Get-Service -Name codedeployagent


# Install Amazon Inspector Agent from SSM-Agent
# Amazon Inspector (https://docs.aws.amazon.com/inspector/latest/userguide/inspector_working-with-agents.html#inspector-agent-windows)
Set-Variable -Name InspectorAgentUrl -Value ("https://d1wk0tztpsntt1.cloudfront.net/windows/installer/latest/AWSAgentInstall.exe")
# $installAwsInspectorAgent = Send-SSMCommand -InstanceId $InstanceId -DocumentName AWS-InstallApplication -Parameter @{'source'=$InspectorAgentUrl; 'parameters'='/install /norestart /quiet /log C:\EC2-Bootstrap\InstallLog-Amazon-Inspector-Agent.txt'}
# Start-Sleep -Seconds 60
# Get-SSMCommandInvocation -Details $true -CommandId $installAwsInspectorAgent.CommandId | select -ExpandProperty CommandPlugins
# Get-Service -Name AWSAgent
# Get-Service -Name AWSAgentUpdater
# cmd.exe /c "C:\Program Files\Amazon Web Services\Aws Agent\AWSAgentStatus.exe"



#-------------------------------------------------------------------------------
Write-Output "#9-0 Execution Time taken[Save Files]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  

# Save Logging Data
Copy-Item "C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1" $WorkingDirectoryPath
Copy-Item "C:\Program Files\Amazon\Ec2ConfigService\Logs\Ec2ConfigLog.txt" $WorkingDirectoryPath
Copy-Item "C:\Windows\TEMP\*.tmp" $WorkingDirectoryPath


# Save Configuration Files
Copy-Item $SysprepSettingsFile $WorkingDirectoryPath
Copy-Item $EC2SettingsFile $WorkingDirectoryPath
Copy-Item $CWLogsSettingsFile $WorkingDirectoryPath


#-------------------------------------------------------------------------------
Write-Output "#9-1 Execution Time taken[Logging]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  

# Stop Logging
# Stop-Transcript

# Get Command History
Get-History | ConvertTo-Csv | Out-File $WorkingDirectoryPath\bootstrap-command-list.csv
Get-History | ConvertTo-Json | Out-File $WorkingDirectoryPath\bootstrap-command-list.json


#-------------------------------------------------------------------------------
Write-Output "#9-2 Execution Time taken[Reboot]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  
Restart-Computer -Force

</powershell>

