<script>
tzutil.exe /g
tzutil.exe /s "Tokyo Standard Time"
tzutil.exe /g
</script>

<powershell>
# EC2-Bootstrap Start
$StartTime = Get-Date
Write-Output "#Execution Time taken[EC2-Bootstrap Start]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  

# Make Directory
Set-Variable -Name WorkingDirectoryPath -Value "C:\EC2-Bootstrap"
New-Item -ItemType Directory -Path $WorkingDirectoryPath -Force
Set-Location -Path $WorkingDirectoryPath

# Set AWS Instance MetaData
Set-Variable -Name AZ -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/placement/availability-zone)
Set-Variable -Name Region -Value (Invoke-RestMethod -Uri http://169.254.169.254/latest/dynamic/instance-identity/document).region
Set-Variable -Name InstanceId -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/instance-id)
Set-Variable -Name InstanceType -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/instance-type)
Set-Variable -Name PrivateIp -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/local-ipv4)
Set-Variable -Name AmiId -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/ami-id)

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
Get-Variable | Export-Csv -Encoding default $WorkingDirectoryPath\bootstrap-variable.csv


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

# Setting AWS Tools for Windows PowerShell
Set-DefaultAWSRegion -Region $Region
Get-DefaultAWSRegion

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

# Change Windows Update Policy
$AUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
$AUSettings.NotificationLevel         = 3      # Automatic Updates prompts users to approve updates & before downloading or installing
$AUSettings.ScheduledInstallationDay  = 1      # Every Sunday
$AUSettings.ScheduledInstallationTime = 3      # AM 3:00
$AUSettings.IncludeRecommendedUpdates = $True  # Enabled
$AUSettings.FeaturedUpdatesEnabled    = $True  # Enabled
$AUSettings.Save()

Start-Sleep -Seconds 5

# Enable Microsoft Update
$SMSettings = New-Object -ComObject Microsoft.Update.ServiceManager -Strict 
$SMSettings.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
$SMSettings.Services

Start-Sleep -Seconds 5

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

# Change System PowerPlan (High Performance)
$HighPowerBase64 = "6auY44OR44OV44Kp44O844Oe44Oz44K5"                       # A string of "high performance" was Base64 encoded in Japanese
$HighPowerByte = [System.Convert]::FromBase64String($HighPowerBase64)       # Conversion from base64 to byte sequence
$HighPowerString = [System.Text.Encoding]::UTF8.GetString($HighPowerByte)   # To convert a sequence of bytes into a string of UTF-8 encoding

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

Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Select-Object ElementName, IsActive | Format-Table -AutoSize

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

# Setting Hostname
Rename-Computer $InstanceId -Force


# Get AMI Information
Write-Output "# Get AMI Information"
Get-EC2Image -ImageId $AmiId | ConvertTo-Json

# Get EC2 Instance Information
Write-Output "# Get EC2 Instance Information"
Get-EC2Instance -Filter @{Name = "instance-id"; Values = $InstanceId} | ConvertTo-Json

# Get EC2 Instance attached EBS Volume Information
Write-Output "# Get EC2 Instance attached EBS Volume Information"
Get-EC2Volume | Where-Object { $_.Attachments.InstanceId -eq $InstanceId} | ConvertTo-Json

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
if ($InstanceType -match "^x1.*|^m4.16xlarge") {
    # Get EC2 Instance Attribute(Elastic Network Adapter Status)
    Write-Output "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
    Get-EC2Instance -Filter @{Name = "instance-id"; Values = $InstanceId} | Select-Object -ExpandProperty "Instances"
    #Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EnaSupport
} elseif ($InstanceType -match "^c3.*|^c4.*|^d2.*|^i2.*|^m4.*|^r3.*") {
    # Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
    Write-Output "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
    Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute sriovNetSupport
} else {
    Write-Output "Instance type of None [Network Interface Performance Attribute]"
}

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
if ($InstanceType -match "^c1.*|^c3.*|^c4.*|^d2.*|^g2.*|^i2.*|^m1.*|^m2.*|^m3.*|^m4.*|^r3.*") {
    # Get EC2 Instance Attribute(EBS-optimized instance Status)
    Write-Output "# Get EC2 Instance Attribute(EBS-optimized instance Status)"
    Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EbsOptimized
} else {
    Write-Output "Instance type of None [Storage Interface Performance Attribute]"
}



# Update Amazon Windows EC2Config Service from SSM-Agent
# $UpdateEC2ConfigCommand = Send-SSMCommand -InstanceId $InstanceId -DocumentName "AWS-UpdateEC2Config"
# Start-Sleep -Seconds 60
# Get-SSMCommandInvocation -CommandId $UpdateEC2ConfigCommand.CommandId -Details $true -InstanceId $InstanceId | select -ExpandProperty CommandPlugins

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


# Save Logging Data
Copy-Item "C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1" $WorkingDirectoryPath
Copy-Item "C:\Program Files\Amazon\Ec2ConfigService\Logs\Ec2ConfigLog.txt" $WorkingDirectoryPath
Copy-Item "C:\Windows\TEMP\*.tmp" $WorkingDirectoryPath

# Save Configuration Files
Copy-Item $SysprepSettingsFile $WorkingDirectoryPath
Copy-Item $EC2SettingsFile $WorkingDirectoryPath
Copy-Item $CWLogsSettingsFile $WorkingDirectoryPath

# Get Command History
# Get-History | Export-Csv -Encoding default $WorkingDirectoryPath\bootstrap-command-list1.csv
# Get-History | ConvertTo-Csv > $WorkingDirectoryPath\bootstrap-command-list2.csv
# Get-History | ConvertTo-Json > $WorkingDirectoryPath\bootstrap-command-list.json

# EC2-Bootstrap Complete
Write-Output "#Execution Time taken[EC2-Bootstrap Complete]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  

# EC2 Instance Reboot
Restart-Computer -Force
</powershell>
