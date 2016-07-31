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
Set-Variable -Name WorkDir -Value "C:\EC2-Bootstrap"
New-Item -ItemType Directory -Path $WorkDir -Force
Set-Location -Path $WorkDir

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
Get-Variable | Export-Csv -Encoding default $WorkDir\bootstrap-variable.csv


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

# Change Windows Update Policy (WUP)
$WUP = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings
$WUP.NotificationLevel         = 3      # Automatic Updates prompts users to approve updates & before downloading or installing
$WUP.ScheduledInstallationDay  = 1      # Every Sunday
$WUP.ScheduledInstallationTime = 3      # AM 3:00
$WUP.IncludeRecommendedUpdates = $True  # Enabled
$WUP.FeaturedUpdatesEnabled    = $True  # Enabled
$WUP.Save()

Start-Sleep -Seconds 5

# Enable Microsoft Update Service (MUS)
$MUS = New-Object -ComObject Microsoft.Update.ServiceManager -Strict 
$MUS.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
$MUS.Services

Start-Sleep -Seconds 5

# Change Windows Folder Option(FO) Policy
Set-Variable -Name HKCU-FO -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

Set-ItemProperty -Path $HKCU-FO -name 'Hidden' -value '1' -force                                  # [Check] Show hidden files, folders, or drives
Set-ItemProperty -Path $HKCU-FO -name 'HideFileExt' -value '0' -force                             # [UnCheck] Hide extensions for known file types
New-ItemProperty -Path $HKCU-FO -name 'PersistBrowsers' -value '1' -propertyType "DWord" -force   # [Check] Restore previous folders windows

# Change Display Desktop Icon(DI) Policy
Set-Variable -Name HKCU-DI -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
Set-Variable -Name HKCU-DIS -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"

New-Item -Path $HKCU-DI
New-Item -Path $HKCU-DIS

New-ItemProperty -Path $HKCU-DIS -name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -value '0' -propertyType "DWord" -force  #[CLSID] : My Computer
New-ItemProperty -Path $HKCU-DIS -name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -value '0' -propertyType "DWord" -force  #[CLSID] : Control Panel
New-ItemProperty -Path $HKCU-DIS -name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -value '0' -propertyType "DWord" -force  #[CLSID] : User's Files
New-ItemProperty -Path $HKCU-DIS -name '{645FF040-5081-101B-9F08-00AA002F954E}' -value '0' -propertyType "DWord" -force  #[CLSID] : Recycle Bin
New-ItemProperty -Path $HKCU-DIS -name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -value '0' -propertyType "DWord" -force  #[CLSID] : Network

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



# Get EC2 Instance Information
Write-Output "# Get EC2 Instance Information"
Get-EC2Instance -Filter @{Name = "instance-id"; Values = $InstanceId} | ConvertTo-Json

# Get EC2 Instance attached EBS Volume Information
Write-Output "# Get EC2 Instance attached EBS Volume Information"
Get-EC2Volume | Where-Object { $_.Attachments.InstanceId -eq $InstanceId} | ConvertTo-Json

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
if ($InstanceType -match "^x1.*") {
    # Get EC2 Instance Attribute(Elastic Network Adapter Status)
    Write-Output "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
    Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EnaSupport
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
Copy-Item "C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1" $WorkDir
Copy-Item "C:\Program Files\Amazon\Ec2ConfigService\Logs\Ec2ConfigLog.txt" $WorkDir
Copy-Item "C:\Windows\TEMP\*.tmp" $WorkDir

# Save Configuration Files
Copy-Item $SysprepSettingsFile $WorkDir
Copy-Item $EC2SettingsFile $WorkDir
Copy-Item $CWLogsSettingsFile $WorkDir

# Get Command History
# Get-History | Export-Csv -Encoding default $WorkDir\bootstrap-command-list1.csv
# Get-History | ConvertTo-Csv > $WorkDir\bootstrap-command-list2.csv
# Get-History | ConvertTo-Json > $WorkDir\bootstrap-command-list.json

# EC2-Bootstrap Complete
Write-Output "#Execution Time taken[EC2-Bootstrap Complete]: $((Get-Date).Subtract($StartTime).Seconds) second(s)"  

# EC2 Instance Reboot
Restart-Computer -Force
</powershell>
