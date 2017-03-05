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
#      -  6.3 : Windows Server 2012 R2 (Microsoft Windows Server 2012 R2 [])
#               [Windows_Server-2012-R2_RTM-Japanese-64Bit-Base-YYYY.MM.DD]
#               [Windows_Server-2012-R2_RTM-English-64Bit-Base-YYYY.MM.DD]
#
#      - 10.0 : Windows Server 2016 (Microsoft Windows Server 2016 [])
#               [Windows_Server-2016-Japanese-Full-Base-YYYY.MM.DD]
#               [Windows_Server-2016-English-Full-Base-YYYY.MM.DD]
#
########################################################################################################################


#-----------------------------------------------------------------------------------------------------------------------
# User Define Parameter
#-----------------------------------------------------------------------------------------------------------------------

# Set Script Parameter for Directory Name (User Defined)
Set-Variable -Name BASE_DIR -Option Constant -Scope Script "$Env:SystemDrive\EC2-Bootstrap"
Set-Variable -Name TOOL_DIR -Option Constant -Scope Script "$BASE_DIR\Tools"
Set-Variable -Name LOGS_DIR -Option Constant -Scope Script "$BASE_DIR\Logs"
Set-Variable -Name TEMP_DIR -Option Constant -Scope Script "$Env:SystemRoot\Temp"

# Set Script Parameter for Log File Name (User Defined)
Set-Variable -Name USERDATA_LOG -Option Constant -Scope Script "$TEMP_DIR\userdata.log"
Set-Variable -Name TRANSCRIPT_LOG -Option Constant -Scope Script "$LOGS_DIR\userdata-transcript-3rd.log"

# Set System & Application Config File (System Defined : Windows Server 2008 R2 - 2012 R2)
Set-Variable -Name EC2ConfigFile -Option Constant -Scope Script -Value "C:\Program Files\Amazon\Ec2ConfigService\Settings\Config.xml"
Set-Variable -Name CWLogsFile -Option Constant -Scope Script -Value "C:\Program Files\Amazon\Ec2ConfigService\Settings\AWS.EC2.Windows.CloudWatch.json"

# Set System & Application Config File (System Defined : Windows Server 2016)
Set-Variable -Name EC2LaunchFile -Option Constant -Scope Script -Value "C:\ProgramData\Amazon\EC2-Windows\Launch\Config\LaunchConfig.json"

# Set System & Application Log File (System Defined : All Windows Server)
Set-Variable -Name SSMAgentLogFile -Option Constant -Scope Script -Value "C:\ProgramData\Amazon\SSM\Logs\amazon-ssm-agent.log"


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


function New-Directory
{
    param([string]$dir)

    if (!(Test-Path -Path $dir)) {
        Write-Log "# Creating directory : $dir"
        New-Item -Path $dir -ItemType Directory -Force
    }
} # end function New-Directory


########################################################################################################################
#
# Windows Bootstrap Individual requirement function
#  [Dependent on function]
#    - Write-Log
#
########################################################################################################################


function Get-AmazonMachineImageInformation
{
    Set-Variable -Name AMIRegistry -Option Constant -Scope Local -Value "HKLM:\SOFTWARE\Amazon\MachineImage"

    if (Test-Path $AMIRegistry) {
        $AMIRegistryValue = Get-ItemProperty -Path $AMIRegistry -ErrorAction SilentlyContinue
        $AmiOriginalVersion = $AMIRegistryValue.AMIVersion
        $AmiOriginalName = $AMIRegistryValue.AMIName

        # Write the information to the Log Files
        Write-Log "# [AMI] Windows - AMI Origin Version : $AmiOriginalVersion"
        Write-Log "# [AMI] Windows - AMI Origin Name : $AmiOriginalName"
    }
} # end function Get-AmazonMachineImageInformation


function Get-DotNetFrameworkVersion
{
    # Get Installed .NET Framework Version
    $dotnet_versions = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name Version -EA 0 | Where-Object -FilterScript { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -Property PSChildName, Version
    foreach ($dotnet_version in $dotnet_versions)
    {
        # Write the information to the Log Files
        Write-Log ("# [Windows] .NET Framework Information : v{0} - Profile : {1} " -f $dotnet_version.Version, $dotnet_version.PSChildName)
    }    
} # end function Get-DotNetFrameworkVersion


function Get-EbsVolumesMappingInformation
{
    # List the Windows disks

    # Create a hash table that maps each device to a SCSI target
    $Map = @{"0" = '/dev/sda1'} 
    for($x = 1; $x -le 26; $x++) {$Map.add($x.ToString(), [String]::Format("xvd{0}",[char](97 + $x)))}
    for($x = 78; $x -le 102; $x++) {$Map.add($x.ToString(), [String]::Format("xvdc{0}",[char](19 + $x)))}

    Try {
        # Use the metadata service to discover which instance the script is running on
        $Local:InstanceId = (Invoke-WebRequest '169.254.169.254/latest/meta-data/instance-id').Content
        $Local:AZ = (Invoke-WebRequest '169.254.169.254/latest/meta-data/placement/availability-zone').Content
        $Local:Region = $AZ.Substring(0, $AZ.Length -1)

        #Get the volumes attached to this instance
        $Local:BlockDeviceMappings = (Get-EC2Instance -Region $Region -Instance $InstanceId).Instances.BlockDeviceMappings

        #Get OS Language
        $Local:OsLanguage = ([CultureInfo]::CurrentCulture).IetfLanguageTag

    } Catch {
        Write-Log "Could not access the AWS API, therefore, VolumeId is not available. Verify that you provided your access keys."
    }
    
    $EBSVolumeLists = Get-WmiObject -Class Win32_DiskDrive | % {
        $Drive = $_
        
        # Find the partitions for this drive
        Get-WmiObject -Class Win32_DiskDriveToDiskPartition | Where-Object {$_.Antecedent -eq $Drive.Path.Path} | %{
            $D2P = $_
            # Get details about each partition
            $Partition = Get-WmiObject -Class Win32_DiskPartition | Where-Object {$_.Path.Path -eq $D2P.Dependent}
            # Find the drive that this partition is linked to
            $Disk = Get-WmiObject -Class Win32_LogicalDiskToPartition | Where-Object {$_.Antecedent -in $D2P.Dependent} | %{ 
                $L2P = $_
                #Get the drive letter for this partition, if there is one
                Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.Path.Path -in $L2P.Dependent}
            }
            $BlockDeviceMapping = $BlockDeviceMappings | Where-Object {$_.DeviceName -eq $Map[$Drive.SCSITargetId.ToString()]}
       
            if ($OsLanguage -eq "ja-JP") {
                # Display the information in a table (Japanese : ja-JP)
                New-Object PSObject -Property @{
                    Device = $Map[$Drive.SCSITargetId.ToString()];
                    Disk = [Int]::Parse($Partition.Name.Split(",")[0].Replace("ディスク #",""));
                    Boot = $Partition.BootPartition;
                    Partition = [Int]::Parse($Partition.Name.Split(",")[1].Replace(" パーティション #",""));
                    SCSITarget = $Drive.SCSITargetId;
                    DriveLetter = if($Disk -eq $NULL) {"NA"} else {$Disk.DeviceID};
                    VolumeName = if($Disk -eq $NULL) {"NA"} else {$Disk.VolumeName};
                    VolumeId = if($BlockDeviceMapping -eq $NULL) {"NA"} else {$BlockDeviceMapping.Ebs.VolumeId}
                }
            } elseif ($OsLanguage -eq "en-US") {
                # Display the information in a table (English : en-US)
                New-Object PSObject -Property @{
                    Device = $Map[$Drive.SCSITargetId.ToString()];
                    Disk = [Int]::Parse($Partition.Name.Split(",")[0].Replace("Disk #",""));
                    Boot = $Partition.BootPartition;
                    Partition = [Int]::Parse($Partition.Name.Split(",")[1].Replace(" Partition #",""));
                    SCSITarget = $Drive.SCSITargetId;
                    DriveLetter = If($Disk -eq $NULL) {"NA"} else {$Disk.DeviceID};
                    VolumeName = If($Disk -eq $NULL) {"NA"} else {$Disk.VolumeName};
                    VolumeId = If($BlockDeviceMapping -eq $NULL) {"NA"} else {$BlockDeviceMapping.Ebs.VolumeId}
                }
            } else {
                # [No Target Server OS]
                Write-Log ("# [Information] [Amazon EC2 Attached EBS Volumes] No Target Server OS Language : " + $OsLanguage)
            }

        }

    } | Sort-Object Disk, Partition | Select-Object Disk, Partition, SCSITarget, DriveLetter, Boot, VolumeId, Device, VolumeName
    
    foreach ($EBSVolumeList in $EBSVolumeLists)
    {
        if ($EBSVolumeList) {
            # Write the information to the Log Files
            Write-Log ("# [EBS] : [Disk - {0}] [Partition - {1}] [SCSITarget - {2}] [DriveLetter - {3}] [Boot - {4}] [VolumeId - {5}] [Device - {6}] [VolumeName - {7}]" -f $EBSVolumeList.Disk, $EBSVolumeList.Partition, $EBSVolumeList.SCSITarget, $EBSVolumeList.DriveLetter, $EBSVolumeList.Boot, $EBSVolumeList.VolumeId, $EBSVolumeList.Device, $EBSVolumeList.VolumeName)
        }
    } 
    
} # end Get-EbsVolumesMappingInformation


function Get-Ec2ConfigVersion
{
    #--------------------------------------------------------------------------------------
    #  Configuring a Windows Instance Using the EC2Config Service
    #   http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/UsingConfig_WinAMI.html
    #--------------------------------------------------------------------------------------

    # Set Initialize Parameter
    Set-Variable -Name Ec2ConfigVersion -Scope Script -Value ($Null)

    # Get EC2Config Version
    $EC2ConfigInfomation = $(Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Where-Object { $_.Name -eq "EC2ConfigService" })
    if ($EC2ConfigInfomation) {
        $Ec2ConfigVersion = $EC2ConfigInfomation.Version
    }

    # Write the information to the Log Files
    if ($Ec2ConfigVersion) {
        Write-Log "# [Windows] Amazon EC2Config Version : $Ec2ConfigVersion"
    }
} # end Get-Ec2ConfigVersion


function Get-Ec2InstanceMetadata
{
    #--------------------------------------------------------------------------------------
    #  Instance Metadata and User Data (Windows)
    #   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/ec2-instance-metadata.html
    #--------------------------------------------------------------------------------------

    # Set AWS Instance Metadata
    Set-Variable -Name AZ -Option Constant -Scope Script -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/placement/availability-zone)
    Set-Variable -Name Region -Option Constant -Scope Script -Value (Invoke-RestMethod -Uri http://169.254.169.254/latest/dynamic/instance-identity/document).region
    Set-Variable -Name InstanceId -Option Constant -Scope Script -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/instance-id)
    Set-Variable -Name InstanceType -Option Constant -Scope Script -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/instance-type)
    Set-Variable -Name PrivateIp -Option Constant -Scope Script -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/local-ipv4)
    Set-Variable -Name AmiId -Option Constant -Scope Script -Value (Invoke-Restmethod -Uri http://169.254.169.254/latest/meta-data/ami-id)

    # Set IAM Role & STS Information
    Set-Variable -Name RoleArn -Option Constant -Scope Script -Value ((Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/iam/info").Content | ConvertFrom-Json).InstanceProfileArn
    Set-Variable -Name RoleName -Option Constant -Scope Script -Value ($RoleArn -split "/" | select -Index 1)
    
    if ($RoleName) {
        Set-Variable -Name StsCredential -Scope Script -Value ((Invoke-WebRequest -Uri ("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + $RoleName)).Content | ConvertFrom-Json)
        Set-Variable -Name StsAccessKeyId -Scope Script -Value $StsCredential.AccessKeyId
        Set-Variable -Name StsSecretAccessKey -Scope Script -Value $StsCredential.SecretAccessKey
        Set-Variable -Name StsToken -Scope Script -Value $StsCredential.Token
    }

    # Set AWS Account ID
    Set-Variable -Name AwsAccountId -Option Constant -Scope Script -Value ((Invoke-WebRequest "http://169.254.169.254/latest/dynamic/instance-identity/document").Content | ConvertFrom-Json).accountId

    # Logging AWS Instance Metadata
    Write-Log "# [AWS] Region : $Region"
    Write-Log "# [AWS] Availability Zone : $AZ"
    Write-Log "# [AWS] Instance ID : $InstanceId"
    Write-Log "# [AWS] Instance Type : $InstanceType"
    Write-Log "# [AWS] VPC Private IP Address : $PrivateIp"
    Write-Log "# [AWS] Amazon Machine Images ID : $AmiId"
    if ($RoleName) {
        Write-Log "# [AWS] EC2 - Instance Profile ARN : $RoleArn"
        Write-Log "# [AWS] EC2 - IAM Role Name : $RoleName"
    }

} # end function Get-Ec2InstanceMetadata


function Get-Ec2LaunchVersion
{
    #--------------------------------------------------------------------------------------
    #  Configuring a Windows Instance Using EC2Launch
    #   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/ec2launch.html
    #--------------------------------------------------------------------------------------

    # Set Initialize Parameter
    Set-Variable -Name Ec2LaunchModuleConfig -Option Constant -Scope Local -Value "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"
    Set-Variable -Name Ec2LaunchVersion -Scope Script -Value ($Null)

    # Get EC2Launch Version from "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"
    if (Test-Path $Ec2LaunchModuleConfig) {
        $EC2LaunchModuleVersion = Select-String -Path $Ec2LaunchModuleConfig -Pattern "ModuleVersion"
        $Ec2LaunchVersion = $($EC2LaunchModuleVersion -match '(\d\.\d\.\d)' | Out-Null; $Matches[1])

        # Write the information to the Log Files
        if ($Ec2LaunchVersion) {
            Write-Log "# [Windows] Amazon EC2Launch Version : $Ec2LaunchVersion"
        }
    }
} # end Get-Ec2LaunchVersion


function Get-Ec2SystemManagerAgentVersion
{
    #--------------------------------------------------------------------------------------
    #  Amazon EC2 Systems Manager
    #   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/systems-manager.html
    #--------------------------------------------------------------------------------------

    # Set Initialize Parameter
    Set-Variable -Name SSMAgentRegistry -Option Constant -Scope Local -Value "HKLM:\SYSTEM\CurrentControlSet\Services\AmazonSSMAgent"
    Set-Variable -Name SSMAgentUninstallRegistry -Option Constant -Scope Local -Value "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B1A3AC35-A431-4C8C-9D21-E2CA92047F76}"
    Set-Variable -Name SsmAgentVersion -Scope Script -Value ($Null)

    if (Test-Path $SSMAgentRegistry) {
        $SSMAgentRegistryValue = Get-ItemProperty -Path $SSMAgentRegistry -ErrorAction SilentlyContinue
        $SsmAgentVersion = $SSMAgentRegistryValue.Version
    }

    if (-not $SsmAgentVersion -and (Test-Path $SSMAgentUninstallRegistry)) {
        $SSMAgentRegistryValue = Get-ItemProperty -Path $SSMAgentUninstallRegistry -ErrorAction SilentlyContinue
        $SsmAgentVersion = $SSMAgentRegistryValue.DisplayVersion
    }

    # Write the information to the Log Files
    if ($SsmAgentVersion) {
        Write-Log "# [Windows] Amazon SSM Agent Version : $SsmAgentVersion"
    }
} # end function Get-Ec2SystemManagerAgentVersion


function Get-NetAdapterBindingInformation
{
    # Get NetAdapter Binding Component
    $bindings = Get-NetAdapterBinding | Select-Object -Property Name, DisplayName, ComponentID, Enabled 
    foreach ($binding in $bindings)
    {
        # Write the information to the Log Files
        Write-Log ("# [Windows - OS Settings] NetAdapterBinding : [Name - {0}] [DisplayName - {1}] [ComponentID - {2}] [Enabled - {3}]" -f $binding.Name, $binding.DisplayName, $binding.ComponentID, $binding.Enabled)
    }    
} # end Get-NetAdapterBindingInformation


function Get-ScriptExecuteByAccount
{
    # Test of administrative privileges
    Set-Variable -Name CheckAdministrator -Scope Local -Value (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

    # Get PowerShell Script Execution UserName
    $ScriptExecuteByAccountInformation = [Security.Principal.WindowsIdentity]::GetCurrent()
    $ScriptExecuteByAccountName = ($ScriptExecuteByAccountInformation.Name -split "\" , 0 , "simplematch" | select -Index 1)

    # Write the information to the Log Files
    if ($ScriptExecuteByAccountName) {
        Write-Log ("# [Windows] Powershell Script Execution Username : " + ($ScriptExecuteByAccountName))
        if ($CheckAdministrator -eq $true){
            Write-Log "# [Windows] [Infomation] Bootstrap scripts run with the privileges of the administrator"
        } else {
            Write-Log "# [Windows] [Warning] Bootstrap scripts run with the privileges of the non-administrator"
        }
    }
} # end Get-ScriptExecuteByAccount


function Get-PageFileInformation
{
    # Get PageFile Information
    $pagefiles = Get-WmiObject -Class Win32_PageFileusage | Select-Object -Property Name, CurrentUsage, AllocatedBaseSize, PeakUsage, InstallDate
    foreach ($pagefile in $pagefiles)
    {
        # Write the information to the Log Files
        Write-Log ("# [Windows - OS Settings] Page File : [Name - {0}] [CurrentUsage - {1}] [AllocatedBaseSize - {2}] [PeakUsage - {3}]" -f $pagefile.Name, $pagefile.CurrentUsage, $pagefile.AllocatedBaseSize, $pagefile.PeakUsage)
    }    
} # end Get-PageFileInformation


function Get-PowerPlanInformation
{
    # Get PowerPlan Settings
    $powerplans = Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Select-Object ElementName, IsActive, Description
    foreach ($powerplan in $powerplans)
    {
        if ($powerplan | Where-Object { $_.IsActive -eq $True }) {
            # Write the information to the Log Files
            Write-Log ("# [Windows - OS Settings] PowerPlan : [ElementName - {0}] [IsActive - {1}] [Description - {2}]" -f $powerplan.ElementName, $powerplan.IsActive, $powerplan.Description)
        }
    } 
} # end Get-PowerPlanInformation


function Get-PowerShellVerson
{
    # Get PowerShell Environment Information
    $PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    $PowerShellClrVersion = $PSVersionTable.CLRVersion.ToString()

    # Write the information to the Log Files
    Write-Log ("# [Windows] PowerShell Information : [Version - {0}] [CLR Version - {1}]" -f $PowerShellVersion, $PowerShellClrVersion)
} # end Get-PowerShellVerson


function Get-WindowsDriverInformation
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
                    Write-Log ("# [Windows] Amazon EC2 Windows OS Driver Information : {0} v{1} " -f $pnp_driver.Name, $win_driver.Version)
                }
        }
    }    
} # end function Get-WindowsDriverInformation


function Get-WindowsServerInformation
{
    #--------------------------------------------------------------------------------------
    #  Windows Server OS Version Tables (Windows NT Version Tables)
    #   https://msdn.microsoft.com/ja-jp/library/windows/desktop/ms724832(v=vs.85).aspx
    #--------------------------------------------------------------------------------------
    #   - Windows Server 2003    : 5.2
    #   - Windows Server 2003 R2 : 5.2
    #   - Windows Server 2008    : 6.0
    #   - Windows Server 2008 R2 : 6.1
    #   - Windows Server 2012    : 6.2
    #   - Windows Server 2012 R2 : 6.3
    #   - Windows Server 2016    : 10.0
    #--------------------------------------------------------------------------------------

    # Initialize Parameter
    Set-Variable -Name productName -Scope Script -Value ($Null)
    Set-Variable -Name installOption -Scope Script -Value ($Null)
    Set-Variable -Name osVersion -Scope Script -Value ($Null)
    Set-Variable -Name osBuildLabEx -Scope Script -Value ($Null)

    Set-Variable -Name windowInfoKey -Option Constant -Scope Local -Value "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    Set-Variable -Name fullServer -Option Constant -Scope Local -Value "Full"
    Set-Variable -Name nanoServer -Option Constant -Scope Local -Value "Nano"
    Set-Variable -Name serverCore -Option Constant -Scope Local -Value "Server Core"
    Set-Variable -Name serverOptions -Option Constant -Scope Local -Value @{ 0 = "Undefined"; 12 = $serverCore; 13 = $serverCore;
        14 = $serverCore; 29 = $serverCore; 39 = $serverCore; 40 = $serverCore; 41 = $serverCore; 43 = $serverCore;
        44 = $serverCore; 45 = $serverCore; 46 = $serverCore; 63 = $serverCore; 143 = $nanoServer; 144 = $nanoServer;
        147 = $serverCore; 148 = $serverCore; }

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

    # Set Parameter 
    Set-Variable -Name WindowsOSVersion -Option Constant -Scope Script -Value ($osVersion.ToString())
    Set-Variable -Name WindowsOSLanguage -Option Constant -Scope Script -Value (([CultureInfo]::CurrentCulture).IetfLanguageTag)

} # end function Get-WindowsServerInformation


########################################################################################################################
#
# Windows Bootstrap Individual requirement function
#  [Dependent on function]
#    - Write-Log
#    - Get-Ec2InstanceMetadata
#    - Get-WindowsServerInformation
#
########################################################################################################################


function Update-SysprepAnswerFile($SysprepAnswerFile)
{
    [xml]$SysprepXMLDocument = Get-Content $SysprepAnswerFile -Encoding UTF8

    $SysprepNamespace = New-Object System.Xml.XmlNamespaceManager($SysprepXMLDocument.NameTable)
    $SysprepNamespace.AddNamespace("u", $SysprepXMLDocument.DocumentElement.NamespaceURI)

    $SysprepSettings = $SysprepXMLDocument.SelectSingleNode("//u:settings[@pass='oobeSystem']", $SysprepNamespace)

    $Sysprep_Node_International = $SysprepSettings.SelectSingleNode("u:component[@name='Microsoft-Windows-International-Core']", $SysprepNamespace)
    $Sysprep_Node_Shell = $SysprepSettings.SelectSingleNode("u:component[@name='Microsoft-Windows-Shell-Setup']", $SysprepNamespace)

    $Sysprep_Node_International.SystemLocale = "ja-JP"
    $Sysprep_Node_International.UserLocale = "ja-JP"

    $Sysprep_Node_Shell.TimeZone = "Tokyo Standard Time"

    $SysprepXMLDocument.Save($SysprepAnswerFile)

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

New-Directory $BASE_DIR
New-Directory $TOOL_DIR
New-Directory $LOGS_DIR

Start-Transcript -Path "$TRANSCRIPT_LOG" -Append -Force

Set-Variable -Name ScriptFullPath -Scope Script -Value ($MyInvocation.InvocationName)
Write-Log "# Script Execution 3rd-Bootstrap Script [START] : $ScriptFullPath"

Set-Location -Path $BASE_DIR

Get-ExecutionPolicy -List
Set-StrictMode -Version Latest


#-----------------------------------------------------------------------------------------------------------------------
# Logging Amazon EC2 System & Windows Server OS Parameter
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Logging Amazon EC2 System & Windows Server OS Parameter"

# Logging AWS Instance Metadata
Get-Ec2InstanceMetadata

# Logging Amazon EC2 attached EBS Volume List
Get-EbsVolumesMappingInformation

# Logging Windows Server OS Parameter [AMI : Amazon Machine Image]
Get-AmazonMachineImageInformation

# Logging PowerShell Script Execution UserName
Get-ScriptExecuteByAccount

# Logging Windows Server OS Parameter [Windows Server Information]
Get-WindowsServerInformation

# Logging Windows Server OS Parameter [.NET Framework Information]
Get-DotNetFrameworkVersion

# Logging Windows Server OS Parameter [PowerShell Environment Information]
Get-PowerShellVerson

# Logging Windows Server OS Parameter [Windows Driver Information]
Get-WindowsDriverInformation

# Logging Windows Server OS Parameter [EC2 Bootstrap Application Information]
if ($WindowsOSVersion -match "^5.*|^6.*") {
    Get-Ec2ConfigVersion
} elseif ($WindowsOSVersion -match "^10.*") {
    Get-Ec2LaunchVersion
} else {
    Write-Log ("# [Warning] No Target - Windows NT Version Information : " + $WindowsOSVersion)
}

# Logging Windows Server OS Parameter [EC2 System Manager (SSM) Agent Information]
Get-Ec2SystemManagerAgentVersion

# Logging Windows Server OS Parameter [OS Settings]
Get-PageFileInformation
Get-NetAdapterBindingInformation
Get-PowerPlanInformation


#-----------------------------------------------------------------------------------------------------------------------
# Amazon EC2 Information [AMI & Instance & EBS Volume]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Amazon EC2 Information [AMI & Instance & EBS Volume]"

# Setting AWS Tools for Windows PowerShell
Set-DefaultAWSRegion -Region $Region
Write-Log ("# [Amazon EC2 - Windows] Display Default Region at AWS Tools for Windows Powershell : " + (Get-DefaultAWSRegion).Name + " - "  + (Get-DefaultAWSRegion).Region)

# Get AMI Information
if ($RoleName) {
    Write-Log "# [Amazon EC2 - Windows] Get AMI Information"
    Get-EC2Image -ImageId $AmiId | ConvertTo-Json | Out-File "$LOGS_DIR\AWS-EC2_AMI-Infomation.txt" -Append -Force
}

# Get EC2 Instance Information
if ($RoleName) {
    Write-Log "# [Amazon EC2 - Windows] Get EC2 Instance Information"
    Get-EC2Instance -Filter @{Name = "instance-id"; Values = $InstanceId} | ConvertTo-Json | Out-File "$LOGS_DIR\AWS-EC2_EC2-Instance-Information.txt" -Append -Force
}

# Get EC2 Instance attached EBS Volume Information
if ($RoleName) {
    Write-Log "# [Amazon EC2 - Windows] Get EC2 Instance attached EBS Volume Information"
    Get-EC2Volume | Where-Object { $_.Attachments.InstanceId -eq $InstanceId} | ConvertTo-Json | Out-File "$LOGS_DIR\AWS-EC2_EBS-Volume-Information.txt" -Append -Force
}

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
if ($RoleName) {
    if ($InstanceType -match "^i3.*|^m4.16xlarge|^p2.*|^r4.*|^x1.*") {
        # Get EC2 Instance Attribute(Elastic Network Adapter Status)
        Write-Log "# [Amazon EC2 - Windows] Get EC2 Instance Attribute(Elastic Network Adapter Status)"
        Get-EC2Instance -Filter @{Name = "instance-id"; Values = $InstanceId} | Select-Object -ExpandProperty "Instances" | Out-File "$LOGS_DIR\AWS-EC2_ENI-ENA-Information.txt" -Append -Force
        # Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EnaSupport
    } elseif ($InstanceType -match "^c3.*|^c4.*|^d2.*|^i2.*|^m4.*|^r3.*") {
        # Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
        Write-Log "# [Amazon EC2 - Windows] Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
        Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute sriovNetSupport | Out-File "$LOGS_DIR\AWS-EC2_ENI-SRIOV-Information.txt" -Append -Force
    } else {
        Write-Log "# [Amazon EC2 - Windows] Instance type of None [Network Interface Performance Attribute]"
    }
}

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
if ($RoleName) {
    if ($InstanceType -match "^c1.*|^c3.*|^c4.*|^d2.*|^g2.*|^i2.*|^i3.*|^m1.*|^m2.*|^m3.*|^m4.*|^p2.*|^r3.*|^r4.*|^x1.*") {
        # Get EC2 Instance Attribute(EBS-optimized instance Status)
        Write-Log "# [Amazon EC2 - Windows] Get EC2 Instance Attribute(EBS-optimized instance Status)"
        Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EbsOptimized | Out-File "$LOGS_DIR\AWS-EC2_EBS-Optimized-Instance-Information.txt" -Append -Force
    } else {
        Write-Log "# [Amazon EC2 - Windows] Instance type of None [Storage Interface Performance Attribute]"
    }
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration"

# Setting System Locale
Write-Log ("# [Windows - OS Settings] Display Windows System Locale (Before) : " + (Get-WinSystemLocale).DisplayName + " - "  + (Get-WinSystemLocale).Name)
Set-WinSystemLocale -SystemLocale ja-JP
Write-Log ("# [Windows - OS Settings] Display Windows System Locale (After) : " + (Get-WinSystemLocale).DisplayName + " - "  + (Get-WinSystemLocale).Name)

Write-Log ("# [Windows - OS Settings] Display Windows Home Location (Before) : " + (Get-WinHomeLocation).HomeLocation)
Set-WinHomeLocation -GeoId 0x7A
Write-Log ("# [Windows - OS Settings] Display Windows Home Location (After) : " + (Get-WinHomeLocation).HomeLocation)

Write-Log ("# [Windows - OS Settings] Make the date and time [format] the same as the display language (Before) : " + (Get-WinCultureFromLanguageListOptOut))
Set-WinCultureFromLanguageListOptOut -OptOut $False
Write-Log ("# [Windows - OS Settings] Make the date and time [format] the same as the display language (After) : " + (Get-WinCultureFromLanguageListOptOut))

# Setting Japanese UI Language
Write-Log ("# [Windows - OS Settings] Override display language (Before) : " + (Get-WinUILanguageOverride).DisplayName + " - "  + (Get-WinUILanguageOverride).Name)
Set-WinUILanguageOverride -Language ja-JP
Write-Log ("# [Windows - OS Settings] Override display language (After) : " + (Get-WinUILanguageOverride).DisplayName + " - "  + (Get-WinUILanguageOverride).Name)

# Change Windows Update Policy
if ($WindowsOSVersion -match "^5.*|^6.*") {
    Write-Log "# [Windows - OS Settings] Change Windows Update Policy (Before)"

    # Change Windows Update Policy 
    $AUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
    $AUSettings.NotificationLevel         = 3      # Automatic Updates prompts users to approve updates & before downloading or installing
    $AUSettings.ScheduledInstallationDay  = 1      # Every Sunday
    $AUSettings.ScheduledInstallationTime = 3      # AM 3:00
    $AUSettings.IncludeRecommendedUpdates = $True  # Enabled
    $AUSettings.FeaturedUpdatesEnabled    = $True  # Enabled
    $AUSettings.Save()

    Start-Sleep -Seconds 5

    Write-Log "# [Windows - OS Settings] Change Windows Update Policy (After)"
} elseif ($WindowsOSVersion -match "^10.*") {
    Write-Log "# [Windows - OS Settings] Change Windows Update Policy (Before)"

    #----------------------------------------------------------------------------
    # [Unimplemented]
    #----------------------------------------------------------------------------

    Write-Log "# [Windows - OS Settings] Change Windows Update Policy (After)"
} else {
    Write-Log ("# [Warning] No Target - Windows NT Version Information : " + $WindowsOSVersion)
}


# Enable Microsoft Update
$SMSettings = New-Object -ComObject Microsoft.Update.ServiceManager -Strict 
$SMSettings.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
$SMSettings.Services

Start-Sleep -Seconds 5


# Change Windows Folder Option Policy
Set-Variable -Name FolderOptionRegistry -Option Constant -Scope Local -Value "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

Set-ItemProperty -Path $FolderOptionRegistry -Name 'Hidden' -Value '1' -Force                                  # [Check] Show hidden files, folders, or drives
Set-ItemProperty -Path $FolderOptionRegistry -Name 'HideFileExt' -Value '0' -Force                             # [UnCheck] Hide extensions for known file types
New-ItemProperty -Path $FolderOptionRegistry -Name 'PersistBrowsers' -Value '1' -PropertyType "DWord" -Force   # [Check] Restore previous folders windows

# Change Display Desktop Icon Policy
Set-Variable -Name DesktopIconRegistry -Option Constant -Scope Local -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
Set-Variable -Name DesktopIconRegistrySetting -Option Constant -Scope Local -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"

New-Item -Path $DesktopIconRegistry -Force 
New-Item -Path $DesktopIconRegistrySetting -Force 

New-ItemProperty -Path $DesktopIconRegistrySetting -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0' -PropertyType "DWord" -Force  #[CLSID] : My Computer
New-ItemProperty -Path $DesktopIconRegistrySetting -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value '0' -PropertyType "DWord" -Force  #[CLSID] : Control Panel
New-ItemProperty -Path $DesktopIconRegistrySetting -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value '0' -PropertyType "DWord" -Force  #[CLSID] : User's Files
New-ItemProperty -Path $DesktopIconRegistrySetting -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Value '0' -PropertyType "DWord" -Force  #[CLSID] : Recycle Bin
New-ItemProperty -Path $DesktopIconRegistrySetting -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Value '0' -PropertyType "DWord" -Force  #[CLSID] : Network

# Test Connecting to the Internet (Google Public DNS : 8.8.8.8)
if (Test-Connection -ComputerName 8.8.8.8 -Count 1) {
    # Write the information to the Log Files
    $netprofile = Get-NetConnectionProfile -IPv4Connectivity Internet
    Write-Log ("# [Windows - OS Settings] NetProfile : [Name - {0}] [InterfaceAlias - {1}] [NetworkCategory - {2}] [IPv4Connectivity - {3}] [IPv6Connectivity - {4}]" -f $netprofile.Name, $netprofile.InterfaceAlias, $netprofile.NetworkCategory, $netprofile.IPv4Connectivity, $netprofile.IPv6Connectivity)

    # Change NetConnectionProfile
    Set-NetConnectionProfile -InterfaceAlias (Get-NetConnectionProfile -IPv4Connectivity Internet).InterfaceAlias -NetworkCategory Private
    Start-Sleep -Seconds 5

    # Write the information to the Log Files
    $netprofile = Get-NetConnectionProfile -IPv4Connectivity Internet
    Write-Log ("# [Windows - OS Settings] NetProfile : [Name - {0}] [InterfaceAlias - {1}] [NetworkCategory - {2}] [IPv4Connectivity - {3}] [IPv6Connectivity - {4}]" -f $netprofile.Name, $netprofile.InterfaceAlias, $netprofile.NetworkCategory, $netprofile.IPv4Connectivity, $netprofile.IPv6Connectivity)
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [Sysprep Answer File Setting]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [Sysprep Answer File Setting]"

# Update Sysprep Answer File
if ($WindowsOSVersion -match "^5.*|^6.*") {
    # Sysprep Answer File
    Set-Variable -Name SysprepFile -Option Constant -Scope Script -Value "C:\Program Files\Amazon\Ec2ConfigService\sysprep2008.xml"

    Write-Log "# [Windows - OS Settings] Update Sysprep Answer File (Before)"
    if (Test-Path $SysprepFile) {
        Get-Content $SysprepFile

        Update-SysprepAnswerFile $SysprepFile

        Get-Content $SysprepFile
    }
    Write-Log "# [Windows - OS Settings] Update Sysprep Answer File (After)"
} elseif ($WindowsOSVersion -match "^10.*") {
    # Sysprep Answer File
    Set-Variable -Name SysprepFile -Option Constant -Scope Script -Value "C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml"

    Write-Log "# [Windows - OS Settings] Update Sysprep Answer File (Before)"
    if (Test-Path $SysprepFile) {
        Get-Content $SysprepFile

        Update-SysprepAnswerFile $SysprepFile

        Get-Content $SysprepFile
    }
    Write-Log "# [Windows - OS Settings] Update Sysprep Answer File (After)"
} else {
    Write-Log ("# [Warning] No Target - Windows NT Version Information : " + $WindowsOSVersion)
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [IPv6 Setting]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [IPv6 Setting]"

# Logging Windows Server OS Parameter [NetAdapter Binding Information]
Get-NetAdapterBindingInformation

# Disable IPv6 Binding
if (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "Amazon Elastic Network Adapter" }) {
    Write-Log "# [Windows - OS Settings] Disable-NetAdapterBinding(IPv6) : Amazon Elastic Network Adapter"
    Disable-NetAdapterBinding -InterfaceDescription "Amazon Elastic Network Adapter" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "Intel(R) 82599 Virtual Function" }) {
    Write-Log "# [Windows - OS Settings] Disable-NetAdapterBinding(IPv6) : Intel(R) 82599 Virtual Function"
    Disable-NetAdapterBinding -InterfaceDescription "Intel(R) 82599 Virtual Function" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "AWS PV Network Device #0" }) {
    Write-Log "# [Windows - OS Settings] Disable-NetAdapterBinding(IPv6) : AWS PV Network Device"
    Disable-NetAdapterBinding -InterfaceDescription "AWS PV Network Device #0" -ComponentID ms_tcpip6 -Confirm:$false
    Start-Sleep -Seconds 5
} else {
    Write-Log "# [Windows - OS Settings] Disable-NetAdapterBinding(IPv6) : No Target Device"
}

# Logging Windows Server OS Parameter [NetAdapter Binding Information]
Get-NetAdapterBindingInformation


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [System PowerPlan]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [System PowerPlan]"

# Change System PowerPlan (High Performance)
$HighPowerBase64 = "6auY44OR44OV44Kp44O844Oe44Oz44K5"                       # A string of "high performance" was Base64 encoded in Japanese
$HighPowerByte = [System.Convert]::FromBase64String($HighPowerBase64)       # Conversion from base64 to byte sequence
$HighPowerString = [System.Text.Encoding]::UTF8.GetString($HighPowerByte)   # To convert a sequence of bytes into a string of UTF-8 encoding

# Logging Windows Server OS Parameter [System Power Plan Information]
Get-PowerPlanInformation

if (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq $HighPowerString }) {
    Write-Log "# [Windows - OS Settings] PowerPlan : Change System PowerPlan - $HighPowerString"
    (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq $HighPowerString }).Activate()
    Start-Sleep -Seconds 5
} elseif (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq "High performance" }) {
    Write-Log "# [Windows - OS Settings] PowerPlan : Change System PowerPlan - High performance"
    (Get-WmiObject -Name root\cimv2\power -Class Win32_PowerPlan -Filter 'ElementName = "High performance"').Activate()
    Start-Sleep -Seconds 5
} else {
    Write-Log "# [Windows - OS Settings] PowerPlan : Change System PowerPlan - No change"
}

# Logging Windows Server OS Parameter [System Power Plan Information]
Get-PowerPlanInformation


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Update (Amazon EC2 Systems Manager Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Package Update System Utility (Amazon EC2 Systems Manager Agent)"

# Package Download System Utility (Amazon EC2 Systems Manager Agent)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/systems-manager-managedinstances.html#sysman-install-managed-win
Write-Log "# Package Download System Utility (Amazon EC2 Systems Manager Agent)"
$AmazonSSMAgentUrl = "https://amazon-ssm-" + ${Region} + ".s3.amazonaws.com/latest/windows_amd64/AmazonSSMAgentSetup.exe"
Invoke-WebRequest -Uri $AmazonSSMAgentUrl -OutFile "$TOOL_DIR\AmazonSSMAgentSetup.exe"

# Logging Windows Server OS Parameter [EC2 System Manager (SSM) Agent Information]
Get-Ec2SystemManagerAgentVersion

# Package Update System Utility (Amazon EC2 Systems Manager Agent)
Write-Log "# Package Update System Utility (Amazon EC2 Systems Manager Agent)"
Start-Process -FilePath "$TOOL_DIR\AmazonSSMAgentSetup.exe" -ArgumentList @('ALLOWEC2INSTALL=YES', '/install', '/norstart', '/log C:\EC2-Bootstrap\Logs\AmazonSSMAgentSetup.log', '/quiet') -Wait | Out-Null

Get-Service -Name AmazonSSMAgent

# Service Automatic Startup Setting (Amazon EC2 Systems Manager Agent)
$AmazonSSMAgentStatus = (Get-WmiObject Win32_Service -filter "Name='AmazonSSMAgent'").StartMode

if ($AmazonSSMAgentStatus -ne "Auto") {
    Write-Log "# [Windows - OS Settings] Service Startup Type Change [AmazonSSMAgent] $AmazonSSMAgentStatus -> Auto"
    Set-Service -Name "AmazonSSMAgent" -StartupType Automatic
    Start-Sleep -Seconds 5
    Write-Log "# [Windows - OS Settings] Service Startup Type Staus [AmazonSSMAgent] $AmazonSSMAgentStatus"
}

# Logging Windows Server OS Parameter [EC2 System Manager (SSM) Agent Information]
Get-Ec2SystemManagerAgentVersion

# Clear Log File
Clear-Content $SSMAgentLogFile

# Get Amazon SSM Agent Service Status
Restart-Service -Name AmazonSSMAgent
Start-Sleep -Seconds 30

# Get Service Status
Get-Service -Name AmazonSSMAgent

# View Log File
Get-Content $SSMAgentLogFile


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (System Utility)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Download (System Utility)"

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
Invoke-WebRequest -Uri 'https://1.as.dl.wireshark.org/win64/Wireshark-win64-2.2.4.exe' -OutFile "$TOOL_DIR\Wireshark-win64.exe"

# Package Download System Utility (EC2Config)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/UsingConfig_Install.html
if ($WindowsOSVersion -match "^5.*|^6.*") {
    Write-Log "# Package Download System Utility (EC2Config)"
    Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Config/EC2Install.zip' -OutFile "$TOOL_DIR\EC2Install.zip"
} else {
    Write-Log ("# [Information] No Target [EC2Config] - Windows NT Version Information : " + $WindowsOSVersion)
}

# Package Download System Utility (EC2Launch)
# http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2launch.html
if ($WindowsOSVersion -match "^10.*") {
    Write-Log "# Package Download System Utility (EC2Launch)"
    Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Launch/latest/EC2-Windows-Launch.zip' -OutFile "$TOOL_DIR\EC2-Windows-Launch.zip"
    Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Launch/latest/install.ps1' -OutFile "$TOOL_DIR\EC2-Windows-Launch-install.ps1"
} else {
    Write-Log ("# [Information] No Target [EC2Launch] - Windows NT Version Information : " + $WindowsOSVersion)
}

# Package Download System Utility (AWS-CLI - 64bit)
# https://aws.amazon.com/jp/cli/
Write-Log "# Package Download System Utility (AWS-CLI - 64bit)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/aws-cli/AWSCLI64.msi' -OutFile "$TOOL_DIR\AWSCLI64.msi"

# Package Download System Utility (AWS Tools for Windows PowerShell)
# https://aws.amazon.com/jp/powershell/
Write-Log "# Package Download System Utility (AWS Tools for Windows PowerShell)"
Invoke-WebRequest -Uri 'http://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi' -OutFile "$TOOL_DIR\AWSToolsAndSDKForNet.msi"

# Package Download System Utility (AWS CloudFormation Helper Scripts)
# http://docs.aws.amazon.com/ja_jp/AWSCloudFormation/latest/UserGuide/cfn-helper-scripts-reference.html
Write-Log "# Package Download System Utility (AWS CloudFormation Helper Scripts)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-win64-latest.msi' -OutFile "$TOOL_DIR\aws-cfn-bootstrap-win64-latest.msi"

# Package Download System Utility (AWS Directory Service PortTest Application)
# http://docs.aws.amazon.com/ja_jp/workspaces/latest/adminguide/connect_verification.html
Write-Log "# Package Download System Utility (AWS Directory Service PortTest Application)"
Invoke-WebRequest -Uri 'http://docs.aws.amazon.com/directoryservice/latest/admin-guide/samples/DirectoryServicePortTest.zip' -OutFile "$TOOL_DIR\DirectoryServicePortTest.zip"

# Package Download System Utility (EC2Rescue)
# https://aws.amazon.com/jp/premiumsupport/knowledge-center/ec2rescue-windows-troubleshoot/
Write-Log "# Package Download System Utility (EC2Rescue)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ec2rescue/windows/EC2Rescue_latest.zip' -OutFile "$TOOL_DIR\EC2Rescue_latest.zip"

# Package Download System Utility (AWS Diagnostics for Windows Server)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/Windows-Server-Diagnostics.html
Write-Log "# Package Download System Utility (AWS Diagnostics for Windows Server)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ec2-downloads-windows/AWSDiagnostics/AWSDiagnostics.zip' -OutFile "$TOOL_DIR\AWSDiagnostics.zip"

# Package Download System Utility (Amazon Inspector Agent)
# https://docs.aws.amazon.com/ja_jp/inspector/latest/userguide/inspector_working-with-agents.html#inspector-agent-windows
Write-Log "# Package Download System Utility (Amazon Inspector Agent)"
Invoke-WebRequest -Uri 'https://d1wk0tztpsntt1.cloudfront.net/windows/installer/latest/AWSAgentInstall.exe' -OutFile "$TOOL_DIR\AmazonInspectorAgent-Windows.exe"

# Package Download System Utility (AWS CodeDeploy agent)
# http://docs.aws.amazon.com/ja_jp/codedeploy/latest/userguide/how-to-run-agent-install.html#how-to-run-agent-install-windows
Write-Log "# Package Download System Utility (AWS CodeDeploy agent)"
$AWSCodeDeployAgentUrl = "https://aws-codedeploy-" + ${Region} + ".s3.amazonaws.com/latest/codedeploy-agent.msi"
Invoke-WebRequest -Uri $AWSCodeDeployAgentUrl -OutFile "$TOOL_DIR\AWSCodeDeployAgent-Windows.msi"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Monitoring Service Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Download (Monitoring Service Agent)"

# Package Download Monitoring Service Agent (Zabix Agent)
# http://www.zabbix.com/download
Write-Log "# Package Download Monitoring Service Agent (Zabix Agent)"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/2.2.14/zabbix_agents_2.2.14.win.zip' -OutFile "$TOOL_DIR\ZabbixAgent-v2.2-Latest-Windows.zip"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/3.0.4/zabbix_agents_3.0.4.win.zip' -OutFile "$TOOL_DIR\ZabbixAgent-v3.0-Latest-Windows.zip"
Invoke-WebRequest -Uri 'http://www.zabbix.com/downloads/3.2.0/zabbix_agents_3.2.0.win.zip' -OutFile "$TOOL_DIR\ZabbixAgent-v3.2-Latest-Windows.zip"

# Package Download Monitoring Service Agent (Datadog Agent)
# http://docs.datadoghq.com/ja/guides/basic_agent_usage/windows/
Write-Log "# Package Download Monitoring Service Agent (Datadog Agent)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ddagent-windows-stable/ddagent-cli.msi' -OutFile "$TOOL_DIR\DatadogAgent-Windows.msi"

# Package Download Monitoring Service Agent (New Relic Infrastructure Agent)
# https://docs.newrelic.com/docs/infrastructure/new-relic-infrastructure/installation/install-infrastructure-windows-server
Write-Log "# Package Download Monitoring Service Agent (New Relic Infrastructure Agent)"
Invoke-WebRequest -Uri 'https://download.newrelic.com/infrastructure_agent/windows/newrelic-infra.msi' -OutFile "$TOOL_DIR\NewRelicInfrastructureAgent-Windows.msi"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Security Service Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Download (Security Service Agent)"

# Package Download Security Service Agent (Deep Security Agent)
# http://esupport.trendmicro.com/ja-jp/enterprise/dsaas/top.aspx
Write-Log "# Package Download Security Service Agent (Deep Security Agent)"
Invoke-WebRequest -Uri 'https://app.deepsecurity.trendmicro.com/software/agent/Windows/x86_64/agent.msi' -OutFile "$TOOL_DIR\DSA-Windows-Agent_x86-64.msi"

# Package Download Security Service Agent (Alert Logic Universal Agent)
# https://docs.alertlogic.com/requirements/system-requirements.htm#reqsAgent
Write-Log "# Package Download Security Service Agent (Alert Logic Universal Agent)"
Invoke-WebRequest -Uri 'https://scc.alertlogic.net/software/al_agent-LATEST.msi' -OutFile "$TOOL_DIR\AlertLogic-Windows_agent-LATEST.msi"


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
Write-LogSeparator "Custom Package Download (NVIDIA GPU Driver & CUDA Toolkit)"

# Package Download NVIDIA Tesla K80 GPU Driver (for Amazon EC2 P2 Instance Family)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/accelerated-computing-instances.html
if ($InstanceType -match "^p2.*") {
    Write-Log "# Package Download NVIDIA Tesla K80 GPU Driver (for Amazon EC2 P2 Instance Family)"
    if ($WindowsOSVersion) {
        if ($WindowsOSVersion -eq "6.1") {
            # [Windows Server 2008 R2]
            $K80_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=91&pfid=762&osid=21&lid=1&whql=1&lang=en-us&ctk=0'
            $K80_driverversion = $($K80_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K80_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K80_driverversion} + "/" + ${K80_driverversion} + "-tesla-desktop-winserver2008-2012r2-64bit-international-whql.exe"
            Invoke-WebRequest -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2008R2.exe"
        } elseif ($WindowsOSVersion -eq "6.3") {
            # [Windows Server 2012 R2]
            $K80_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=91&pfid=762&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $K80_driverversion = $($K80_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K80_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K80_driverversion} + "/" + ${K80_driverversion} + "-tesla-desktop-winserver2008-2012r2-64bit-international-whql.exe"
            Invoke-WebRequest -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2012R2.exe"
        } elseif ($WindowsOSVersion -eq "10.0") {
            # [Windows Server 2016]
            $K80_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=91&pfid=762&osid=74&lid=1&whql=1&lang=en-us&ctk=0'
            $K80_driverversion = $($K80_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K80_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K80_driverversion} + "/" + ${K80_driverversion} + "-tesla-desktop-winserver2016-international-whql.exe"
            Invoke-WebRequest -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2016.exe"
        } else {
            # [No Target Server OS]
            Write-Log ("# [Information] [NVIDIA Tesla K80 GPU Driver] No Target Server OS Version : " + $WindowsOSVersion)
        }
    } else {
        # [Undefined Server OS]
        Write-Log "# [Warning] [NVIDIA Tesla K80 GPU Driver] Undefined Server OS"
    }
}


# Package Download NVIDIA GRID K520 GPU Driver (for Amazon EC2 G2 Instance Family)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/accelerated-computing-instances.html
if ($InstanceType -match "^g2.*") {
    Write-Log "# Package Download NVIDIA GRID K520 GPU Driver (for Amazon EC2 G2 Instance Family)"
    if ($WindowsOSVersion) {
        if ($WindowsOSVersion -eq "6.1") {
            # [Windows Server 2008 R2]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=21&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">R.*\((.*)\)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "-quadro-tesla-grid-winserv2008-2008r2-2012-64bit-international-whql.exe"
            Invoke-WebRequest -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2008R2.exe"
        } elseif ($WindowsOSVersion -eq "6.2") {
            # [Windows Server 2012]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=32&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">R.*\((.*)\)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "-quadro-tesla-grid-winserv2008-2008r2-2012-64bit-international-whql.exe"
            Invoke-WebRequest -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2012.exe"
        } elseif ($WindowsOSVersion -eq "6.3") {
            # [Windows Server 2012 R2]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">R.*\((.*)\)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "-quadro-tesla-grid-winserv2008-2008r2-2012-64bit-international-whql.exe"
            Invoke-WebRequest -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2012R2.exe"
        } else {
            # [No Target Server OS]
            Write-Log ("# [Information] [NVIDIA GRID K520 GPU Driver] No Target Server OS Version : " + $WindowsOSVersion)
        }
    } else {
        # [Undefined Server OS]
        Write-Log "# [Warning] [NVIDIA GRID K520 GPU Driver] Undefined Server OS"
    }
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Storage & Network Driver)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Download (Storage & Network Driver)"

# Package Download Amazon Windows Paravirtual Drivers
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/xen-drivers-overview.html
Write-Log "# Package Download Amazon Windows Paravirtual Drivers"
Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/Drivers/AWSPVDriverSetup.zip' -OutFile "$TOOL_DIR\AWSPVDriverSetup.zip"

# Package Download Intel Network Driver
if ($WindowsOSVersion) {
    if ($WindowsOSVersion -eq "6.1") {
        # [Windows Server 2008 R2]
        # https://downloadcenter.intel.com/ja/download/18725/
        # Package Download Intel Network Driver (Windows Server 2008 R2)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2008 R2)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/18725/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"
    } elseif ($WindowsOSVersion -eq "6.2") {
        # [Windows Server 2012]
        # https://downloadcenter.intel.com/ja/download/21694/
        # Package Download Intel Network Driver (Windows Server 2012)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2012)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/21694/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"
    } elseif ($WindowsOSVersion -eq "6.3") {
        # [Windows Server 2012 R2]
        # https://downloadcenter.intel.com/ja/download/23073/
        # Package Download Intel Network Driver (Windows Server 2012 R2)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2012 R2)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/23073/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"
    } elseif ($WindowsOSVersion -eq "10.0") {
        # [Windows Server 2016]
        # https://downloadcenter.intel.com/ja/download/26092/
        # Package Download Intel Network Driver (Windows Server 2016)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2016)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/26092/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\PROWinx64.exe"
    } else {
        # [No Target Server OS]
        Write-Log ("# [Information] [Intel Network Driver] No Target Server OS Version : " + $WindowsOSVersion)
    }
} else {
    # [Undefined Server OS]
    Write-Log "# [Warning] [Intel Network Driver] Undefined Server OS"
}

# Package Download Amazon Elastic Network Adapter Driver
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/enhanced-networking-ena.html
Write-Log "# Package Download Amazon Elastic Network Adapter Driver"
Invoke-WebRequest -Uri 'http://ec2-windows-drivers.s3.amazonaws.com/ENA.zip' -OutFile "$TOOL_DIR\ENA.zip"


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Installation (Application)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Installation (Application)"

# Package Install Modern Web Browser (Google Chrome 64bit)
Write-Log "# Package Download Modern Web Browser (Google Chrome 64bit)"
Invoke-WebRequest -Uri 'https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi' -OutFile "$TOOL_DIR\googlechrome.msi"
Write-Log "# Package Install Modern Web Browser (Google Chrome 64bit)"
Start-Process -FilePath "$TOOL_DIR\googlechrome.msi" -ArgumentList @("/quiet", "/log C:\EC2-Bootstrap\Logs\APPS_ChromeSetup.log") -Wait | Out-Null

# Package Install Text Editor (Visual Studio Code)
Write-Log "# Package Download Text Editor (Visual Studio Code)"
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?LinkID=623230' -OutFile "$TOOL_DIR\VSCodeSetup-stable.exe"
Write-Log "# Package Install Text Editor (Visual Studio Code)"
Start-Process -FilePath "$TOOL_DIR\VSCodeSetup-stable.exe" -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/LOG=C:\EC2-Bootstrap\Logs\APPS_VSCodeSetup.log") | Out-Null
Start-Sleep -Seconds 120


#-----------------------------------------------------------------------------------------------------------------------
# Collect Script/Config Files & Logging Data Files
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Collect Script/Config Files & Logging Data Files"

# Get System & User Variables
Write-Log "# Get System & User Variables"
Get-Variable | Export-Csv -Encoding default $BASE_DIR\Bootstrap-Variable.csv

# Save Userdata Script, Bootstrap Script, Logging Data Files
if ($WindowsOSVersion) {
    if ($WindowsOSVersion -eq "6.1") {
        # [Windows Server 2008 R2]
        Write-Log ("# Save Userdata Script, Bootstrap Script, Logging Data Files [Windows Server 2008 R2] : Windows NT OS Version : " + $WindowsOSVersion)

        # Save Script Files
        Copy-Item -Path "C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1" -Destination $BASE_DIR
        Copy-Item -Path "$TEMP_DIR\*.ps1" -Destination $BASE_DIR

        # Save Configuration Files
        Copy-Item -Path $SysprepFile -Destination $BASE_DIR
        Copy-Item -Path $EC2ConfigFile -Destination $BASE_DIR
        Copy-Item -Path $CWLogsFile -Destination $BASE_DIR

        # Save Logging Files
        Copy-Item -Path "C:\Program Files\Amazon\Ec2ConfigService\Logs\Ec2ConfigLog.txt" -Destination $LOGS_DIR 
        Copy-Item -Path $SSMAgentLogFile -Destination $LOGS_DIR 
        Copy-Item -Path "$TEMP_DIR\*.tmp" -Destination $LOGS_DIR 

    } elseif ($WindowsOSVersion -eq "6.2") {
        # [Windows Server 2012]
        Write-Log ("# Save Userdata Script, Bootstrap Script, Logging Data Files [Windows Server 2012] : Windows NT OS Version : " + $WindowsOSVersion)

        # Save Script Files
        Copy-Item -Path "C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1" -Destination $BASE_DIR
        Copy-Item -Path "$TEMP_DIR\*.ps1" -Destination $BASE_DIR

        # Save Configuration Files
        Copy-Item -Path $SysprepFile -Destination $BASE_DIR
        Copy-Item -Path $EC2ConfigFile -Destination $BASE_DIR
        Copy-Item -Path $CWLogsFile -Destination $BASE_DIR

        # Save Logging Files
        Copy-Item -Path "C:\Program Files\Amazon\Ec2ConfigService\Logs\Ec2ConfigLog.txt" -Destination $LOGS_DIR 
        Copy-Item -Path $SSMAgentLogFile -Destination $LOGS_DIR 
        Copy-Item -Path "$TEMP_DIR\*.tmp" -Destination $LOGS_DIR 

    } elseif ($WindowsOSVersion -eq "6.3") {
        # [Windows Server 2012 R2]
        Write-Log ("# Save Userdata Script, Bootstrap Script, Logging Data Files [Windows Server 2012 R2] : Windows NT OS Version : " + $WindowsOSVersion)

        # Save Script Files
        Copy-Item -Path "C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1" -Destination $BASE_DIR
        Copy-Item -Path "$TEMP_DIR\*.ps1" -Destination $BASE_DIR

        # Save Configuration Files
        Copy-Item -Path $SysprepFile -Destination $BASE_DIR
        Copy-Item -Path $EC2ConfigFile -Destination $BASE_DIR
        Copy-Item -Path $CWLogsFile -Destination $BASE_DIR

        # Save Logging Files
        Copy-Item -Path "C:\Program Files\Amazon\Ec2ConfigService\Logs\Ec2ConfigLog.txt" -Destination $LOGS_DIR 
        Copy-Item -Path $SSMAgentLogFile -Destination $LOGS_DIR 
        Copy-Item -Path "$TEMP_DIR\*.tmp" -Destination $LOGS_DIR 

    } elseif ($WindowsOSVersion -eq "10.0") {
        # [Windows Server 2016]
        Write-Log ("# Save Userdata Script, Bootstrap Script, Logging Data Files [Windows Server 2016] : Windows NT OS Version : " + $WindowsOSVersion)

        # Save Script Files
        Copy-Item -Path "$TEMP_DIR\*.ps1" -Destination $BASE_DIR

        # Save Configuration Files
        Copy-Item -Path $SysprepFile -Destination $BASE_DIR
        Copy-Item -Path $EC2LaunchFile -Destination $BASE_DIR
        Copy-Item "C:\ProgramData\Amazon\EC2-Windows\Launch\Config\DriveLetterMappingConfig.json" $BASE_DIR
        Copy-Item "C:\ProgramData\Amazon\EC2-Windows\Launch\Config\EventLogConfig.json" $BASE_DIR

        # Save Logging Files
        Copy-Item -Path "C:\ProgramData\Amazon\EC2-Windows\Launch\Log\*.log" -Destination $LOGS_DIR 
        Copy-Item -Path $SSMAgentLogFile -Destination $LOGS_DIR 
        Copy-Item -Path "$TEMP_DIR\*.tmp" -Destination $LOGS_DIR 

    } else {
        # [No Target Server OS]
        Write-Log ("# [Information] [Save Userdata Script, Bootstrap Script, Logging Data Files] No Target Windows NT OS Version : " + $WindowsOSVersion)
    }
} else {
    # [Undefined Server OS]
    Write-Log "# [Save Userdata Script, Bootstrap Script, Logging Data Files] Undefined Windows Server OS"
}


# Log Separator
Write-LogSeparator "Complete Script Execution 3rd-Bootstrap Script"

# Complete Logging
Write-Log "# Script Execution 3rd-Bootstrap Script [COMPLETE] : $ScriptFullPath"
# Save Logging Files(Write-Log Function LogFiles)
Copy-Item -Path $USERDATA_LOG -Destination $LOGS_DIR 

# Stop Transcript Logging
Stop-Transcript
# Save Logging Files(Start-Transcript Function LogFiles)
Copy-Item -Path "$TEMP_DIR\userdata-transcript-*.log" -Destination $LOGS_DIR 


#-----------------------------------------------------------------------------------------------------------------------
# Hostname rename & Instance Reboot
#-----------------------------------------------------------------------------------------------------------------------

# Setting Hostname
Set-Variable -Name Hostname -Option Constant -Scope Local -Value ($PrivateIp.Replace(".", "-"))
Rename-Computer $Hostname -Force

# EC2 Instance Reboot
Restart-Computer -Force
