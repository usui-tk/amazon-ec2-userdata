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


function New-Directory {
    param([string]$dir)

    if (!(Test-Path -Path $dir)) {
        Write-Log "# Creating directory : $dir"
        New-Item -Path $dir -ItemType Directory -Force
    }
} # end function New-Directory


function Set-TimeZoneCompatible {
    [CmdletBinding(SupportsShouldProcess = $True)]
    param( 
        [Parameter(ValueFromPipeline = $False, ValueFromPipelineByPropertyName = $True, Mandatory = $False)]
        [ValidateSet("Dateline Standard Time", "UTC-11", "Hawaiian Standard Time", "Alaskan Standard Time", "Pacific Standard Time (Mexico)", "Pacific Standard Time", "US Mountain Standard Time", "Mountain Standard Time (Mexico)", "Mountain Standard Time", "Central America Standard Time", "Central Standard Time", "Central Standard Time (Mexico)", "Canada Central Standard Time", "SA Pacific Standard Time", "Eastern Standard Time", "US Eastern Standard Time", "Venezuela Standard Time", "Paraguay Standard Time", "Atlantic Standard Time", "Central Brazilian Standard Time", "SA Western Standard Time", "Pacific SA Standard Time", "Newfoundland Standard Time", "E. South America Standard Time", "Argentina Standard Time", "SA Eastern Standard Time", "Greenland Standard Time", "Montevideo Standard Time", "Bahia Standard Time", "UTC-02", "Mid-Atlantic Standard Time", "Azores Standard Time", "Cape Verde Standard Time", "Morocco Standard Time", "UTC", "GMT Standard Time", "Greenwich Standard Time", "W. Europe Standard Time", "Central Europe Standard Time", "Romance Standard Time", "Central European Standard Time", "W. Central Africa Standard Time", "Namibia Standard Time", "Jordan Standard Time", "GTB&nbsp;Standard Time", "Middle East Standard Time", "Egypt Standard Time", "Syria Standard Time", "E. Europe Standard Time", "South Africa Standard Time", "FLE&nbsp;Standard Time", "Turkey Standard Time", "Israel Standard Time", "Arabic Standard Time", "Kaliningrad Standard Time", "Arab Standard Time", "E. Africa Standard Time", "Iran Standard Time", "Arabian Standard Time", "Azerbaijan Standard Time", "Russian Standard Time", "Mauritius Standard Time", "Georgian Standard Time", "Caucasus Standard Time", "Afghanistan Standard Time", "Pakistan Standard Time", "West Asia Standard Time", "India Standard Time", "Sri Lanka Standard Time", "Nepal Standard Time", "Central Asia Standard Time", "Bangladesh Standard Time", "Ekaterinburg Standard Time", "Myanmar Standard Time", "SE Asia Standard Time", "N. Central Asia Standard Time", "China Standard Time", "North Asia Standard Time", "Singapore Standard Time", "W. Australia Standard Time", "Taipei Standard Time", "Ulaanbaatar Standard Time", "North Asia East Standard Time", "Tokyo Standard Time", "Korea Standard Time", "Cen. Australia Standard Time", "AUS Central Standard Time", "E. Australia Standard Time", "AUS Eastern Standard Time", "West Pacific Standard Time", "Tasmania Standard Time", "Yakutsk&nbsp;Standard Time", "Central Pacific Standard Time", "Vladivostok Standard Time", "New Zealand Standard Time", "UTC+12", "Fiji Standard Time", "Magadan&nbsp;Standard Time", "Tonga Standard Time", "Samoa Standard Time")]
        [ValidateNotNullOrEmpty()]
        [string]$TimeZone = "Tokyo Standard Time"
    ) 

    $process = New-Object System.Diagnostics.Process 
    $process.StartInfo.WindowStyle = "Hidden" 
    $process.StartInfo.FileName = "tzutil.exe" 
    $process.StartInfo.Arguments = "/s `"$TimeZone`"" 
    $process.Start() | Out-Null 
} # end function Set-TimeZoneCompatible



########################################################################################################################
#
# Windows Bootstrap Individual requirement function
#  [Dependent on function]
#    - Write-Log
#
########################################################################################################################


function Get-AmazonMachineImageInformation {
    Set-Variable -Name AMIRegistry -Option Constant -Scope Local -Value "HKLM:\SOFTWARE\Amazon\MachineImage"

    if (Test-Path $AMIRegistry) {
        $AMIRegistryValue = Get-ItemProperty -Path $AMIRegistry -ErrorAction SilentlyContinue
        $AmiOriginalVersion = $AMIRegistryValue.AMIVersion
        $AmiOriginalName = $AMIRegistryValue.AMIName

        # Write the information to the Log Files
        Write-Log "# [AWS - AMI] Windows - AMI Origin Version : $AmiOriginalVersion"
        Write-Log "# [AWS - AMI] Windows - AMI Origin Name : $AmiOriginalName"
    }
} # end function Get-AmazonMachineImageInformation


function Get-AmazonMachineInformation {
    # Get System BIOS Information
    Set-Variable -Name BiosRegistry -Option Constant -Scope Local -Value "HKLM:\HARDWARE\DESCRIPTION\System"

    if (Test-Path $BiosRegistry) {
        $BiosRegistryValue = Get-ItemProperty -Path $BiosRegistry -ErrorAction SilentlyContinue
        $SystemBiosVersion = $BiosRegistryValue.SystemBiosVersion

        # Write the information to the Log Files
        Write-Log "# [AWS - EC2] Hardware - System BIOS Revision : $SystemBiosVersion"
    }

    # Get System BIOS Details Information
    Set-Variable -Name BiosDetailsRegistry -Option Constant -Scope Local -Value "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"

    if (Test-Path $BiosDetailsRegistry) {
        $BiosDetailsRegistryValue = Get-ItemProperty -Path $BiosDetailsRegistry -ErrorAction SilentlyContinue
        $BiosSystemManufacturer = $BiosDetailsRegistryValue.SystemManufacturer
        $BiosSystemProductName = $BiosDetailsRegistryValue.SystemProductName
        $BiosSystemVersion = $BiosDetailsRegistryValue.SystemVersion

        # Write the information to the Log Files
        Write-Log "# [AWS - EC2] Hardware - System BIOS Manufacturer : $BiosSystemManufacturer"
        Write-Log "# [AWS - EC2] Hardware - System BIOS ProductName : $BiosSystemProductName"
        Write-Log "# [AWS - EC2] Hardware - System BIOS Version : $BiosSystemVersion"        
    }

    # Get System CPU Information
    Set-Variable -Name CpuRegistry -Option Constant -Scope Local -Value "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0"

    if (Test-Path $CpuRegistry) {
        $CpuRegistryValue = Get-ItemProperty -Path $CpuRegistry -ErrorAction SilentlyContinue
        $CpuVendorIdentifier = $CpuRegistryValue.VendorIdentifier
        $CpuProcessorName = $CpuRegistryValue.ProcessorNameString

        # Write the information to the Log Files
        Write-Log "# [AWS - EC2] Hardware - CPU Vendor Information : $CpuVendorIdentifier"
        Write-Log "# [AWS - EC2] Hardware - CPU Model Information : $CpuProcessorName"
    }

    # Get Windows RegisteredOrganization & RegisteredOwner Information
    Set-Variable -Name Ec2Registry -Option Constant -Scope Local -Value "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    if (Test-Path $Ec2Registry) {
        $Ec2RegistryValue = Get-ItemProperty -Path $Ec2Registry -ErrorAction SilentlyContinue
        $Ec2RegisteredOrganization = $Ec2RegistryValue.RegisteredOrganization
        $Ec2RegisteredOwner = $Ec2RegistryValue.RegisteredOwner

        # Write the information to the Log Files
        Write-Log "# [AWS - EC2] Windows - RegisteredOrganization : $Ec2RegisteredOrganization"
        Write-Log "# [AWS - EC2] Windows - RegisteredOwner : $Ec2RegisteredOwner"
    }

} # end function Get-AmazonMachineInformation


function Get-DotNetFrameworkVersion {
    # Get Installed .NET Framework Version
    $dotnet_versions = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name Version -EA 0 | Where-Object -FilterScript { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -Property PSChildName, Version
    foreach ($dotnet_version in $dotnet_versions) {
        # Write the information to the Log Files
        Write-Log ("# [Windows] .NET Framework Information : v{0} - Profile : {1} " -f $dotnet_version.Version, $dotnet_version.PSChildName)
    }    
} # end function Get-DotNetFrameworkVersion


function Get-EbsVolumesMappingInformation {
    # List the Windows disks

    # Set Initialize Parameter
    Set-Variable -Name BlockDeviceMapping -Scope Script -Value ($Null)
    Set-Variable -Name EBSVolumeList -Scope Script -Value ($Null)
    Set-Variable -Name BlockDeviceMappings -Scope Script -Value ($Null)
    Set-Variable -Name EBSVolumeLists -Scope Script -Value ($Null)

    # Create a hash table that maps each device to a SCSI target
    $Map = @{"0" = '/dev/sda1'} 
    for ($x = 1; $x -le 26; $x++) {$Map.add($x.ToString(), [String]::Format("xvd{0}", [char](97 + $x)))}
    for ($x = 78; $x -le 102; $x++) {$Map.add($x.ToString(), [String]::Format("xvdc{0}", [char](19 + $x)))}

    Try {
        # Use the metadata service to discover which instance the script is running on
        
        # InstanceId
        if ( [string]::IsNullOrEmpty($InstanceId) ) {
            $InstanceId = (Invoke-WebRequest '169.254.169.254/latest/meta-data/instance-id').Content
        }

        # AZ:Availability Zone
        if ( [string]::IsNullOrEmpty($AZ) ) {
            $AZ = (Invoke-WebRequest '169.254.169.254/latest/meta-data/placement/availability-zone').Content
        }

        # Region
        if ( [string]::IsNullOrEmpty($Region) ) {
            $Region = $AZ.Substring(0, $AZ.Length - 1)
        }

        #Get OS Language
        $OsLanguage = ([CultureInfo]::CurrentCulture).IetfLanguageTag
        
        #Get the volumes attached to this instance
        $BlockDeviceMappings = (Get-EC2Instance -Region $Region -Instance $InstanceId).Instances.BlockDeviceMappings | Sort-Object | Get-Unique

    }
    Catch {
        Write-Log "Could not access the AWS API, therefore, VolumeId is not available. Verify that you provided your access keys."
    }
    
    $EBSVolumeLists = Get-WmiObject -Class Win32_DiskDrive | % {
        $Drive = $_
        
        # Find the partitions for this drive
        Get-WmiObject -Class Win32_DiskDriveToDiskPartition | Where-Object {$_.Antecedent -eq $Drive.Path.Path} | % {
            $D2P = $_
            # Get details about each partition
            $Partition = Get-WmiObject -Class Win32_DiskPartition | Where-Object {$_.Path.Path -eq $D2P.Dependent}
            # Find the drive that this partition is linked to
            $Disk = Get-WmiObject -Class Win32_LogicalDiskToPartition | Where-Object {$_.Antecedent -in $D2P.Dependent} | % { 
                $L2P = $_
                #Get the drive letter for this partition, if there is one
                Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.Path.Path -in $L2P.Dependent}
            }
            $BlockDeviceMapping = $BlockDeviceMappings | Where-Object {$_.DeviceName -eq $Map[$Drive.SCSITargetId.ToString()]}
       
            if ($OsLanguage -eq "ja-JP") {
                # Setting Paramter ["Disk #" in Japanese]
                $Word_Disk_Base64 = "44OH44Kj44K544KvICM="                                    # A string of "Disk #" was Base64 encoded in Japanese
                $Word_Disk_Byte = [System.Convert]::FromBase64String($Word_Disk_Base64)       # Conversion from base64 to byte sequence
                $Word_Disk_String = [System.Text.Encoding]::UTF8.GetString($Word_Disk_Byte)   # To convert a sequence of bytes into a string of UTF-8 encoding

                # Setting Paramter [" Partition #" in Japanese]
                $Word_Partition_Base64 = "IOODkeODvOODhuOCo+OCt+ODp+ODsyAj"                             # A string of " Partition #" was Base64 encoded in Japanese
                $Word_Partition_Byte = [System.Convert]::FromBase64String($Word_Partition_Base64)       # Conversion from base64 to byte sequence
                $Word_Partition_String = [System.Text.Encoding]::UTF8.GetString($Word_Partition_Byte)   # To convert a sequence of bytes into a string of UTF-8 encoding

                # Display the information in a table (Japanese : ja-JP)
                New-Object -TypeName PSCustomObject -Property @{
                    Device      = $Map[$Drive.SCSITargetId.ToString()];
                    Disk        = [Int]::Parse($Partition.Name.Split(",")[0].Replace("${Word_Disk_String}", ""));
                    Boot        = $Partition.BootPartition;
                    Partition   = [Int]::Parse($Partition.Name.Split(",")[1].Replace("${Word_Partition_String}", ""));
                    SCSITarget  = $Drive.SCSITargetId;
                    DriveLetter = if ($Disk -eq $NULL) {"NA"} else {$Disk.DeviceID};
                    VolumeName  = if ($Disk -eq $NULL) {"NA"} else {$Disk.VolumeName};
                    VolumeId    = if ($BlockDeviceMapping -eq $NULL) {"NA"} else {$BlockDeviceMapping.Ebs.VolumeId}
                }
            }
            elseif ($OsLanguage -eq "en-US") {
                # Display the information in a table (English : en-US)
                New-Object -TypeName PSCustomObject -Property @{
                    Device      = $Map[$Drive.SCSITargetId.ToString()];
                    Disk        = [Int]::Parse($Partition.Name.Split(",")[0].Replace("Disk #", ""));
                    Boot        = $Partition.BootPartition;
                    Partition   = [Int]::Parse($Partition.Name.Split(",")[1].Replace(" Partition #", ""));
                    SCSITarget  = $Drive.SCSITargetId;
                    DriveLetter = If ($Disk -eq $NULL) {"NA"} else {$Disk.DeviceID};
                    VolumeName  = If ($Disk -eq $NULL) {"NA"} else {$Disk.VolumeName};
                    VolumeId    = If ($BlockDeviceMapping -eq $NULL) {"NA"} else {$BlockDeviceMapping.Ebs.VolumeId}
                }
            }
            else {
                # [No Target Server OS]
                Write-Log ("# [Information] [Amazon EC2 Attached EBS Volumes] No Target Server OS Language : " + $OsLanguage)
            }

        }

    } | Sort-Object Disk, Partition | Select-Object Disk, Partition, SCSITarget, DriveLetter, Boot, VolumeId, Device, VolumeName
    
    foreach ($EBSVolumeList in $EBSVolumeLists) {
        if ($EBSVolumeList) {
            # Write the information to the Log Files
            Write-Log ("# [AWS - EBS] Windows - [Disk - {0}] [Partition - {1}] [SCSITarget - {2}] [DriveLetter - {3}] [Boot - {4}] [VolumeId - {5}] [Device - {6}] [VolumeName - {7}]" -f $EBSVolumeList.Disk, $EBSVolumeList.Partition, $EBSVolumeList.SCSITarget, $EBSVolumeList.DriveLetter, $EBSVolumeList.Boot, $EBSVolumeList.VolumeId, $EBSVolumeList.Device, $EBSVolumeList.VolumeName)
        }
    } 
    
} # end Get-EbsVolumesMappingInformation


function Get-Ec2ConfigVersion {
    #--------------------------------------------------------------------------------------
    #  Configuring a Windows Instance Using the EC2Config Service
    #   http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/UsingConfig_WinAMI.html
    #--------------------------------------------------------------------------------------

    # Set Initialize Parameter
    Set-Variable -Name Ec2ConfigVersion -Scope Script -Value ($Null)

    # Get EC2Config Version
    $EC2ConfigInformation = $(Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Where-Object { $_.Name -eq "EC2ConfigService" })
    if ($EC2ConfigInformation) {
        $Ec2ConfigVersion = $EC2ConfigInformation.Version
    }

    # Write the information to the Log Files
    if ($Ec2ConfigVersion) {
        Write-Log "# [Windows] Amazon EC2 Windows Utility Information - Amazon EC2Config Version : $Ec2ConfigVersion"
    }
} # end Get-Ec2ConfigVersion


function Get-Ec2InstanceMetadata {
    #--------------------------------------------------------------------------------------
    #  Instance Metadata and User Data (Windows)
    #   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/ec2-instance-metadata.html
    #--------------------------------------------------------------------------------------

    # Set AWS Instance Metadata
    Set-Variable -Name AZ -Option Constant -Scope Script -Value (Invoke-Restmethod -Uri "http://169.254.169.254/latest/meta-data/placement/availability-zone")
    Set-Variable -Name Region -Option Constant -Scope Script -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/dynamic/instance-identity/document").region
    Set-Variable -Name InstanceId -Option Constant -Scope Script -Value (Invoke-Restmethod -Uri "http://169.254.169.254/latest/meta-data/instance-id")
    Set-Variable -Name InstanceType -Option Constant -Scope Script -Value (Invoke-Restmethod -Uri "http://169.254.169.254/latest/meta-data/instance-type")
    Set-Variable -Name PrivateIp -Option Constant -Scope Script -Value (Invoke-Restmethod -Uri "http://169.254.169.254/latest/meta-data/local-ipv4")
    Set-Variable -Name AmiId -Option Constant -Scope Script -Value (Invoke-Restmethod -Uri "http://169.254.169.254/latest/meta-data/ami-id")

    # Set IAM Role & STS Information
    Set-Variable -Name RoleArn -Option Constant -Scope Script -Value ((Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/iam/info").Content | ConvertFrom-Json).InstanceProfileArn
    Set-Variable -Name RoleName -Option Constant -Scope Script -Value ($RoleArn -split "/" | Select-Object -Index 1)
    
    if ($RoleName) {
        Set-Variable -Name StsCredential -Scope Script -Value ((Invoke-WebRequest -Uri ("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + $RoleName)).Content | ConvertFrom-Json)
        Set-Variable -Name StsAccessKeyId -Scope Script -Value $StsCredential.AccessKeyId
        Set-Variable -Name StsSecretAccessKey -Scope Script -Value $StsCredential.SecretAccessKey
        Set-Variable -Name StsToken -Scope Script -Value $StsCredential.Token
    }

    # Set AWS Account ID
    Set-Variable -Name AwsAccountId -Option Constant -Scope Script -Value ((Invoke-WebRequest "http://169.254.169.254/latest/dynamic/instance-identity/document").Content | ConvertFrom-Json).accountId

    # Logging AWS Instance Metadata
    Write-Log "# [AWS - EC2] Region : $Region"
    Write-Log "# [AWS - EC2] Availability Zone : $AZ"
    Write-Log "# [AWS - EC2] Instance ID : $InstanceId"
    Write-Log "# [AWS - EC2] Instance Type : $InstanceType"
    Write-Log "# [AWS - EC2] VPC Private IP Address(IPv4) : $PrivateIp"
    Write-Log "# [AWS - EC2] Amazon Machine Images ID : $AmiId"
    if ($RoleName) {
        Write-Log "# [AWS - EC2] Instance Profile ARN : $RoleArn"
        Write-Log "# [AWS - EC2] IAM Role Name : $RoleName"
    }

} # end function Get-Ec2InstanceMetadata


function Get-Ec2LaunchVersion {
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
            Write-Log "# [Windows] Amazon EC2 Windows Utility Information - Amazon EC2Launch Version : $Ec2LaunchVersion"
        }
    }
} # end Get-Ec2LaunchVersion


function Get-Ec2SystemManagerAgentVersion {
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
        Write-Log "# [Windows] Amazon EC2 Windows Utility Information - Amazon SSM Agent Version : $SsmAgentVersion"
    }
} # end function Get-Ec2SystemManagerAgentVersion


function Get-NetAdapterBindingInformation {
    # Get NetAdapter Binding Component
    $NetAdapterBindings = Get-NetAdapterBinding | Select-Object -Property Name, DisplayName, ComponentID, Enabled 
    foreach ($NetAdapterBinding in $NetAdapterBindings) {
        # Write the information to the Log Files
        Write-Log ("# [Windows - OS Settings] NetAdapterBinding : [Name - {0}] [DisplayName - {1}] [ComponentID - {2}] [Enabled - {3}]" -f $NetAdapterBinding.Name, $NetAdapterBinding.DisplayName, $NetAdapterBinding.ComponentID, $NetAdapterBinding.Enabled)
    }    
} # end Get-NetAdapterBindingInformation


function Get-NetFirewallProfileInformation {
    # Get Net Firewall Profile
    $FirewallProfiles = Get-NetFirewallProfile | Select-Object -Property Name, Enabled
    foreach ($FirewallProfile in $FirewallProfiles) {
        # Write the information to the Log Files
        Write-Log ("# [Windows - OS Settings] NetFirewallProfile : [Name - {0}] [Enabled - {1}]" -f $FirewallProfile.Name, $FirewallProfile.Enabled)
    }    
} # end Get-NetFirewallProfileInformation


function Get-ScriptExecuteByAccount {
    # Get PowerShell Script Execution UserName
    Set-Variable -Name ScriptExecuteByAccountInformation -Scope Local -Value ([Security.Principal.WindowsIdentity]::GetCurrent())
    Set-Variable -Name ScriptExecuteByAccountName -Scope Local -Value ($ScriptExecuteByAccountInformation.Name -split "\" , 0 , "simplematch" | Select-Object -Index 1)
    
    # Test of administrative privileges
    Set-Variable -Name CheckAdministrator -Scope Local -Value (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

    # Write the information to the Log Files
    if ($ScriptExecuteByAccountName) {
        Write-Log ("# [Windows] Powershell Script Execution Username : " + ($ScriptExecuteByAccountName))
        if ($CheckAdministrator -eq $true) {
            Write-Log "# [Windows] [Information] Bootstrap scripts run with the privileges of the administrator"
        }
        else {
            Write-Log "# [Windows] [Warning] Bootstrap scripts run with the privileges of the non-administrator"
        }
    }
} # end Get-ScriptExecuteByAccount


function Get-PageFileInformation {
    # Get PageFile Information
    $pagefiles = Get-WmiObject -Class Win32_PageFileusage | Select-Object -Property Name, CurrentUsage, AllocatedBaseSize, PeakUsage, InstallDate
    foreach ($pagefile in $pagefiles) {
        # Write the information to the Log Files
        Write-Log ("# [Windows - OS Settings] Page File : [Name - {0}] [CurrentUsage - {1}] [AllocatedBaseSize - {2}] [PeakUsage - {3}]" -f $pagefile.Name, $pagefile.CurrentUsage, $pagefile.AllocatedBaseSize, $pagefile.PeakUsage)
    }    
} # end Get-PageFileInformation


function Get-PowerPlanInformation {
    # Get PowerPlan Settings
    $powerplans = Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Select-Object ElementName, IsActive, Description
    foreach ($powerplan in $powerplans) {
        if ($powerplan | Where-Object { $_.IsActive -eq $True }) {
            # Write the information to the Log Files
            Write-Log ("# [Windows - OS Settings] PowerPlan : [ElementName - {0}] [IsActive - {1}] [Description - {2}]" -f $powerplan.ElementName, $powerplan.IsActive, $powerplan.Description)
        }
    } 
} # end Get-PowerPlanInformation


function Get-PowerShellVerson {
    # Get PowerShell Environment Information
    $PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    $PowerShellClrVersion = $PSVersionTable.CLRVersion.ToString()

    # Write the information to the Log Files
    Write-Log ("# [Windows] PowerShell Information : [Version - {0}] [CLR Version - {1}]" -f $PowerShellVersion, $PowerShellClrVersion)
} # end Get-PowerShellVerson


function Get-WindowsDriverInformation {
    $win_drivers = Get-WindowsDriver -Online | Where-Object { $_.OriginalFileName -like '*xenvbd*' -or $_.ClassName -eq 'Net' -and `
        ($_.ProviderName -eq 'Amazon Inc.' -or $_.ProviderName -eq 'Citrix Systems, Inc.' -or $_.ProviderName -like 'Intel*' -or $_.ProviderName -eq 'Amazon Web Services, Inc.') }
    $pnp_drivers = Get-CimInstance -ClassName Win32_PnPEntity | Where-Object { $_.Service -eq 'xenvbd' -or `
            $_.Manufacturer -like 'Intel*' -or $_.Manufacturer -eq 'Citrix Systems, Inc.' -or $_.Manufacturer -eq 'Amazon Inc.' -or $_.Manufacturer -eq 'Amazon Web Services, Inc.' }
    
    foreach ($win_driver in $win_drivers) {
        foreach ($pnp_driver in $pnp_drivers) {
            if ($pnp_driver.Service -and $win_driver.OriginalFileName -like ("*{0}*" -f $pnp_driver.Service)) {
                # Write the information to the Log Files
                Write-Log ("# [Windows] Amazon EC2 Windows OS Driver Information : {0} v{1} " -f $pnp_driver.Name, $win_driver.Version)
            }
        }
    }    
} # end function Get-WindowsDriverInformation


function Get-WindowsServerInformation {
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
        147 = $serverCore; 148 = $serverCore; 
    }

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
        }
        elseif ($osVersionSplit.Count -eq 1) {
            $osVersion = ("{0}.0" -f $osVersionSplit[0])
        }
    }

    if ($serverOptions[$osSkuNumber]) {
        $installOption = $serverOptions[$osSkuNumber]
    }
    else {
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


function Update-SysprepAnswerFile($SysprepAnswerFile) {
    [xml]$SysprepXMLDocument = Get-Content -Path $SysprepAnswerFile -Encoding UTF8

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

#Get OS Information & Language
$Local:TimezoneLanguage = ([CultureInfo]::CurrentCulture).IetfLanguageTag
$Local:TimezoneOSversion = (Get-CimInstance Win32_OperatingSystem | Select-Object Version).Version

if ($TimezoneLanguage -eq "ja-JP") {
    if ($TimezoneOSversion -match "^5.*|^6.*") {
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
        Set-TimeZoneCompatible "Tokyo Standard Time"
        Start-Sleep -Seconds 5
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
    }
    elseif ($TimezoneOSversion -match "^10.*") {
        Get-TimeZone
        Set-TimeZone -Id "Tokyo Standard Time"
        Start-Sleep -Seconds 5
        Get-TimeZone
    }
    else {
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
    }
}
else {
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
}


#-----------------------------------------------------------------------------------------------------------------------
# Preparation for script execution
#-----------------------------------------------------------------------------------------------------------------------

Set-Variable -Name ScriptFullPath -Scope Script -Value ($MyInvocation.InvocationName)
Write-Log "# Script Execution 3rd-Bootstrap Script [START] : $ScriptFullPath"

New-Directory $BASE_DIR
New-Directory $TOOL_DIR
New-Directory $LOGS_DIR

Start-Transcript -Path "$TRANSCRIPT_LOG" -Append -Force

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

# Logging Amazon EC2 Hardware
Get-AmazonMachineInformation

# Logging Amazon EC2 attached EBS Volume List
if ($RoleName) {
    Get-EbsVolumesMappingInformation
}

# Logging Windows Server OS Parameter [AMI : Amazon Machine Image]
if ($RoleName) {
    Get-AmazonMachineImageInformation
}

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
}
elseif ($WindowsOSVersion -match "^10.*") {
    Get-Ec2LaunchVersion
}
else {
    Write-Log ("# [Warning] No Target - Windows NT Version Information : " + $WindowsOSVersion)
}

# Logging Windows Server OS Parameter [EC2 System Manager (SSM) Agent Information]
Get-Ec2SystemManagerAgentVersion

# Logging Windows Server OS Parameter [OS Settings]
Get-NetFirewallProfileInformation
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
Write-Log ("# [Amazon EC2 - Windows] Display Default Region at AWS Tools for Windows Powershell : " + (Get-DefaultAWSRegion).Name + " - " + (Get-DefaultAWSRegion).Region)

# Setting AWS Tools for Windows PowerShell (Additional)
#  Clear-AWSHistory
#  Set-AWSHistoryConfiguration -MaxCmdletHistory 512 -MaxServiceCallHistory 512 -RecordServiceRequests
#  Set-AWSResponseLogging -Level Always

# Get AMI Information
if ($RoleName) {
    Write-Log "# [Amazon EC2 - Windows] Get AMI Information"
    Get-EC2Image -ImageId $AmiId | ConvertTo-Json | Out-File "$LOGS_DIR\AWS-EC2_AMI-Information.txt" -Append -Force
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
#
# - ENA (Elastic Network Adapter)
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/enhanced-networking-ena.html
# - SR-IOV
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/sriov-networking.html
# - Xen(PV)
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/xen-drivers-overview.html
#
if ($RoleName) {
    if ($InstanceType -match "^e3.*|^f1.*|^g3.*|^i3.*|^p2.*|^p3.*|^r4.*|^x1.*|^x1e.*|^m4.16xlarge") {
        # Get EC2 Instance Attribute(Elastic Network Adapter Status)
        Write-Log "# [Amazon EC2 - Windows] Get EC2 Instance Attribute(Elastic Network Adapter Status)"
        Get-EC2Instance -Filter @{Name = "instance-id"; Values = $InstanceId} | Select-Object -ExpandProperty "Instances" | Out-File "$LOGS_DIR\AWS-EC2_ENI-ENA-Information.txt" -Append -Force
        # Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EnaSupport
    }
    elseif ($InstanceType -match "^c3.*|^c4.*|^d2.*|^i2.*|^r3.*|^m4.*") {
        # Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
        Write-Log "# [Amazon EC2 - Windows] Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
        Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute sriovNetSupport | Out-File "$LOGS_DIR\AWS-EC2_ENI-SRIOV-Information.txt" -Append -Force
    }
    else {
        Write-Log "# [Amazon EC2 - Windows] Instance type of None [Network Interface Performance Attribute]"
    }
}

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
#
# - EBS Optimized Instance
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/EBSOptimized.html
#
if ($RoleName) {
    if ($InstanceType -match "^c1.*|^c3.*|^c4.*|^d2.*|^e3.*|^f1.*|^g2.*|^g3.*|^i2.*|^i3.*|^m1.*|^m2.*|^m3.*|^m4.*|^p2.*|^p3.*|^r3.*|^r4.*|^x1.*|^x1e.*") {
        # Get EC2 Instance Attribute(EBS-optimized instance Status)
        Write-Log "# [Amazon EC2 - Windows] Get EC2 Instance Attribute(EBS-optimized instance Status)"
        Get-EC2InstanceAttribute -InstanceId $InstanceId -Attribute EbsOptimized | Out-File "$LOGS_DIR\AWS-EC2_EBS-Optimized-Instance-Information.txt" -Append -Force
    }
    else {
        Write-Log "# [Amazon EC2 - Windows] Instance type of None [Storage Interface Performance Attribute]"
    }
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [Windows OS Setting]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [Windows OS Setting]"

if ($WindowsOSLanguage) {
    if ($WindowsOSLanguage -eq "ja-JP") {
        if ($WindowsOSVersion -match "^6.1") {
            Write-Log "Windows Server OS Configuration [Windows OS Setting] : START"

            #----------------------------------------------------------------------------
            # [Unimplemented]
            #----------------------------------------------------------------------------

            Write-Log "Windows Server OS Configuration [Windows OS Setting] : COMPLETE"
        }
        elseif ($WindowsOSVersion -match "^6.2|^6.3|^10.0") {
            Write-Log "Windows Server OS Configuration [Windows OS Setting] : START"

            # Setting System Locale
            Write-Log ("# [Windows - OS Settings] Display Windows System Locale (Before) : " + (Get-WinSystemLocale).DisplayName + " - " + (Get-WinSystemLocale).Name)
            Set-WinSystemLocale -SystemLocale ja-JP
            Write-Log ("# [Windows - OS Settings] Display Windows System Locale (After) : " + (Get-WinSystemLocale).DisplayName + " - " + (Get-WinSystemLocale).Name)
            
            Write-Log ("# [Windows - OS Settings] Display Windows Home Location (Before) : " + (Get-WinHomeLocation).HomeLocation)
            Set-WinHomeLocation -GeoId 0x7A
            Write-Log ("# [Windows - OS Settings] Display Windows Home Location (After) : " + (Get-WinHomeLocation).HomeLocation)

            Write-Log ("# [Windows - OS Settings] Make the date and time [format] the same as the display language (Before) : " + (Get-WinCultureFromLanguageListOptOut))
            Set-WinCultureFromLanguageListOptOut -OptOut $False
            Write-Log ("# [Windows - OS Settings] Make the date and time [format] the same as the display language (After) : " + (Get-WinCultureFromLanguageListOptOut))

            # Setting Japanese UI Language
            Set-WinUILanguageOverride -Language ja-JP
            Write-Log ("# [Windows - OS Settings] Override display language (After) : " + (Get-WinUILanguageOverride).DisplayName + " - " + (Get-WinUILanguageOverride).Name)

            Write-Log "Windows Server OS Configuration [Windows OS Setting] : COMPLETE"
        }
        else {
            Write-Log ("# [Warning] No Target [OS-Language - Japanese] - Windows NT Version Information : " + $WindowsOSVersion)
        }
    }
    else {
        Write-Log ("# [Information] No Target [OS-Language - Japanese] - Windows Language Information : " + $WindowsOSLanguage)
    }
}
else {
    Write-Log "# [Warning] No Target - Windows OS Language"
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [Windows & Microsoft Update Setting]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [Windows & Microsoft Update Setting]"

# Change Windows Update Policy
Write-Log "# [Windows - OS Settings] Change Windows Update Policy (Before)"

if ($WindowsOSVersion -match "^5.*|^6.*") {
    
    # Get Windows Update Policy
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"

    # Change Windows Update Policy 
    $AUSettings = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings
    $AUSettings.NotificationLevel = 3      # Automatic Updates prompts users to approve updates & before downloading or installing
    # $AUSettings.ScheduledInstallationDay  = 1    # Every Sunday
    # $AUSettings.ScheduledInstallationTime = 3    # AM 3:00
    $AUSettings.IncludeRecommendedUpdates = $True  # Enabled
    $AUSettings.FeaturedUpdatesEnabled = $True  # Enabled

    # Save Windows Update Policy 
    $AUSettings.Save()

    Start-Sleep -Seconds 5

    # Get Windows Update Policy
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"

    Write-Log "# [Windows - OS Settings] Change Windows Update Policy (After)"
}
elseif ($WindowsOSVersion -match "^10.*") {

    #----------------------------------------------------------------------------
    # [not implemented yet]
    #----------------------------------------------------------------------------

    Write-Log "# [Windows - OS Settings] Change Windows Update Policy (After)"
}
else {
    Write-Log ("# [Warning] No Target - Windows NT Version Information : " + $WindowsOSVersion)
}


# Enable Microsoft Update
Write-Log "# [Windows - OS Settings] Change Microsoft Update Policy (Before)"

if ($WindowsOSVersion -match "^5.*|^6.*") {
    # Enable Microsoft Update
    $SMSettings = New-Object -ComObject "Microsoft.Update.ServiceManager" -Strict 
    $SMSettings.AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "")
    $SMSettings.Services

    Start-Sleep -Seconds 5

    Write-Log "# [Windows - OS Settings] Change Microsoft Update Policy (After)"
}
elseif ($WindowsOSVersion -match "^10.*") {

    #----------------------------------------------------------------------------
    # [not implemented yet]
    #----------------------------------------------------------------------------

    Write-Log "# [Windows - OS Settings] Change Microsoft Update Policy (After)"
}
else {
    Write-Log ("# [Warning] No Target - Windows NT Version Information : " + $WindowsOSVersion)
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [Folder Option Setting]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [Folder Option Setting]"

# Change Windows Folder Option Policy
Write-Log "# [Windows - OS Settings] Change Windows Folder Option Policy (Before)"
Set-Variable -Name FolderOptionRegistry -Option Constant -Scope Local -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

Get-ItemProperty -Path $FolderOptionRegistry

# [Check] Show hidden files, folders, or drives
Set-ItemProperty -Path $FolderOptionRegistry -Name 'Hidden' -Value '1' -Force
# [UnCheck] Hide extensions for known file types
Set-ItemProperty -Path $FolderOptionRegistry -Name 'HideFileExt' -Value '0' -Force
# [Check] Restore previous folders windows
New-ItemProperty -Path $FolderOptionRegistry -Name 'PersistBrowsers' -Value '1' -PropertyType "DWord" -Force

Get-ItemProperty -Path $FolderOptionRegistry

Write-Log "# [Windows - OS Settings] Change Windows Folder Option Policy (After)"


# Change Display Desktop Icon Policy
Write-Log "# [Windows - OS Settings] Change Display Desktop Icon Policy (Before)"
Set-Variable -Name DesktopIconRegistry -Option Constant -Scope Local -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
Set-Variable -Name DesktopIconRegistrySetting -Option Constant -Scope Local -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"

New-Item -Path $DesktopIconRegistry -Force 
New-Item -Path $DesktopIconRegistrySetting -Force 

#[CLSID] : My Computer
New-ItemProperty -Path $DesktopIconRegistrySetting -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0' -PropertyType "DWord" -Force
#[CLSID] : Control Panel
New-ItemProperty -Path $DesktopIconRegistrySetting -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value '0' -PropertyType "DWord" -Force
#[CLSID] : User's Files
New-ItemProperty -Path $DesktopIconRegistrySetting -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value '0' -PropertyType "DWord" -Force
#[CLSID] : Recycle Bin
New-ItemProperty -Path $DesktopIconRegistrySetting -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Value '0' -PropertyType "DWord" -Force
#[CLSID] : Network
New-ItemProperty -Path $DesktopIconRegistrySetting -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Value '0' -PropertyType "DWord" -Force

Get-ItemProperty -Path $DesktopIconRegistrySetting

Write-Log "# [Windows - OS Settings] Change Display Desktop Icon Policy (After)"


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [Network Connection Profile Setting]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [Network Connection Profile Setting]"

if ($WindowsOSVersion -match "^6.1") {
    Write-Log "Windows Server OS Configuration [Network Connection Profile Setting] : START"

    # Skip network location setting for pre-Vista operating systems
    if ([environment]::OSVersion.version.Major -lt 6) { return }

    # Skip network location setting if local machine is joined to a domain.
    if (1, 3, 4, 5 -contains (Get-WmiObject win32_computersystem).DomainRole) { return }

    # Get network connections
    $networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
    $connections = $networkListManager.GetNetworkConnections()

    # Set network location to Private for all networks
    $connections | % {$_.GetNetwork().SetCategory(1)}

    Write-Log "Windows Server OS Configuration [Network Connection Profile Setting] : COMPLETE"
}
elseif ($WindowsOSVersion -match "^6.2|^6.3|^10.0") {
    Write-Log "Windows Server OS Configuration [Network Connection Profile Setting] : START"

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

        Write-Log "Windows Server OS Configuration [Network Connection Profile Setting] : COMPLETE"
    }
    else {
        Write-Log ("# [Warning] No Target - Windows NT Version Information : " + $WindowsOSVersion)
    }
}
else {
    Write-Log ("# [Warning] No Target - Windows NT Version Information : " + $WindowsOSVersion)
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [Sysprep Answer File Setting]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [Sysprep Answer File Setting]"

# Update Sysprep Answer File
if ($WindowsOSLanguage) {
    if ($WindowsOSLanguage -eq "ja-JP") {
        # Update Sysprep Answer File
        if ($WindowsOSVersion -match "^5.*|^6.*") {
            # Sysprep Answer File
            Set-Variable -Name SysprepFile -Option Constant -Scope Script -Value "C:\Program Files\Amazon\Ec2ConfigService\sysprep2008.xml"
            
            Write-Log "# [Windows - OS Settings] Update Sysprep Answer File (Before)"
            
            if (Test-Path $SysprepFile) {
                Get-Content -Path $SysprepFile
                Update-SysprepAnswerFile $SysprepFile
                Get-Content -Path $SysprepFile
            }

            Write-Log "# [Windows - OS Settings] Update Sysprep Answer File (After)"

        }
        elseif ($WindowsOSVersion -match "^10.*") {
            # Sysprep Answer File
            Set-Variable -Name SysprepFile -Option Constant -Scope Script -Value "C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml"
            
            Write-Log "# [Windows - OS Settings] Update Sysprep Answer File (Before)"

            if (Test-Path $SysprepFile) {
                Get-Content -Path $SysprepFile
                Update-SysprepAnswerFile $SysprepFile
                Get-Content -Path $SysprepFile
            }
            
            Write-Log "# [Windows - OS Settings] Update Sysprep Answer File (After)"
        }
        else {
            Write-Log ("# [Warning] No Target [OS-Language - Japanese] - Windows NT Version Information : " + $WindowsOSVersion)
        }
    }
    else {
        Write-Log ("# [Information] No Target [OS-Language - Japanese] - Windows Language Information : " + $WindowsOSLanguage)
    }
}
else {
    Write-Log "# [Warning] No Target - Windows OS Language"
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [IPv6 Setting]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [IPv6 Setting]"

if ($WindowsOSVersion -match "^6.1") {
    Write-Log "Windows Server OS Configuration [IPv6 Setting] : START"

    # Display IPv6 Information
    netsh interface ipv6 show interface | Out-Default
    netsh interface ipv6 show prefixpolicies | Out-Default
    netsh interface ipv6 show global | Out-Default

    # Disable IPv6 Binding (ISATAP Interface)
    netsh interface ipv6 isatap set state disabled | Out-Default

    # Disable IPv6 Binding (6to4 Interface)
    netsh interface ipv6 6to4 set state disabled | Out-Default

    # Disable IPv6 Binding (Teredo Interface)
    netsh interface ipv6 set teredo disabled | Out-Default

    # Display IPv6 Information
    netsh interface ipv6 show interface | Out-Default
    netsh interface ipv6 show prefixpolicies | Out-Default
    netsh interface ipv6 show global | Out-Default

    Write-Log "Windows Server OS Configuration [IPv6 Setting] : COMPLETE"
}
elseif ($WindowsOSVersion -match "^6.2|^6.3|^10.0") {
    Write-Log "Windows Server OS Configuration [IPv6 Setting] : START"

    # Logging Windows Server OS Parameter [NetAdapter Binding Information]
    Get-NetAdapterBindingInformation

    # Disable IPv6 Binding
    if (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "Amazon Elastic Network Adapter" }) {
        Write-Log "# [Windows - OS Settings] Disable-NetAdapterBinding(IPv6) : Amazon Elastic Network Adapter"
        Disable-NetAdapterBinding -InterfaceDescription "Amazon Elastic Network Adapter" -ComponentID ms_tcpip6 -Confirm:$false
        Start-Sleep -Seconds 5
    }
    elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "Intel(R) 82599 Virtual Function" }) {
        Write-Log "# [Windows - OS Settings] Disable-NetAdapterBinding(IPv6) : Intel(R) 82599 Virtual Function"
        Disable-NetAdapterBinding -InterfaceDescription "Intel(R) 82599 Virtual Function" -ComponentID ms_tcpip6 -Confirm:$false
        Start-Sleep -Seconds 5
    }
    elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "AWS PV Network Device #0" }) {
        Write-Log "# [Windows - OS Settings] Disable-NetAdapterBinding(IPv6) : AWS PV Network Device"
        Disable-NetAdapterBinding -InterfaceDescription "AWS PV Network Device #0" -ComponentID ms_tcpip6 -Confirm:$false
        Start-Sleep -Seconds 5
    }
    else {
        Write-Log "# [Windows - OS Settings] Disable-NetAdapterBinding(IPv6) : No Target Device"
    }

    # Logging Windows Server OS Parameter [NetAdapter Binding Information]
    Get-NetAdapterBindingInformation

    Write-Log "Windows Server OS Configuration [IPv6 Setting] : COMPLETE"
}
else {
    Write-Log ("# [Warning] No Target - Windows NT Version Information : " + $WindowsOSVersion)
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [System PowerPlan]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [System PowerPlan]"

# Setting Paramter ["high performance" in Japanese]
$Word_HighPower_Base64 = "6auY44OR44OV44Kp44O844Oe44Oz44K5"                             # A string of "high performance" was Base64 encoded in Japanese
$Word_HighPower_Byte = [System.Convert]::FromBase64String($Word_HighPower_Base64)       # Conversion from base64 to byte sequence
$Word_HighPower_String = [System.Text.Encoding]::UTF8.GetString($Word_HighPower_Byte)   # To convert a sequence of bytes into a string of UTF-8 encoding

# Logging Windows Server OS Parameter [System Power Plan Information]
Get-PowerPlanInformation

# Change System PowerPlan (High Performance)
if (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq $Word_HighPower_String }) {
    Write-Log "# [Windows - OS Settings] PowerPlan : Change System PowerPlan - $Word_HighPower_String"
    (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq $Word_HighPower_String }).Activate()
    Start-Sleep -Seconds 5
}
elseif (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq "High performance" }) {
    Write-Log "# [Windows - OS Settings] PowerPlan : Change System PowerPlan - High performance"
    (Get-WmiObject -Name root\cimv2\power -Class Win32_PowerPlan -Filter 'ElementName = "High performance"').Activate()
    Start-Sleep -Seconds 5
}
else {
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
Start-Process -FilePath "$TOOL_DIR\AmazonSSMAgentSetup.exe" -ArgumentList @('ALLOWEC2INSTALL=YES', '/install', '/norstart', '/log C:\EC2-Bootstrap\Logs\APPS_AmazonSSMAgentSetup.log', '/quiet') -Wait | Out-Null

Start-Sleep -Seconds 10

Get-Service -Name AmazonSSMAgent

# Service Automatic Startup Setting (Amazon EC2 Systems Manager Agent)
$AmazonSSMAgentStatus = (Get-WmiObject Win32_Service -Filter "Name='AmazonSSMAgent'").StartMode

if ($AmazonSSMAgentStatus -ne "Auto") {
    Write-Log "# [Windows - OS Settings] [Amazon EC2 Systems Manager Agent] Service Startup Type : $AmazonSSMAgentStatus -> Auto"
    Set-Service -Name "AmazonSSMAgent" -StartupType Automatic

    Start-Sleep -Seconds 5

    $AmazonSSMAgentStatus = (Get-WmiObject Win32_Service -Filter "Name='AmazonSSMAgent'").StartMode
    Write-Log "# [Windows - OS Settings] [Amazon EC2 Systems Manager Agent] Service Startup Type : $AmazonSSMAgentStatus"
}

# Logging Windows Server OS Parameter [EC2 System Manager (SSM) Agent Information]
Get-Ec2SystemManagerAgentVersion

# Get Amazon SSM Agent Service Status
Restart-Service -Name AmazonSSMAgent
Start-Sleep -Seconds 30

# Get Service Status
Get-Service -Name AmazonSSMAgent

# View Log File
Get-Content -Path $SSMAgentLogFile

# Display Windows Server OS Parameter [EC2 System Manager (SSM) Agent Information]
if ($RoleName) {
    Start-Process -FilePath "C:\Program Files\Amazon\SSM\ssm-cli.exe" -ArgumentList "get-instance-information" -RedirectStandardOutput "$LOGS_DIR\APPS_EC2-SSM-AgentStatus.log" -RedirectStandardError "$LOGS_DIR\APPS_EC2-SSM-AgentStatusError.log"
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Install (Amazon Inspector Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Package Install System Utility (Amazon Inspector Agent)"

# Package Download System Utility (Amazon Inspector Agent)
# https://docs.aws.amazon.com/ja_jp/inspector/latest/userguide/inspector_agents-on-win.html
Write-Log "# Package Download System Utility (Amazon Inspector Agent)"
Invoke-WebRequest -Uri 'https://d1wk0tztpsntt1.cloudfront.net/windows/installer/latest/AWSAgentInstall.exe' -OutFile "$TOOL_DIR\AWSAgentInstall.exe"

# Package Install System Utility (Amazon Inspector Agent)
Write-Log "# Package Install System Utility (Amazon Inspector Agent)"
Start-Process -FilePath "$TOOL_DIR\AWSAgentInstall.exe" -ArgumentList @('/install', '/quiet', '/norestart', '/log C:\EC2-Bootstrap\Logs\APPS_AmazonInspecterAgentSetup.log') -Wait | Out-Null

Start-Sleep -Seconds 10

Get-Service -Name AWSAgent

# Service Automatic Startup Setting (Amazon Inspector Agent)
$AmazonInspectorAgentStatus = (Get-WmiObject Win32_Service -Filter "Name='AWSAgent'").StartMode

if ($AmazonInspectorAgentStatus -ne "Auto") {
    Write-Log "# [Windows - OS Settings] [AWS Inspector Agent] Service Startup Type : $AmazonInspectorAgentStatus -> Auto"
    Set-Service -Name "AWSAgent" -StartupType Automatic

    Start-Sleep -Seconds 5

    $AmazonInspectorAgentStatus = (Get-WmiObject Win32_Service -Filter "Name='AWSAgent'").StartMode
    Write-Log "# [Windows - OS Settings] [AWS Inspector Agent] Service Startup Type : $AmazonInspectorAgentStatus"
}

# Display Windows Server OS Parameter [Amazon Inspector Agent Information]
if ($RoleName) {
    cmd.exe /c "C:\Program Files\Amazon Web Services\AWS Agent\AWSAgentStatus.exe" 2>&1

    Start-Process -FilePath "C:\Program Files\Amazon Web Services\AWS Agent\AWSAgentStatus.exe" -RedirectStandardOutput "$LOGS_DIR\APPS_AmazonInspecterAgentStatus.log" -RedirectStandardError "$LOGS_DIR\APPS_AmazonInspecterAgentStatusError.log"
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Install (Amazon EC2 Elastic GPU Software)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Package Install System Utility (Amazon EC2 Elastic GPU Software)"

# Initialize Parameter
Set-Variable -Name ElasticGpuId -Scope Script -Value ($Null)
Set-Variable -Name ElasticGpuResponse -Scope Script -Value ($Null)
Set-Variable -Name ElasticGpuResponseError -Scope Script -Value ($Null)

# Check Amazon EC2 Elastic GPUs Support InstanceType
# https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/elastic-gpus.html
Write-Log "# Check Amazon EC2 Elastic GPUs Support InstanceType"
if ($InstanceType -match "^c3.*|^c4.*|^m3.*|^m4.*|^r3.*|^r4.*|^x1.*|^d2.*|^i3.*|^t2.medium|^t2.large|^t2.xlarge|^t2.2xlarge") {
    # Amazon EC2 Elastic GPUs Support InstanceType
    Write-Log "# [AWS - EC2-ElasticGPU] InstanceType : $InstanceType"
}
else {
    # Amazon EC2 Elastic GPUs Support InstanceType (None)
    Write-Log ("# [AWS - EC2-ElasticGPU] InstanceType : " + $InstanceType + " - Not Suppoort Instance Type")
}

# Check Amazon EC2 Elastic GPU ID
$ElasticGpuResponseError = try { $ElasticGpuResponse = Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/elastic-gpus/associations" } catch {$_.Exception.Response.StatusCode.Value__}
if ([String]::IsNullOrEmpty($ElasticGpuResponseError)) {
    # The Amazon EC2 Elastic GPU is attached
    Write-Log "# [AWS - EC2-ElasticGPU] Elastic GPU is attached"
    Set-Variable -Name ElasticGpuId -Option Constant -Scope Script -Value (Invoke-Restmethod -Uri "http://169.254.169.254/latest/meta-data/elastic-gpus/associations")
}
else {
    # The Amazon EC2 Elastic GPU is not attached
    Write-Log "# [AWS - EC2-ElasticGPU] Elastic GPU is not attached"
}

# Check Amazon EC2 Elastic GPU Information
if ($ElasticGpuId -match "^egpu-*") {
    Write-Log "# Check Amazon EC2 Elastic GPU Information"

    # Get EC2 Instance attached Elastic GPU Information
    Set-Variable -Name ElasticGpuInformation -Scope Script -Value ((Invoke-WebRequest "http://169.254.169.254/latest/meta-data/elastic-gpus/associations/${ElasticGpuId}").content | ConvertFrom-Json)
    Set-Variable -Name ElasticGpuType -Scope Script -Value ($ElasticGpuInformation.elasticGpuType)
    Set-Variable -Name ElasticGpuEniIpAddress -Scope Script -Value ($ElasticGpuInformation.connectionConfig.ipv4Address)
    
    # Logging Amazon EC2 Elastic GPU Information
    Write-Log "# [AWS - EC2-ElasticGPU] ElasticGpuId : $ElasticGpuId"
    Write-Log "# [AWS - EC2-ElasticGPU] ElasticGpuType : $ElasticGpuType"
    Write-Log "# [AWS - EC2-ElasticGPU] ElasticGpuEniIpAddress : $ElasticGpuEniIpAddress"

    $ElasticGpuInformation | ConvertTo-Json | Out-File "$LOGS_DIR\AWS-EC2_ElasticGPU-Information.txt" -Append -Force

    if ($RoleName) {
        Set-Variable -Name ElasticGpuEniInsterface -Scope Script -Value (Get-EC2NetworkInterface | Where-Object { $_.RequesterId -eq "amazon-elasticgpus" } | Where-Object { $_.PrivateIpAddress -eq ${ElasticGpuEniIpAddress} })
        Set-Variable -Name ElasticGpuEniId -Scope Script -Value ($ElasticGpuEniInsterface.NetworkInterfaceId)

        Write-Log "# [AWS - EC2-ElasticGPU] ElasticGpuEniId : $ElasticGpuEniId"

        $ElasticGpuEniInsterface | ConvertTo-Json | Out-File "$LOGS_DIR\AWS-EC2_ElasticGPU_ENI-Information.txt" -Append -Force
    }

    # Package Download System Utility (Amazon EC2 Elastic GPU Software)
    # https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/working-with-elastic-gpus.html
    Write-Log "# Package Download System Utility (Amazon EC2 Elastic GPU Software)"
    Invoke-WebRequest -Uri 'http://ec2-elasticgpus.s3-website-us-east-1.amazonaws.com/latest' -OutFile "$TOOL_DIR\EC2ElasticGPUs_Manager.msi"

    # Package Install System Utility (Amazon EC2 Elastic GPU Software)
    Write-Log "# Package Install System Utility (Amazon EC2 Elastic GPU Software)"
    Start-Process "msiexec.exe" -Wait -ArgumentList @("/i $TOOL_DIR\EC2ElasticGPUs_Manager.msi", "/qn", "/L*v $LOGS_DIR\APPS_EC2ElasticGPUs_Manager.log")
    Start-Sleep -Seconds 10

    # Setting Application Path (Amazon EC2 Elastic GPU Software)
    [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\Amazon\EC2ElasticGPUs\manager\", [EnvironmentVariableTarget]::Machine)
 
    # Service Automatic Startup Setting (Amazon EC2 Elastic GPU Manager)
    Get-Service -Name EC2ElasticGPUs_Manager

    $EC2ElasticGPUs_ManagerStatus = (Get-WmiObject Win32_Service -Filter "Name='EC2ElasticGPUs_Manager'").StartMode

    if ($EC2ElasticGPUs_ManagerStatus -ne "Auto") {
        Write-Log "# [Windows - OS Settings] [Amazon EC2 Elastic GPU Manager] Service Startup Type : $EC2ElasticGPUs_ManagerStatus -> Auto"
        Set-Service -Name "EC2ElasticGPUs_Manager" -StartupType Automatic

        Start-Sleep -Seconds 5

        $EC2ElasticGPUs_ManagerStatus = (Get-WmiObject Win32_Service -Filter "Name='EC2ElasticGPUs_Manager'").StartMode
        Write-Log "# [Windows - OS Settings] [Amazon EC2 Elastic GPU Manager] Service Startup Type : $EC2ElasticGPUs_ManagerStatus"
    }

    # Display Windows Server OS Parameter [Amazon EC2 Elastic GPU Manager Information]
    cmd.exe /c "C:\Program Files\Amazon\EC2ElasticGPUs\manager\egcli.exe" 2>&1

    Start-Process -FilePath "C:\Program Files\Amazon\EC2ElasticGPUs\manager\egcli.exe" -RedirectStandardOutput "$LOGS_DIR\APPS_AmazonEC2ElasticGpuManagerStatus.log" -RedirectStandardError "$LOGS_DIR\APPS_AmazonEC2ElasticGpuManagerStatusError.log"
}


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
#  [Amazon EC2 G2 Instance Family]
#  NVIDIA GRID K520 GPU Parameter
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1
#    -> GRID : 9
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=9
#    -> [psid] GRID Series : 94
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=94
#    -> [pfid] GRID K520 : 704
#
#  [Amazon EC2 G3 Instance Family]
#  NVIDIA Tesla M60
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1
#    -> Tesla : 7
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=7
#    -> [psid] M-Class : 75
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=75
#    -> [pfid] Tesla M60 : 783
#
#  [Amazon EC2 P2 Instance Family]
#  NVIDIA Tesla K80
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1
#    -> Tesla : 7
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=7
#    -> [psid] K-Series : 91
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=91
#    -> [pfid] Tesla K80 : 762
#
#  [Amazon EC2 P3 Instance Family]
#  NVIDIA Tesla V100
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1
#    -> Tesla : 7
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=7
#    -> [psid] V-Series : 105
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=105
#    -> [pfid] Tesla V100 : 857
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

Write-Log "# Check Amazon EC2 G2 Instance Family"

# Package Download NVIDIA GRID K520 GPU Driver (for Amazon EC2 G2 Instance Family)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/accelerated-computing-instances.html
if ($InstanceType -match "^g2.*") {
    Write-Log "# Package Download NVIDIA GRID K520 GPU Driver (for Amazon EC2 G2 Instance Family)"
    if ($WindowsOSVersion) {
        if ($WindowsOSVersion -eq "6.1") {
            # [Windows Server 2008 R2]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=21&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/GRID/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "quadro-tesla-grid-winserv2008-2008r2-2012-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID K520 GPU Driver URL : " + $K520_driverurl)
            Invoke-WebRequest -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2008R2.exe"
        }
        elseif ($WindowsOSVersion -eq "6.2") {
            # [Windows Server 2012]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=32&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/GRID/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "quadro-tesla-grid-winserv2008-2008r2-2012-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID K520 GPU Driver URL : " + $K520_driverurl)
            Invoke-WebRequest -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2012.exe"
        }
        elseif ($WindowsOSVersion -eq "6.3") {
            # [Windows Server 2012 R2]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/GRID/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "quadro-tesla-grid-winserv2008-2008r2-2012-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID K520 GPU Driver URL : " + $K520_driverurl)
            Invoke-WebRequest -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2012R2.exe"
        }
        elseif ($WindowsOSVersion -eq "10.0") {
            # [Windows Server 2016]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=74&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/GRID/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "-quadro-winserv-2016-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID K520 GPU Driver URL : " + $K520_driverurl)
            Invoke-WebRequest -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2016.exe"
        }
        else {
            # [No Target Server OS]
            Write-Log ("# [Information] [NVIDIA GRID K520 GPU Driver] No Target Server OS Version : " + $WindowsOSVersion)
        }
    }
    else {
        # [Undefined Server OS]
        Write-Log "# [Warning] [NVIDIA GRID K520 GPU Driver] Undefined Server OS"
    }
}


Write-Log "# Check Amazon EC2 G3 Instance Family"

# Package Download NVIDIA Tesla M60 GPU Driver (for Amazon EC2 G3 Instance Family)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/accelerated-computing-instances.html
if ($InstanceType -match "^g3.*") {
    Write-Log "# Package Download NVIDIA GRID M60 GPU Driver (for Amazon EC2 G3 Instance Family)"
    if ($WindowsOSVersion) {
        if ($WindowsOSVersion -eq "6.1") {
            # [Windows Server 2008 R2]
            $M60_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=75&pfid=783&osid=21&lid=1&whql=1&lang=en-us&ctk=0'
            $M60_driverversion = $($M60_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $M60_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${M60_driverversion} + "/" + ${M60_driverversion} + "-tesla-desktop-winserver2008-2012r2-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID M60 GPU Driver URL : " + $M60_driverurl)
            Invoke-WebRequest -Uri $M60_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-M60-GPU-Driver_for_WindowsServer2008R2.exe"
        }
        elseif ($WindowsOSVersion -eq "6.3") {
            # [Windows Server 2012 R2]
            $M60_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=75&pfid=783&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $M60_driverversion = $($M60_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $M60_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${M60_driverversion} + "/" + ${M60_driverversion} + "-tesla-desktop-winserver2008-2012r2-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID M60 GPU Driver URL : " + $M60_driverurl)
            Invoke-WebRequest -Uri $M60_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-M60-GPU-Driver_for_WindowsServer2012R2.exe"
        }
        elseif ($WindowsOSVersion -eq "10.0") {
            # [Windows Server 2016]
            $M60_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=75&pfid=783&osid=74&lid=1&whql=1&lang=en-us&ctk=0'
            $M60_driverversion = $($M60_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $M60_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${M60_driverversion} + "/" + ${M60_driverversion} + "-tesla-desktop-winserver2016-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID M60 GPU Driver URL : " + $M60_driverurl)
            Invoke-WebRequest -Uri $M60_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-M60-GPU-Driver_for_WindowsServer2016.exe"
        }
        else {
            # [No Target Server OS]
            Write-Log ("# [Information] [NVIDIA GRID M60 GPU Driver] No Target Server OS Version : " + $WindowsOSVersion)
        }
    }
    else {
        # [Undefined Server OS]
        Write-Log "# [Warning] [NVIDIA GRID M60 GPU Driver] Undefined Server OS"
    }
}


Write-Log "# Check Amazon EC2 P2 Instance Family"

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
            Write-Log ("# [Information] Package Download NVIDIA Tesla K80 GPU Driver URL : " + $K80_driverurl)
            Invoke-WebRequest -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2008R2.exe"
        }
        elseif ($WindowsOSVersion -eq "6.3") {
            # [Windows Server 2012 R2]
            $K80_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=91&pfid=762&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $K80_driverversion = $($K80_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K80_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K80_driverversion} + "/" + ${K80_driverversion} + "-tesla-desktop-winserver2008-2012r2-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA Tesla K80 GPU Driver URL : " + $K80_driverurl)
            Invoke-WebRequest -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2012R2.exe"
        }
        elseif ($WindowsOSVersion -eq "10.0") {
            # [Windows Server 2016]
            $K80_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=91&pfid=762&osid=74&lid=1&whql=1&lang=en-us&ctk=0'
            $K80_driverversion = $($K80_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K80_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K80_driverversion} + "/" + ${K80_driverversion} + "-tesla-desktop-winserver2016-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA Tesla K80 GPU Driver URL : " + $K80_driverurl)
            Invoke-WebRequest -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2016.exe"
        }
        else {
            # [No Target Server OS]
            Write-Log ("# [Information] [NVIDIA Tesla K80 GPU Driver] No Target Server OS Version : " + $WindowsOSVersion)
        }
    }
    else {
        # [Undefined Server OS]
        Write-Log "# [Warning] [NVIDIA Tesla K80 GPU Driver] Undefined Server OS"
    }
}


Write-Log "# Check Amazon EC2 P3 Instance Family"

# Package Download NVIDIA Tesla V100 GPU Driver (for Amazon EC2 P3 Instance Family)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/accelerated-computing-instances.html
if ($InstanceType -match "^p3.*") {
    Write-Log "# Package Download NVIDIA Tesla V100 GPU Driver (for Amazon EC2 P3 Instance Family)"
    if ($WindowsOSVersion) {
        if ($WindowsOSVersion -eq "6.3") {
            # [Windows Server 2012 R2]
            $V100_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=105&pfid=857&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $V100_driverversion = $($V100_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $V100_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${V100_driverversion} + "/" + ${V100_driverversion} + "-tesla-desktop-2012r2-64bit-international.exe"
            Write-Log ("# [Information] Package Download NVIDIA Tesla V100 GPU Driver URL : " + $V100_driverurl)
            Invoke-WebRequest -Uri $V100_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-V100-GPU-Driver_for_WindowsServer2012R2.exe"
        }
        elseif ($WindowsOSVersion -eq "10.0") {
            # [Windows Server 2016]
            $V100_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=105&pfid=857&osid=74&lid=1&whql=1&lang=en-us&ctk=0'
            $V100_driverversion = $($V100_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $V100_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${V100_driverversion} + "/" + ${V100_driverversion} + "-tesla-desktop-winserver2016-international.exe"
            Write-Log ("# [Information] Package Download NVIDIA Tesla V100 GPU Driver URL : " + $V100_driverurl)
            Invoke-WebRequest -Uri $V100_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-V100-GPU-Driver_for_WindowsServer2016.exe"
        }
        else {
            # [No Target Server OS]
            Write-Log ("# [Information] [NVIDIA Tesla V100 GPU Driver] No Target Server OS Version : " + $WindowsOSVersion)
        }
    }
    else {
        # [Undefined Server OS]
        Write-Log "# [Warning] [NVIDIA Tesla V100 GPU Driver] Undefined Server OS"
    }
}


Write-Log "# Check Amazon EC2 G2 & G3 & P2 & P3 Instance Family"

# Package Download NVIDIA GPUProfiler (for Amazon EC2 G2/G3/P2/P3 Instance Family)
# https://github.com/JeremyMain/GPUProfiler
if ($InstanceType -match "^g2.*|^g3.*|^p2.*|^p3.*") {
    Write-Log "# Package Download NVIDIA GPUProfiler (for Amazon EC2 G2/G3/P2 Instance Family)"
    Invoke-WebRequest -Uri 'https://github.com/JeremyMain/GPUProfiler/releases/download/v1.05/GPUProfiler_1.05-x64.zip' -OutFile "$TOOL_DIR\GPUProfiler_1.05-x64.zip"
}



#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Storage & Network Driver)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Download (Storage & Network Driver)"

# Package Download Amazon Windows Paravirtual Drivers
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/xen-drivers-overview.html
Write-Log "# Package Download Amazon Windows Paravirtual Drivers"
Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/Drivers/AWSPVDriverSetup.zip' -OutFile "$TOOL_DIR\AWS-StorageNetworkDriver-AWSPVDriverSetup.zip"

# Package Download Amazon Elastic Network Adapter Driver
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/enhanced-networking-ena.html
Write-Log "# Package Download Amazon Elastic Network Adapter Driver"
Invoke-WebRequest -Uri 'http://ec2-windows-drivers.s3.amazonaws.com/ENA.zip' -OutFile "$TOOL_DIR\AWS-NetworkDriver-ENA.zip"

# Package Download Intel Network Driver
if ($WindowsOSVersion) {
    if ($WindowsOSVersion -eq "6.1") {
        # [Windows Server 2008 R2]
        # https://downloadcenter.intel.com/ja/download/18725/
        # Package Download Intel Network Driver (Windows Server 2008 R2)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2008 R2)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/18725/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\Intel-NetworkDriver-PROWinx64_For_WindowsServer2008R2.exe"
    }
    elseif ($WindowsOSVersion -eq "6.2") {
        # [Windows Server 2012]
        # https://downloadcenter.intel.com/ja/download/21694/
        # Package Download Intel Network Driver (Windows Server 2012)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2012)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/21694/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\Intel-NetworkDriver-PROWinx64_For_WindowsServer2012.exe"
    }
    elseif ($WindowsOSVersion -eq "6.3") {
        # [Windows Server 2012 R2]
        # https://downloadcenter.intel.com/ja/download/23073/
        # Package Download Intel Network Driver (Windows Server 2012 R2)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2012 R2)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/23073/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\Intel-NetworkDriver-PROWinx64_For_WindowsServer2012R2.exe"
    }
    elseif ($WindowsOSVersion -eq "10.0") {
        # [Windows Server 2016]
        # https://downloadcenter.intel.com/ja/download/26092/
        # Package Download Intel Network Driver (Windows Server 2016)
        Write-Log "# Package Download Intel Network Driver (Windows Server 2016)"
        Invoke-WebRequest -Uri 'https://downloadmirror.intel.com/26092/eng/PROWinx64.exe' -OutFile "$TOOL_DIR\Intel-NetworkDriver-PROWinx64_For_WindowsServer2016.exe"
    }
    else {
        # [No Target Server OS]
        Write-Log ("# [Information] [Intel Network Driver] No Target Server OS Version : " + $WindowsOSVersion)
    }
}
else {
    # [Undefined Server OS]
    Write-Log "# [Warning] [Intel Network Driver] Undefined Server OS"
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Installation (Application)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Installation (Application)"

# Package Install Modern Web Browser (Google Chrome 64bit Edition)
Write-Log "# Package Download Modern Web Browser (Google Chrome 64bit Edition)"
Invoke-WebRequest -Uri 'https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi' -OutFile "$TOOL_DIR\googlechrome.msi"
Write-Log "# Package Install Modern Web Browser (Google Chrome 64bit Edition)"
Start-Process "msiexec.exe" -Wait -ArgumentList @("/i $TOOL_DIR\googlechrome.msi", "/qn", "/L*v $LOGS_DIR\APPS_ChromeSetup.log")

#---------------------------------------------------------------
# [Caution : Finally the installation process]
#---------------------------------------------------------------

# Package Install Text Editor (Visual Studio Code 64bit Edition)
Write-Log "# Package Download Text Editor (Visual Studio Code 64bit Edition)"
Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=852157' -OutFile "$TOOL_DIR\VSCodeSetup-x64.exe"
Write-Log "# Package Install Text Editor (Visual Studio Code 64bit Edition)"
Start-Process -FilePath "$TOOL_DIR\VSCodeSetup-x64.exe" -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/LOG=C:\EC2-Bootstrap\Logs\APPS_VSCodeSetup.log") | Out-Null
Start-Sleep -Seconds 180


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

# Package Download System Utility (Tera Term)
# https://ja.osdn.net/projects/ttssh2/
Write-Log "# Package Download System Utility (Tera Term)"
Invoke-WebRequest -Uri 'http://dforest.watch.impress.co.jp/library/u/utf8teraterm/10868/teraterm-4.96.exe' -OutFile "$TOOL_DIR\teraterm-4.96.exe"
# Invoke-WebRequest -Uri 'https://ja.osdn.net/dl/ttssh2/teraterm-4.96.exe' -OutFile "$TOOL_DIR\teraterm-4.96.exe"

# Package Download System Utility (SQL Server Management Studio [SSMS])
# https://docs.microsoft.com/ja-jp/sql/ssms/download-sql-server-management-studio-ssms
# Write-Log "# Package Download System Utility (SQL Server Management Studio [SSMS])"
# Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=858904' -OutFile "$TOOL_DIR\SSMS-Setup-JPN.exe"

# Package Download System Utility (EC2Config)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/UsingConfig_Install.html
if ($WindowsOSVersion -match "^5.*|^6.*") {
    Write-Log "# Package Download System Utility (EC2Config)"
    Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Config/EC2Install.zip' -OutFile "$TOOL_DIR\EC2Install.zip"
}

# Package Download System Utility (EC2Launch)
# http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2launch.html
if ($WindowsOSVersion -match "^10.*") {
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

# Package Download System Utility (AWS CloudFormation Helper Scripts)
# http://docs.aws.amazon.com/ja_jp/AWSCloudFormation/latest/UserGuide/cfn-helper-scripts-reference.html
Write-Log "# Package Download System Utility (AWS CloudFormation Helper Scripts)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-win64-latest.msi' -OutFile "$TOOL_DIR\aws-cfn-bootstrap-win64-latest.msi"

# Package Download System Utility (AWS Directory Service PortTest Application)
# http://docs.aws.amazon.com/ja_jp/workspaces/latest/adminguide/connect_verification.html
Write-Log "# Package Download System Utility (AWS Directory Service PortTest Application)"
Invoke-WebRequest -Uri 'http://docs.aws.amazon.com/directoryservice/latest/admin-guide/samples/DirectoryServicePortTest.zip' -OutFile "$TOOL_DIR\DirectoryServicePortTest.zip"

# Package Download System Utility (EC2Rescue)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/Windows-Server-EC2Rescue.html
Write-Log "# Package Download System Utility (EC2Rescue)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ec2rescue/windows/EC2Rescue_latest.zip' -OutFile "$TOOL_DIR\EC2Rescue_latest.zip"

# Package Download System Utility (AWSLogCollector)
# 
Write-Log "# Package Download System Utility (AWSLogCollector)"
Invoke-WebRequest -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/Scripts/AWSLogCollector.zip' -OutFile "$TOOL_DIR\AWSLogCollector.zip"

# Package Download System Utility (AWS Diagnostics for Windows Server)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/Windows-Server-Diagnostics.html
Write-Log "# Package Download System Utility (AWS Diagnostics for Windows Server)"
Invoke-WebRequest -Uri 'https://s3.amazonaws.com/ec2-downloads-windows/AWSDiagnostics/AWSDiagnostics.zip' -OutFile "$TOOL_DIR\AWSDiagnostics.zip"


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

    }
    elseif ($WindowsOSVersion -eq "6.2") {
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

    }
    elseif ($WindowsOSVersion -eq "6.3") {
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

    }
    elseif ($WindowsOSVersion -eq "10.0") {
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

    }
    else {
        # [No Target Server OS]
        Write-Log ("# [Information] [Save Userdata Script, Bootstrap Script, Logging Data Files] No Target Windows NT OS Version : " + $WindowsOSVersion)
    }
}
else {
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
# Hostname rename [#Exclude Amazon WorkSpaces, Amazon AppStream 2.0]
#-----------------------------------------------------------------------------------------------------------------------

# Setting Hostname
Set-Variable -Name Hostname -Option Constant -Scope Local -Value ($PrivateIp.Replace(".", "-"))
Rename-Computer $Hostname -Force


#-----------------------------------------------------------------------------------------------------------------------
# Instance Reboot
#-----------------------------------------------------------------------------------------------------------------------

# EC2 Instance Reboot
Restart-Computer -Force
