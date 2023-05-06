########################################################################################################################
#.SYNOPSIS
#
#   Amazon EC2 Bootstrap Script - 3rd Bootstrap (Regacy)
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
########################################################################################################################

#-------------------------------------------------------------------------------
# Information of Windows Server
#  - Windows Server
#    https://docs.microsoft.com/ja-jp/windows-server/windows-server
#
#  - Windows Server on AWS
#    https://aws.amazon.com/jp/windows/
#    http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/
#
#  - Windows Server AMI
#    https://aws.amazon.com/jp/windows/resources/amis/
#    https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/windows-ami-version-history.html
#-------------------------------------------------------------------------------


#-----------------------------------------------------------------------------------------------------------------------
# User Define Parameter
#-----------------------------------------------------------------------------------------------------------------------

# Set Script Parameter for Script (User Defined)
Set-Variable -Name FLAG_APP_INSTALL -Option Constant -Scope Script -Value "$TRUE"
Set-Variable -Name FLAG_APP_DOWNLOAD -Option Constant -Scope Script -Value "$TRUE"

# Set Script Parameter for Directory Name (User Defined)
Set-Variable -Name BASE_DIR -Option Constant -Scope Script "$Env:SystemDrive\EC2-Bootstrap"
Set-Variable -Name TOOL_DIR -Option Constant -Scope Script "$BASE_DIR\Tools"
Set-Variable -Name LOGS_DIR -Option Constant -Scope Script "$BASE_DIR\Logs"
Set-Variable -Name TEMP_DIR -Option Constant -Scope Script "$Env:SystemRoot\Temp"

# Set Script Parameter for Log File Name (User Defined)
Set-Variable -Name USERDATA_LOG -Option Constant -Scope Script "$TEMP_DIR\userdata.log"
Set-Variable -Name TRANSCRIPT_LOG -Option Constant -Scope Script "$LOGS_DIR\userdata-transcript.log"

# Set System Config File (sysprep)
Set-Variable -Name EC2Launchv2SysprepFile -Option Constant -Scope Script -Value "C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml"
Set-Variable -Name EC2LaunchSysprepFile -Option Constant -Scope Script -Value "C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml"
Set-Variable -Name EC2ConfigSysprepFile -Option Constant -Scope Script -Value "C:\Program Files\Amazon\Ec2ConfigService\sysprep2008.xml"

# Set System & Application Config File (System Defined : Windows Server 2016, 2019)
Set-Variable -Name EC2LaunchFile -Option Constant -Scope Script -Value "C:\ProgramData\Amazon\EC2-Windows\Launch\Config\LaunchConfig.json"

# Set System & Application Config File (System Defined : Windows Server 2008 R2, 2012, 2012 R2)
Set-Variable -Name EC2ConfigFile -Option Constant -Scope Script -Value "C:\Program Files\Amazon\Ec2ConfigService\Settings\Config.xml"

# Set System & Application Config File (System Defined : Windows Server 2008 R2, 2012, 2012 R2, 2016, 2019)
Set-Variable -Name EC2Launchv2File -Option Constant -Scope Script -Value "C:\ProgramData\Amazon\EC2Launch\config\agent-config.yml"

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
        Start-Sleep -Seconds 1
    }
} # end function New-Directory


function Convert-SCSITargetIdToDeviceName {
    param([int]$SCSITargetId)
    If ($SCSITargetId -eq 0) {
        return "sda1"
    }
    $deviceName = "xvd"
    If ($SCSITargetId -gt 25) {
        $deviceName += [char](0x60 + [int]($SCSITargetId / 26))
    }
    $deviceName += [char](0x61 + $SCSITargetId % 26)
    return $deviceName
} # end Convert-SCSITargetIdToDeviceName


function Set-TimeZoneCompatible {
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
#    - Convert-SCSITargetIdToDeviceName
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


function Get-CustomizeEc2InstanceMetadata {
    #--------------------------------------------------------------------------------------
    #  Get AWS Instance MetaData Service (IMDS v1, v2)
    #   https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/configuring-instance-metadata-service.html
    #   https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/instancedata-data-retrieval.html
    #--------------------------------------------------------------------------------------

    # Set Initialize Parameter
    Set-Variable -Name Token -Scope Script -Value ($Null)
    Set-Variable -Name Az -Scope Script -Value ($Null)
    Set-Variable -Name AzId -Scope Script -Value ($Null)
    Set-Variable -Name Region -Scope Script -Value ($Null)
    Set-Variable -Name InstanceId -Scope Script -Value ($Null)
    Set-Variable -Name InstanceType -Scope Script -Value ($Null)
    Set-Variable -Name PrivateIp -Scope Script -Value ($Null)
    Set-Variable -Name AmiId -Scope Script -Value ($Null)
    Set-Variable -Name RoleArn -Scope Script -Value ($Null)
    Set-Variable -Name RoleName -Scope Script -Value ($Null)
    Set-Variable -Name StsCredential -Scope Script -Value ($Null)
    Set-Variable -Name StsAccessKeyId -Scope Script -Value ($Null)
    Set-Variable -Name StsSecretAccessKey -Scope Script -Value ($Null)
    Set-Variable -Name StsToken -Scope Script -Value ($Null)
    Set-Variable -Name AwsAccountId -Scope Script -Value ($Null)

    # Getting an Instance Metadata Service v2 (IMDS v2) token
    $Token = $(Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -Method PUT 'http://169.254.169.254/latest/api/token')

    if ($Token) {
        #-----------------------------------------------------------------------
        # Retrieving Metadata Using the Instance Metadata Service v2 (IMDS v2)
        #-----------------------------------------------------------------------
        Write-Log "# [AWS - EC2] Retrieving Metadata Using the Instance Metadata Service v2 (IMDS v2)"

        # AWS Instance Metadata
        Set-Variable -Name Az -Scope Script -Value (Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/meta-data/placement/availability-zone")
        Set-Variable -Name AzId -Scope Script -Value (Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/meta-data/placement/availability-zone-id")
        Set-Variable -Name Region -Scope Script -Value (Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/meta-data/placement/region")
        Set-Variable -Name InstanceId -Scope Script -Value (Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/meta-data/instance-id")
        Set-Variable -Name InstanceType -Scope Script -Value (Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/meta-data/instance-type")
        Set-Variable -Name PrivateIp -Scope Script -Value (Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/meta-data/local-ipv4")
        Set-Variable -Name AmiId -Scope Script -Value (Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/meta-data/ami-id")

        # IAM Role & STS Information
        Set-Variable -Name RoleArn -Scope Script -Value ((Invoke-WebRequest -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/meta-data/iam/info" -UseBasicParsing) | ConvertFrom-Json).InstanceProfileArn
        Set-Variable -Name RoleName -Scope Script -Value ($RoleArn -split "/" | Select-Object -Index 1)

        if ($RoleName) {
            Set-Variable -Name StsCredential -Scope Script -Value ((Invoke-WebRequest -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri ("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + $RoleName) -UseBasicParsing) | ConvertFrom-Json)
            Set-Variable -Name StsAccessKeyId -Scope Script -Value $StsCredential.AccessKeyId
            Set-Variable -Name StsSecretAccessKey -Scope Script -Value $StsCredential.SecretAccessKey
            Set-Variable -Name StsToken -Scope Script -Value $StsCredential.Token
        }

        # AWS Account ID
        Set-Variable -Name AwsAccountId -Scope Script -Value ((Invoke-WebRequest -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/dynamic/instance-identity/document" -UseBasicParsing) | ConvertFrom-Json).accountId
    }
    else {
        #-----------------------------------------------------------------------
        # Retrieving Metadata Using the Instance Metadata Service v1 (IMDS v1)
        #-----------------------------------------------------------------------
        Write-Log "# [AWS - EC2] Retrieving Metadata Using the Instance Metadata Service v1 (IMDS v1)"

        # AWS Instance Metadata
        Set-Variable -Name Az -Scope Script -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/placement/availability-zone")
        Set-Variable -Name AzId -Scope Script -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/placement/availability-zone-id")
        Set-Variable -Name Region -Scope Script -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/placement/region")
        Set-Variable -Name InstanceId -Scope Script -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/instance-id")
        Set-Variable -Name InstanceType -Scope Script -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/instance-type")
        Set-Variable -Name PrivateIp -Scope Script -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/local-ipv4")
        Set-Variable -Name AmiId -Scope Script -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/ami-id")

        # IAM Role & STS Information
        Set-Variable -Name RoleArn -Scope Script -Value ((Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/iam/info" -UseBasicParsing) | ConvertFrom-Json).InstanceProfileArn
        Set-Variable -Name RoleName -Scope Script -Value ($RoleArn -split "/" | Select-Object -Index 1)

        if ($RoleName) {
            Set-Variable -Name StsCredential -Scope Script -Value ((Invoke-WebRequest -Uri ("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + $RoleName) -UseBasicParsing) | ConvertFrom-Json)
            Set-Variable -Name StsAccessKeyId -Scope Script -Value $StsCredential.AccessKeyId
            Set-Variable -Name StsSecretAccessKey -Scope Script -Value $StsCredential.SecretAccessKey
            Set-Variable -Name StsToken -Scope Script -Value $StsCredential.Token
        }

        # AWS Account ID
        Set-Variable -Name AwsAccountId -Scope Script -Value ((Invoke-WebRequest -Uri "http://169.254.169.254/latest/dynamic/instance-identity/document" -UseBasicParsing) | ConvertFrom-Json).accountId
    }

    # Logging AWS Instance Metadata
    Write-Log "# [AWS - EC2] Region : $Region"
    Write-Log "# [AWS - EC2] Availability Zone : $Az"
    Write-Log "# [AWS - EC2] Availability Zone ID: $AzId"
    Write-Log "# [AWS - EC2] Instance ID : $InstanceId"
    Write-Log "# [AWS - EC2] Instance Type : $InstanceType"
    Write-Log "# [AWS - EC2] VPC Private IP Address(IPv4) : $PrivateIp"
    Write-Log "# [AWS - EC2] Amazon Machine Images ID : $AmiId"
    if ($RoleName) {
        Write-Log "# [AWS - EC2] Instance Profile ARN : $RoleArn"
        Write-Log "# [AWS - EC2] IAM Role Name : $RoleName"
    }

} # end function Get-CustomizeEc2InstanceMetadata


function Get-DotNetFrameworkVersion {
    # Get Installed .NET Framework Version
    $dotnet_versions = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name Version -EA 0 | Where-Object -FilterScript { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -Property PSChildName, Version
    foreach ($dotnet_version in $dotnet_versions) {
        # Write the information to the Log Files
        Write-Log ("# [Windows] .NET Framework Information : v{0} - Profile : {1} " -f $dotnet_version.Version, $dotnet_version.PSChildName)
    }
} # end function Get-DotNetFrameworkVersion


function Get-EbsVolumesMappingInformation {
    #--------------------------------------------------------------------------------------
    #  Listing the Disks Using Windows PowerShell
    #   https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-windows-volumes.html#windows-list-disks
    #--------------------------------------------------------------------------------------

    # Set Initialize Parameter
    Set-Variable -Name BlockDeviceName -Scope Script -Value ($Null)
    Set-Variable -Name BlockDeviceMappings -Scope Script -Value ($Null)
    Set-Variable -Name EBSVolumeList -Scope Script -Value ($Null)
    Set-Variable -Name EBSVolumeLists -Scope Script -Value ($Null)
    Set-Variable -Name VirtualDevice -Scope Script -Value ($Null)
    Set-Variable -Name VirtualDeviceMap -Scope Script -Value ($Null)
    Set-Variable -Name VolumeName -Scope Script -Value ($Null)
    Set-Variable -Name DeviceName -Scope Script -Value ($Null)

    # Test Cmdlet
    if (Get-Command -CommandType Cmdlet | Where-Object { $_.Name -eq "Get-EC2InstanceMetadata" }) {
        Try {
            Get-EC2InstanceMetadata -ListCategory
        }
        Catch {
            Write-Host "Could not access the instance Metadata using AWS Get-EC2Instance CMDLet. Verify that you provided your access keys or assigned an IAM role with adequate permissions." -ForegroundColor Yellow
        }
    }

    # List the Windows disks
    [string[]]$array1 = @()
    [string[]]$array2 = @()
    [string[]]$array3 = @()
    [string[]]$array4 = @()

    Get-WmiObject Win32_Volume | Select-Object Name, DeviceID | ForEach-Object {
        $array1 += $_.Name
        $array2 += $_.DeviceID
    }

    $i = 0
    While ($i -ne ($array2.Count)) {
        $array3 += ((Get-Volume -Path $array2[$i] | Get-Partition | Get-Disk).SerialNumber) -replace "_[^ ]*$" -replace "vol", "vol-"
        $array4 += ((Get-Volume -Path $array2[$i] | Get-Partition | Get-Disk).FriendlyName)
        $i ++
    }

    [array[]]$array = $array1, $array2, $array3, $array4

    Try {
        # Getting an Instance Metadata Service v2 (IMDS v2) token
        $Token = $(Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -Method PUT 'http://169.254.169.254/latest/api/token')

        if ($Token) {
            #-----------------------------------------------------------------------
            # Retrieving Metadata Using the Instance Metadata Service v2 (IMDS v2)
            #-----------------------------------------------------------------------
            Write-Log "# [AWS - EC2] Retrieving Metadata Using the Instance Metadata Service v2 (IMDS v2)"

            # InstanceId
            if ( [string]::IsNullOrEmpty($InstanceId) ) {
                Set-Variable -Name InstanceId -Scope Script -Value (Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/meta-data/instance-id")
            }

            # Region
            if ( [string]::IsNullOrEmpty($Region) ) {
                Set-Variable -Name Region -Scope Script -Value (Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri "http://169.254.169.254/latest/meta-data/placement/region")
            }
        }
        else {
            #-----------------------------------------------------------------------
            # Retrieving Metadata Using the Instance Metadata Service v1 (IMDS v1)
            #-----------------------------------------------------------------------
            Write-Log "# [AWS - EC2] Retrieving Metadata Using the Instance Metadata Service v1 (IMDS v1)"

            # InstanceId
            if ( [string]::IsNullOrEmpty($InstanceId) ) {
                Set-Variable -Name InstanceId -Scope Script -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/instance-id")
            }

            # Region
            if ( [string]::IsNullOrEmpty($Region) ) {
                Set-Variable -Name Region -Scope Script -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/placement/region")
            }
        }
    }
    Catch {
        Write-Host "Could not access the instance Metadata using Invoke-RestMethod CMDLet. Verify you have AWSPowershell SDK version '3.1.73.0' or greater installed and Metadata is enabled for this instance." -ForegroundColor Yellow
    }

    Try {
        # Get the volumes attached to this instance
        $BlockDeviceMappings = (Get-EC2Instance -Region $Region -Instance $InstanceId).Instances.BlockDeviceMappings
    }
    Catch {
        Write-Host "Could not access the instance Metadata using AWS Get-EC2Instance CMDLet. Verify that you provided your access keys or assigned an IAM role with adequate permissions." -ForegroundColor Yellow
    }

    Try {
        # Get the block-device-mapping
        $VirtualDeviceMap = (Get-EC2InstanceMetadata -Category "BlockDeviceMapping").GetEnumerator() | Where-Object { $_.Key -ne "ami" }
    }
    Catch {
        Write-Host "Could not access the AWS API using AWS Get-EC2InstanceMetadata CMDLet, therefore, VolumeId is not available. Verify that you provided your access keys or assigned an IAM role with adequate permissions." -ForegroundColor Yellow
    }

    # Get EBS volumes and Ephemeral disks Information
    $EBSVolumeLists = Get-Disk | ForEach-Object {
        $DriveLetter = $null
        $VolumeName = $null
        $VirtualDevice = $null
        $DeviceName = $_.FriendlyName

        $DiskDrive = $_
        $Disk = $_.Number
        $Partitions = $_.NumberOfPartitions
        $EbsVolumeID = $_.SerialNumber -replace "_[^ ]*$" -replace "vol", "vol-"

        if ($Partitions -ge 1) {
            $PartitionsData = Get-Partition -DiskId $_.Path
            $DriveLetter = $PartitionsData.DriveLetter | Where-object { $_ -notin @("", $null) }
            $VolumeName = (Get-PSDrive | Where-Object { $_.Name -in @($DriveLetter) }).Description | Where-object { $_ -notin @("", $null) }
        }

        if ($DiskDrive.path -like "*PROD_PVDISK*") {
            $BlockDeviceName = Convert-SCSITargetIdToDeviceName((Get-WmiObject -Class Win32_Diskdrive | Where-Object { $_.DeviceID -eq ("\\.\PHYSICALDRIVE" + $DiskDrive.Number) }).SCSITargetId)
            $BlockDeviceName = "/dev/" + $BlockDeviceName
            $BlockDevice = $BlockDeviceMappings | Where-Object { $BlockDeviceName -like "*" + $_.DeviceName + "*" }
            $EbsVolumeID = $BlockDevice.Ebs.VolumeId
            $VirtualDevice = ($VirtualDeviceMap.GetEnumerator() | Where-Object { $_.Value -eq $BlockDeviceName }).Key | Select-Object -First 1
        }
        elseif ($DiskDrive.path -like "*PROD_AMAZON_EC2_NVME*") {
            $BlockDeviceName = (Get-EC2InstanceMetadata -Category "BlockDeviceMapping").ephemeral((Get-WmiObject -Class Win32_Diskdrive | Where-Object { $_.DeviceID -eq ("\\.\PHYSICALDRIVE" + $DiskDrive.Number) }).SCSIPort - 2)
            $BlockDevice = $null
            $VirtualDevice = ($VirtualDeviceMap.GetEnumerator() | Where-Object { $_.Value -eq $BlockDeviceName }).Key | Select-Object -First 1
        }
        elseif ($DiskDrive.path -like "*PROD_AMAZON*") {
            if ($DriveLetter -match '[^a-zA-Z0-9]') {
                $i = 0
                While ($i -ne ($array3.Count)) {
                    if ($array[2][$i] -eq $EbsVolumeID) {
                        $DriveLetter = $array[0][$i]
                        $DeviceName = $array[3][$i]
                        }
                    $i ++
                }
            }
            $BlockDevice = ""
            $BlockDeviceName = ($BlockDeviceMappings | Where-Object { $_.ebs.VolumeId -eq $EbsVolumeID }).DeviceName
        }
        elseif ($DiskDrive.path -like "*NETAPP*") {
            if ($DriveLetter -match '[^a-zA-Z0-9]') {
                $i = 0
                While ($i -ne ($array3.Count)) {
                    if ($array[2][$i] -eq $EbsVolumeID) {
                        $DriveLetter = $array[0][$i]
                        $DeviceName = $array[3][$i]
                    }
                    $i ++
                }
            }
            $EbsVolumeID = "FSxN Volume"
            $BlockDevice = ""
            $BlockDeviceName = ($BlockDeviceMappings | Where-Object { $_.ebs.VolumeId -eq $EbsVolumeID }).DeviceName
        }
        else {
            $BlockDeviceName = $null
            $BlockDevice = $null
        }

        New-Object PSObject -Property @{
            Disk          = $Disk;
            Partitions    = $Partitions;
            DriveLetter   = if ($null -eq $DriveLetter) { "N/A" } else { $DriveLetter };
            EbsVolumeId   = if ($null -eq $EbsVolumeID) { "N/A" } else { $EbsVolumeID };
            Device        = if ($null -eq $BlockDeviceName) { "N/A" } else { $BlockDeviceName };
            VirtualDevice = if ($null -eq $VirtualDevice) { "N/A" } else { $VirtualDevice };
            VolumeName    = if ($null -eq $VolumeName) { "N/A" } else { $VolumeName };
            DeviceName    = if ($null -eq $DeviceName) { "N/A" } else { $DeviceName };
        }
    } | Sort-Object Disk | Select-Object -Property Disk, Partitions, DriveLetter, EbsVolumeId, Device, VirtualDevice, DeviceName, VolumeName

    foreach ($EBSVolumeList in $EBSVolumeLists) {
        if ($EBSVolumeList) {
            # Write the information to the Log Files
            Write-Log ("# [AWS - EBS] Windows - [Disk - {0}] [Partitions - {1}] [DriveLetter - {2}] [EbsVolumeId - {3}] [Device - {4}] [VirtualDevice - {5}]  [DeviceName - {6}] [VolumeName - {7}]" -f $EBSVolumeList.Disk, $EBSVolumeList.Partitions, $EBSVolumeList.DriveLetter, $EBSVolumeList.EbsVolumeId, $EBSVolumeList.Device, $EBSVolumeList.VirtualDevice, $EBSVolumeList.DeviceName, $EBSVolumeList.VolumeName)
        }
    }

} # end Get-EbsVolumesMappingInformation


function Get-Ec2ConfigVersion {
    #--------------------------------------------------------------------------------------
    #  Configuring a Windows Instance Using the EC2Config Service
    #   http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/UsingConfig_WinAMI.html
    #--------------------------------------------------------------------------------------

    # Set Initialize Parameter
    Set-Variable -Name EC2ConfigInformation -Scope Script -Value ($Null)
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



function Get-Ec2LaunchVersion {
    #--------------------------------------------------------------------------------------
    #  Configuring a Windows Instance Using EC2Launch
    #   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/ec2launch.html
    #--------------------------------------------------------------------------------------

    # Set Initialize Parameter
    Set-Variable -Name Ec2LaunchModuleConfig -Option Constant -Scope Local -Value "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"
    Set-Variable -Name Ec2LaunchVersion -Scope Script -Value ($Null)

    # Get EC2Launch Version
    if (Test-Path $Ec2LaunchModuleConfig) {
        Import-Module -Name "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"
        $Ec2LaunchVersion = (Get-Module EC2Launch).Version.ToString()

        # Write the information to the Log Files
        if ($Ec2LaunchVersion) {
            Write-Log "# [Windows] Amazon EC2 Windows Utility Information - Amazon EC2Launch Version : $Ec2LaunchVersion"
        }
    }
} # end Get-Ec2LaunchVersion


function Get-Ec2LaunchV2Version {
    #--------------------------------------------------------------------------------------
    #  Configuring a Windows Instance Using EC2Launch
    #   https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/ec2launch-v2.html
    #--------------------------------------------------------------------------------------

    # Set Initialize Parameter
    Set-Variable -Name Ec2LaunchV2Information -Scope Script -Value ($Null)
    Set-Variable -Name Ec2LaunchV2Version -Scope Script -Value ($Null)

    # Get EC2Launch Version
    $Ec2LaunchV2Information = $(Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Where-Object { $_.Name -eq "Amazon EC2Launch" })
    if ($Ec2LaunchV2Information) {
        $Ec2LaunchV2Version = $Ec2LaunchV2Information.Version
    }

    # Write the information to the Log Files
    if ($Ec2LaunchV2Version) {
        Write-Log "# [Windows] Amazon EC2 Windows Utility Information - Amazon EC2Launch v2 Version : $Ec2LaunchV2Version"
    }
} # end Get-Ec2LaunchV2Version


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
            Write-Log "# [Windows] Bootstrap scripts run with the privileges of the administrator"
        }
        else {
            Write-Log "# [Windows] Bootstrap scripts run with the privileges of the non-administrator"
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


function Get-WebContentToFile {
    Param([String]$Uri, [String]$OutFile)

    # Initialize Parameter
    Set-Variable -Name DownloadStatus -Scope Script -Value ($Null)

    # Workaround -> https://github.com/PowerShell/PowerShell/issues/2138
    Set-Variable -Name ProgressPreference -Scope Script -Value "SilentlyContinue"

    if ( Test-Path $OutFile ) {
        Write-Log ("# [NOTICE] File already exists : " + $OutFile)
        Write-Log ("# [NOTICE] Do not download files from : " + $Uri)
    }
    else {

        Write-Log ("# [Get-WebContentToFile] Download processing start    [" + $Uri + "] -> [" + $OutFile + "]" )

        Try {
            $DownloadStatus = Measure-Command { (Invoke-WebRequest -Uri $Uri -UseBasicParsing -OutFile $OutFile) }
        }
        Catch {
            Write-Log ("# [Error] URL is not accessible (file does not exist) : " + $Uri)
        }

        if ( Test-Path $OutFile ) {
            Write-Log ("# [Get-WebContentToFile] Download processing time      ( " + $DownloadStatus.TotalSeconds + " seconds )" )
            Write-Log ("# [Get-WebContentToFile] Download processing complete [" + $Uri + "] -> [" + $OutFile + "]" )
        }

    }
} # end Get-WebContentToFile


function Get-WindowsServerInformation {
    #--------------------------------------------------------------------------------------
    #  Windows Server OS Version Tables (Windows NT Version Tables)
    #   https://learn.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version
    #--------------------------------------------------------------------------------------
    #   - Windows Server 2003    : 5.2
    #   - Windows Server 2003 R2 : 5.2
    #   - Windows Server 2008    : 6.0
    #   - Windows Server 2008 R2 : 6.1
    #   - Windows Server 2012    : 6.2
    #   - Windows Server 2012 R2 : 6.3
    #   - Windows Server 2016    : 10.0 [Build No. 14393]
    #   - Windows Server 2019    : 10.0 [Build No. 17763]
    #   - Windows Server 2022    : 10.0 [Build No. 20348]
    #--------------------------------------------------------------------------------------

    # Initialize Parameter
    Set-Variable -Name productName -Scope Script -Value ($Null)
    Set-Variable -Name installOption -Scope Script -Value ($Null)
    Set-Variable -Name osVersion -Scope Script -Value ($Null)
    Set-Variable -Name osBuildLabEx -Scope Script -Value ($Null)
    Set-Variable -Name osBuildNo -Scope Script -Value ($Null)

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
    $osInfo = Get-CimInstance Win32_OperatingSystem | Select-Object Version, BuildNumber, OperatingSystemSKU
    $osBuildNumber = [int]$osInfo.BuildNumber
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

    # Identify the version of Windows Server 2016, 2019, 2022
    #---------------------------------------------------------------------------
    #   - Windows Server 2016    : 10.0 [Build No. 14393]
    #   - Windows Server 2019    : 10.0 [Build No. 17763]
    #   - Windows Server 2022    : 10.0 [Build No. 20348]
    #---------------------------------------------------------------------------

    # Set Parameter
    if ($osBuildNumber -eq "14393") {
        Set-Variable -Name WindowsOSName -Option Constant -Scope Script -Value "Windows Server 2016"
    }
    elseif ($osBuildNumber -eq "17763") {
        Set-Variable -Name WindowsOSName -Option Constant -Scope Script -Value "Windows Server 2019"
    }
    elseif ($osBuildNumber -eq "20348") {
        Set-Variable -Name WindowsOSName -Option Constant -Scope Script -Value "Windows Server 2022"
    }
    else {
        Set-Variable -Name WindowsOSName -Option Constant -Scope Script -Value ($productName)
    }

    # Write the information to the Log Files
    Write-Log ("# [Windows] Windows Server OS Product Name : {0}" -f $productName)
    Write-Log ("# [Windows] Windows Server OS Name : {0}" -f $WindowsOSName)
    Write-Log ("# [Windows] Windows Server OS Version : {0}" -f $osVersion)
    Write-Log ("# [Windows] Windows Server OS Install Option : {0}" -f $installOption)
    Write-Log ("# [Windows] Windows Server Build Number : {0}" -f $osBuildNumber)
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
#    - Get-CustomizeEc2InstanceMetadata
#    - Get-Ec2LaunchV2Version
#    - Get-Ec2LaunchVersion
#    - Get-Ec2ConfigVersion
#    - Get-WindowsServerInformation
#
########################################################################################################################


function Get-Ec2BootstrapProgram {
    # Checking the existence of the sysprep file
    Write-Log "# [Windows - OS Settings] Checking the existence of the sysprep file"

    if (Test-Path $EC2Launchv2SysprepFile) {
        Set-Variable -Name SysprepFile -Value $EC2Launchv2SysprepFile
        Write-Log ("# [Windows - OS Settings] Found sysprep file [EC2Launch v2] : " + $SysprepFile)
        if ($WindowsOSVersion -match "^6.*|^10.*") {
            Get-Ec2LaunchV2Version
        }
    }
    elseif (Test-Path $EC2LaunchSysprepFile) {
        Set-Variable -Name SysprepFile -Value $EC2LaunchSysprepFile
        Write-Log ("# [Windows - OS Settings] Found sysprep file [EC2Launch] : " + $SysprepFile)
        if ($WindowsOSVersion -match "^10.*") {
            Get-Ec2LaunchVersion
        }
    }
    elseif (Test-Path $EC2ConfigSysprepFile) {
        Set-Variable -Name SysprepFile -Value $EC2ConfigSysprepFile
        Write-Log ("# [Windows - OS Settings] Found sysprep file [EC2Config] : " + $SysprepFile)
        if ($WindowsOSVersion -match "^5.*|^6.*") {
            Get-Ec2ConfigVersion
        }
    }
    else {
        Write-Log "# [Warning] Not Found - Sysprep files"
    }

} # end function Update-SysprepAnswerFile


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

} # end function Get-Ec2BootstrapProgram



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

if ($TimezoneLanguage -eq "ja-JP") {
    if (Get-Command -CommandType Cmdlet | Where-Object { $_.Name -eq "Set-TimeZone" }) {

        # Set Initialize Parameter
        Set-Variable -Name TimeZoneInformation -Scope Script -Value ($Null)

        # Get TimeZone
        $TimeZoneInformation = (Get-TimeZone | Select-Object Id, Displayname, StandardName, BaseUtcOffset)
        Write-Log ("# [Windows - OS Settings] TimeZone - [Id - {0}] [Displayname - {1}] [StandardName - {2}] [BaseUtcOffset - {3}]" -f $TimeZoneInformation.Id, $TimeZoneInformation.Displayname, $TimeZoneInformation.StandardName, $TimeZoneInformation.BaseUtcOffset)

        Set-TimeZone -Id "Tokyo Standard Time" | Out-Null
        Start-Sleep -Seconds 5

        # Get TimeZone
        $TimeZoneInformation = (Get-TimeZone | Select-Object Id, Displayname, StandardName, BaseUtcOffset)
        Write-Log ("# [Windows - OS Settings] TimeZone - [Id - {0}] [Displayname - {1}] [StandardName - {2}] [BaseUtcOffset - {3}]" -f $TimeZoneInformation.Id, $TimeZoneInformation.Displayname, $TimeZoneInformation.StandardName, $TimeZoneInformation.BaseUtcOffset)
    }
    else {
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
        Set-TimeZoneCompatible "Tokyo Standard Time"
        Start-Sleep -Seconds 5
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

# Log Separator
Write-LogSeparator "# [Bootstrap Script] : Running UserData scripts retrieved from GitHub repositories"
Write-Log "# Script Execution 3rd-Bootstrap Script [START] : $ScriptFullPath"

# Create Directory
if ( -not (Test-Path $BASE_DIR)){
    New-Directory $BASE_DIR | Out-Null
}

if ( -not (Test-Path $TOOL_DIR)){
    New-Directory $TOOL_DIR | Out-Null
}

if ( -not (Test-Path $LOGS_DIR)){
    New-Directory $LOGS_DIR | Out-Null
}


Start-Transcript -Path "$TRANSCRIPT_LOG" -Append -Force

Set-Location -Path $BASE_DIR | Out-Null

Get-ExecutionPolicy -List
Set-StrictMode -Version Latest


#-----------------------------------------------------------------------------------------------------------------------
# Change PowerShell SecurityProtocol
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Change PowerShell SecurityProtocol"

# Initialize Parameter
Set-Variable -Name PowerShellSystemSupportSecurityProtocol -Scope Script -Value ($Null)
Set-Variable -Name PowerShellSecurityProtocol -Scope Script -Value ($Null)

# Get System Support - PowerShell SecurityProtocol
$PowerShellSystemSupportSecurityProtocol = @([enum]::GetNames([Net.SecurityProtocolType]))
Write-Log ("# [PowerShell SecurityProtocol] (Get System Support) : " + ($PowerShellSystemSupportSecurityProtocol -join ', '))

# Get PowerShell SecurityProtocol
$PowerShellSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
Write-Log ("# [PowerShell SecurityProtocol] (Before) : " + $PowerShellSecurityProtocol)

# Set PowerShell SecurityProtocol
# https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-
if ($PowerShellSecurityProtocol -match "^Ssl3|^Tls") {
    if ($WindowsOSVersion -eq "6.1") {
        # Set PowerShell SecurityProtocol [TLS v1.1, v1.2]
        [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12;
    }
    elseif ($WindowsOSVersion -eq "6.2") {
        # Set PowerShell SecurityProtocol [TLS v1.1, v1.2]
        [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12;
    }
    elseif ($WindowsOSVersion -eq "6.3") {
        # Set PowerShell SecurityProtocol [TLS v1.1, v1.2]
        [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12;
    }
    elseif ($WindowsOSVersion -eq "10.0") {
        switch ($WindowsOSName) {
            'Windows Server 2016' {
                # Set PowerShell SecurityProtocol [TLS v1.2, v1.3]
                [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13;
            }
            'Windows Server 2019' {
                # Set PowerShell SecurityProtocol [TLS v1.2, v1.3]
                [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13;
            }
            'Windows Server 2022' {
                # Set PowerShell SecurityProtocol [TLS v1.2, v1.3]
                [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13;
            }
            default {
                # Set PowerShell SecurityProtocol [TLS v1.2, v1.3]
                [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13;
            }
        }
    }
    else {
        # [No Target Server OS]
        # Set PowerShell SecurityProtocol [TLS v1.2, v1.3]
        [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13;
    }
}

# Get PowerShell SecurityProtocol
$PowerShellSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
Write-Log ("# [PowerShell SecurityProtocol] (After) : " + $PowerShellSecurityProtocol)


#-----------------------------------------------------------------------------------------------------------------------
# Test Network Connection
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Test Network Connection"

# Initialize Parameter
Set-Variable -Name FlagInternetConnection -Scope Script -Value ($Null)

# Test Connecting to the Internet (Google Public DNS : 8.8.8.8)
#  https://developers.google.com/speed/public-dns/
$FlagInternetConnectionByIPAddress = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue
if ($FlagInternetConnectionByIPAddress -eq $TRUE) {
    Write-Log "# [Network Connection] Google Public DNS : 8.8.8.8 - [Connection OK]"
}
else {
    Write-Log "# [Network Connection] Google Public DNS : 8.8.8.8 - [Connection NG]"
}

# Test Connecting to the Internet (Google WebSite : www.google.com)
$FlagInternetConnectionByFQDN = Test-Connection -ComputerName www.google.com -Count 1 -Quiet -ErrorAction SilentlyContinue
if ($FlagInternetConnectionByFQDN -eq $TRUE) {
    Write-Log "# [Network Connection] Google WebSite : www.google.com - [Connection OK]"
}
else {
    Write-Log "# [Network Connection] Google WebSite : www.google.com - [Connection NG]"
}

# Test HTTPS Connecting to the Internet (AWS Check IP Address service : https://checkip.amazonaws.com/)
#  https://docs.aws.amazon.com/ja_jp/batch/latest/userguide/get-set-up-for-aws-batch.html#create-a-base-security-group
$FlagInternetConnectionByHTTPS = Invoke-WebRequest -Uri "https://checkip.amazonaws.com/" -UseBasicParsing
if ($FlagInternetConnectionByHTTPS.StatusCode -eq 200) {
    Write-Log "# [Network Connection] AWS Check IP Address service : checkip.amazonaws.com - [Connection OK]"
    Write-Log ("# [Network Connection] AWS Check IP Address service : Public IP Address is " + ($FlagInternetConnectionByHTTPS.RawContent | Select-String -Pattern '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' -AllMatches -Encoding default | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }))
}
else {
    Write-Log "# [Network Connection] AWS Check IP Address service : checkip.amazonaws.com - [Connection NG]"
}


#-----------------------------------------------------------------------------------------------------------------------
# Logging Amazon EC2 System & Windows Server OS Parameter
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Logging Amazon EC2 System & Windows Server OS Parameter"

# Logging Amazon EC2 Instance Metadata
Get-CustomizeEc2InstanceMetadata

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

# Logging Windows Server OS Parameter [EC2 Bootstrap Application Information (EC2Config / EC2Launch / EC2Launch V2)]
Get-Ec2BootstrapProgram

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

# View AWS Tools for Windows PowerShell Version
Get-AWSPowerShellVersion
# Get-AWSPowerShellVersion -ListServiceVersionInfo

# Setting AWS Tools for Windows PowerShell
Initialize-AWSDefaultConfiguration -Region $Region
Set-DefaultAWSRegion -Region $Region

# Log Setting Information [Set-DefaultAWSRegion]
Start-Sleep -Seconds 5
Write-Log ("# [Amazon EC2 - Windows] Display Default Region at AWS Tools for Windows Powershell : " + (Get-DefaultAWSRegion).Name + " - " + (Get-DefaultAWSRegion).Region)

# Setting AWS Tools for Windows PowerShell (Additional)
#  Clear-AWSHistory
#  Set-AWSHistoryConfiguration -MaxCmdletHistory 512 -MaxServiceCallHistory 512 -RecordServiceRequests
#  Set-AWSResponseLogging -Level Always

# Get AWS Region Information
if ($RoleName) {
    Write-Log "# [Amazon EC2 - Windows] Get AWS Region Information"
    Get-AWSRegion | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-AWSRegion.txt" -Append -Force
}

# Get Amazon EC2 Instance Information
if ($RoleName) {
    Write-Log "# [Amazon EC2 - Windows] Get EC2 Instance Information"
    Get-EC2Instance -Filter @{Name = "instance-id"; Values = $InstanceId } | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Instance.txt" -Append -Force
}

# Get Amazon EC2 Instance attached EBS Volume Information
if ($RoleName) {
    Write-Log "# [Amazon EC2 - Windows] Get EC2 Instance attached EBS Volume Information"
    Get-EC2Volume -Filter @{Name = "attachment.instance-id"; Values = $InstanceId } | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Volume.txt" -Append -Force
}

# Get AMI information of this EC2 instance
if ($RoleName) {
    Write-Log "# [Amazon EC2 - Windows] Get AMI information of this EC2 instance"
    Get-EC2Image -ImageId $AmiId -Region $Region | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Image.txt" -Append -Force
}

# Get AMI Information from Systems Manager Parameter Store
#
# [Calling AMI public parameters]
#   https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-public-parameters-ami.html
#
if ($RoleName) {

    # Initialize Parameter
    Set-Variable -Name SSMAccessibleFlags -Scope Script -Value ($True)

    Try {
        Write-Log "# [Amazon EC2 - Windows] Get AMI Information from Systems Manager Parameter Store (/aws/service/ami-windows-latest)"
        Get-SSMParametersByPath -Path "/aws/service/ami-windows-latest" -Region $Region | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-SSMParametersByPath_aws-service-ami-windows-latest.txt" -Append -Force
    }
    Catch {
        Write-Host "Could not access the AWS API, therefore, SSM Parameter Store is not available. Verify that you provided your access keys or assigned an IAM role with adequate permissions." -ForegroundColor Yellow
        # SSM Accessible Flags
        Set-Variable -Name SSMAccessibleFlags -Scope Script -Value ($False)
    }

    if ($SSMAccessibleFlags -eq $True) {
        Write-Log "# [Amazon EC2 - Windows] Get AMI Information from Systems Manager Parameter Store (For AMI)"

        # Windows_Server-2012-R2_RTM-Japanese-64Bit-Base
        Get-EC2Image -Region $Region -ImageId ((Get-SSMParameterValue -Region $Region -Name "/aws/service/ami-windows-latest/Windows_Server-2012-R2_RTM-Japanese-64Bit-Base").Parameters[0].Value) | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Image_Windows_Server-2012-R2_RTM-Japanese-64Bit-Base.txt" -Append -Force

        # Windows_Server-2016-Japanese-Full-Base
        Get-EC2Image -Region $Region -ImageId ((Get-SSMParameterValue -Region $Region -Name "/aws/service/ami-windows-latest/Windows_Server-2016-Japanese-Full-Base").Parameters[0].Value ) | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Image_Windows_Server-2016-Japanese-Full-Base.txt" -Append -Force

        # Windows_Server-2019-Japanese-Full-Base
        Get-EC2Image -Region $Region -ImageId ((Get-SSMParameterValue -Region $Region -Name "/aws/service/ami-windows-latest/Windows_Server-2019-Japanese-Full-Base").Parameters[0].Value) | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Image_Windows_Server-2019-Japanese-Full-Base.txt" -Append -Force

        # Windows_Server-2022-Japanese-Full-Base
        Get-EC2Image -Region $Region -ImageId ((Get-SSMParameterValue -Region $Region -Name "/aws/service/ami-windows-latest/Windows_Server-2022-Japanese-Full-Base").Parameters[0].Value) | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Image_Windows_Server-2022-Japanese-Full-Base.txt" -Append -Force

        # Windows_Server-2012-R2_RTM-English-64Bit-Base
        Get-EC2Image -Region $Region -ImageId ((Get-SSMParameterValue -Region $Region -Name "/aws/service/ami-windows-latest/Windows_Server-2012-R2_RTM-English-64Bit-Base").Parameters[0].Value) | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Image_Windows_Server-2012-R2_RTM-English-64Bit-Base.txt" -Append -Force

        # Windows_Server-2016-English-Full-Base
        Get-EC2Image -Region $Region -ImageId ((Get-SSMParameterValue -Region $Region -Name "/aws/service/ami-windows-latest/Windows_Server-2016-English-Full-Base").Parameters[0].Value) | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Image_Windows_Server-2016-English-Full-Base.txt" -Append -Force

        # Windows_Server-2019-English-Full-Base
        Get-EC2Image -Region $Region -ImageId ((Get-SSMParameterValue -Region $Region -Name "/aws/service/ami-windows-latest/Windows_Server-2019-English-Full-Base").Parameters[0].Value) | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Image_Windows_Server-2019-English-Full-Base.txt" -Append -Force

        # Windows_Server-2022-English-Full-Base
        Get-EC2Image -Region $Region -ImageId ((Get-SSMParameterValue -Region $Region -Name "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base").Parameters[0].Value) | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Image_Windows_Server-2022-English-Full-Base.txt" -Append -Force
    }

}

# Get EBS snapshot information for AWS-provided installation media
#
# [Adding Windows Components Using Installation Media]
#   https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/windows-optional-components.html
#
if ($RoleName) {
    Write-Log "# [Amazon EC2 - Windows] Get EBS snapshot information for AWS-provided installation media"
    Get-EC2Snapshot -Owner amazon -Filter @{ Name = "description"; Values = "Windows*" } | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-Information_Get-EC2Snapshot_WindowsInstallationMedia-List.txt" -Append -Force
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
            Write-Log ("# [Warning] No Target [OS-Language - Japanese] - Windows Server OS Version Information : " + $WindowsOSVersion)
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
    $AUSettings.FeaturedUpdatesEnabled = $True     # Enabled

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
    Write-Log ("# [Warning] No Target - Windows Server OS Version Information : " + $WindowsOSVersion)
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
    Write-Log ("# [Warning] No Target - Windows Server OS Version Information : " + $WindowsOSVersion)
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [Windows Time Service (w32tm) Setting]
# https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/windows-set-time.html
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [Windows Time Service (w32tm) Setting]"

# Initialize Parameter
Set-Variable -Name W32TM -Scope Script -Value "C:\Windows\System32\w32tm.exe"

# Configuration for Amazon Time Sync Service
Write-Log ("# [Windows - OS Settings] Amazon Time Sync Service - Support Instance Type  : " + $InstanceType)

# Get Windows Time Service (Service Status/Configuration/Peer Status)
Write-Log "# [Amazon EC2 - Windows] Amazon Time Sync Service - Get Windows Time Service (Service Status/Configuration/Peer Status)"
Start-Process -FilePath $W32TM -Verb runas -PassThru -Wait -ArgumentList @("/query /status /verbose")
Start-Process -FilePath $W32TM -Verb runas -PassThru -Wait -ArgumentList @("/query /configuration /verbose")
Start-Process -FilePath $W32TM -Verb runas -PassThru -Wait -ArgumentList @("/query /peers /verbose")

# Set Windows Time Service for Amazon Time Sync Service
Start-Process -FilePath $W32TM -Verb runas -PassThru -Wait -ArgumentList @("/config /update /manualpeerlist:169.254.169.123 /syncfromflags:manual")

# Get Windows Time Service (Service Status/Configuration/Peer Status)
Write-Log "# [Amazon EC2 - Windows] Amazon Time Sync Service - Get Windows Time Service (Service Status/Configuration/Peer Status)"
Start-Process -FilePath $W32TM -Verb runas -PassThru -Wait -ArgumentList @("/query /status /verbose")
Start-Process -FilePath $W32TM -Verb runas -PassThru -Wait -ArgumentList @("/query /configuration /verbose")
Start-Process -FilePath $W32TM -Verb runas -PassThru -Wait -ArgumentList @("/query /peers /verbose")


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [Folder Option Setting]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [Folder Option Setting]"

# Change Windows Folder Option Policy
Write-Log "# [Windows - OS Settings] Change Windows Folder Option Policy (Before)"

Set-Variable -Name HKLM_FolderOptionRegistry -Option Constant -Scope Local -Value "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Set-Variable -Name HKCU_FolderOptionRegistry -Option Constant -Scope Local -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

if (Test-Path -Path $HKLM_FolderOptionRegistry) {
    # [Check] Show hidden files, folders, or drives
    if ((Get-Item -Path $HKLM_FolderOptionRegistry).GetValueNames() -contains 'Hidden') {
        Set-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'Hidden' -Value '1' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKLM_FolderOptionRegistry + "\Hidden")
    }
    else {
        New-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'Hidden' -Value '1' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKLM_FolderOptionRegistry + "\Hidden")
    }

    # [UnCheck] Hide extensions for known file types
    if ((Get-Item -Path $HKLM_FolderOptionRegistry).GetValueNames() -contains 'HideFileExt') {
        Set-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'HideFileExt' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKLM_FolderOptionRegistry + "\HideFileExt")
    }
    else {
        New-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'HideFileExt' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKLM_FolderOptionRegistry + "\HideFileExt")
    }

    # [Check] Restore previous folders windows
    if ((Get-Item -Path $HKLM_FolderOptionRegistry).GetValueNames() -contains 'PersistBrowsers') {
        Set-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'PersistBrowsers' -Value '1' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKLM_FolderOptionRegistry + "\PersistBrowsers")
    }
    else {
        New-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'PersistBrowsers' -Value '1' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKLM_FolderOptionRegistry + "\PersistBrowsers")
    }
}

if ( -Not (Test-Path -Path $HKCU_FolderOptionRegistry ) ) {
    Write-Log ("# New-Item - " + $HKCU_FolderOptionRegistry)
    New-Item -Path $HKCU_FolderOptionRegistry -Force | Out-Null
    Start-Sleep -Seconds 5
}

if (Test-Path -Path $HKCU_FolderOptionRegistry) {
    # [Check] Show hidden files, folders, or drives
    if ((Get-Item -Path $HKCU_FolderOptionRegistry).GetValueNames() -contains 'Hidden') {
        Set-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'Hidden' -Value '1' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKCU_FolderOptionRegistry + "\Hidden")
    }
    else {
        New-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'Hidden' -Value '1' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKCU_FolderOptionRegistry + "\Hidden")
    }

    # [UnCheck] Hide extensions for known file types
    if ((Get-Item -Path $HKCU_FolderOptionRegistry).GetValueNames() -contains 'HideFileExt') {
        Set-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'HideFileExt' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKCU_FolderOptionRegistry + "\HideFileExt")
    }
    else {
        New-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'HideFileExt' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKCU_FolderOptionRegistry + "\HideFileExt")
    }

    # [Check] Restore previous folders windows
    if ((Get-Item -Path $HKCU_FolderOptionRegistry).GetValueNames() -contains 'PersistBrowsers') {
        Set-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'PersistBrowsers' -Value '1' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKCU_FolderOptionRegistry + "\PersistBrowsers")
    }
    else {
        New-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'PersistBrowsers' -Value '1' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKCU_FolderOptionRegistry + "\PersistBrowsers")
    }
}

Write-Log "# [Windows - OS Settings] Change Windows Folder Option Policy (After)"


# Change Display Desktop Icon Policy
Write-Log "# [Windows - OS Settings] Change Display Desktop Icon Policy (Before)"

Set-Variable -Name HKLM_DesktopIconRegistrySetting -Option Constant -Scope Local -Value "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
Set-Variable -Name HKCU_DesktopIconRegistry -Option Constant -Scope Local -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
Set-Variable -Name HKCU_DesktopIconRegistrySetting -Option Constant -Scope Local -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"

if (Test-Path -Path $HKLM_DesktopIconRegistrySetting) {
    #[CLSID] : My Computer
    if ((Get-Item -Path $HKLM_DesktopIconRegistrySetting).GetValueNames() -contains '{20D04FE0-3AEA-1069-A2D8-08002B30309D}') {
        Set-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{20D04FE0-3AEA-1069-A2D8-08002B30309D}")
    }
    else {
        New-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{20D04FE0-3AEA-1069-A2D8-08002B30309D}")
    }

    #[CLSID] : Control Panel
    if ((Get-Item -Path $HKLM_DesktopIconRegistrySetting).GetValueNames() -contains '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}') {
        Set-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}")
    }
    else {
        New-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}")
    }

    #[CLSID] : User's Files
    if ((Get-Item -Path $HKLM_DesktopIconRegistrySetting).GetValueNames() -contains '{59031a47-3f72-44a7-89c5-5595fe6b30ee}') {
        Set-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")
    }
    else {
        New-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")
    }

    #[CLSID] : Recycle Bin
    if ((Get-Item -Path $HKLM_DesktopIconRegistrySetting).GetValueNames() -contains '{645FF040-5081-101B-9F08-00AA002F954E}') {
        Set-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{645FF040-5081-101B-9F08-00AA002F954E}")
    }
    else {
        New-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{645FF040-5081-101B-9F08-00AA002F954E}")
    }

    #[CLSID] : Network
    if ((Get-Item -Path $HKLM_DesktopIconRegistrySetting).GetValueNames() -contains '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}') {
        Set-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}")
    }
    else {
        New-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}")
    }
}

if ( -Not (Test-Path -Path $HKCU_DesktopIconRegistry ) ) {
    Write-Log ("# New-Item - " + $HKCU_DesktopIconRegistry)
    New-Item -Path $HKCU_DesktopIconRegistry -Force | Out-Null
    Start-Sleep -Seconds 5

    Write-Log ("# New-Item - " + $HKCU_DesktopIconRegistrySetting)
    New-Item -Path $HKCU_DesktopIconRegistrySetting -Force | Out-Null
    Start-Sleep -Seconds 5
}

if (Test-Path -Path $HKCU_DesktopIconRegistrySetting) {
    #[CLSID] : My Computer
    if ((Get-Item -Path $HKCU_DesktopIconRegistrySetting).GetValueNames() -contains '{20D04FE0-3AEA-1069-A2D8-08002B30309D}') {
        Set-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{20D04FE0-3AEA-1069-A2D8-08002B30309D}")
    }
    else {
        New-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{20D04FE0-3AEA-1069-A2D8-08002B30309D}")
    }

    #[CLSID] : Control Panel
    if ((Get-Item -Path $HKCU_DesktopIconRegistrySetting).GetValueNames() -contains '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}') {
        Set-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}")
    }
    else {
        New-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}")
    }

    #[CLSID] : User's Files
    if ((Get-Item -Path $HKCU_DesktopIconRegistrySetting).GetValueNames() -contains '{59031a47-3f72-44a7-89c5-5595fe6b30ee}') {
        Set-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")
    }
    else {
        New-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")
    }

    #[CLSID] : Recycle Bin
    if ((Get-Item -Path $HKCU_DesktopIconRegistrySetting).GetValueNames() -contains '{645FF040-5081-101B-9F08-00AA002F954E}') {
        Set-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{645FF040-5081-101B-9F08-00AA002F954E}")
    }
    else {
        New-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{645FF040-5081-101B-9F08-00AA002F954E}")
    }

    #[CLSID] : Network
    if ((Get-Item -Path $HKCU_DesktopIconRegistrySetting).GetValueNames() -contains '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}') {
        Set-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Value '0' -Force | Out-Null
        Write-Log ("# Set-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}")
    }
    else {
        New-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Value '0' -PropertyType "DWord" -Force | Out-Null
        Write-Log ("# New-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}")
    }
}

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
    $connections | ForEach-Object { $_.GetNetwork().SetCategory(1) }

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
        Write-Log ("# [Warning] No Target - Windows Server OS Version Information : " + $WindowsOSVersion)
    }
}
else {
    Write-Log ("# [Warning] No Target - Windows Server OS Version Information : " + $WindowsOSVersion)
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [Sysprep Answer File Setting]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [Sysprep Answer File Setting]"

# Update Sysprep Answer File
if ($WindowsOSLanguage -eq "ja-JP") {
    Write-Log "# [Windows - OS Settings] Checking the existence of the sysprep file"

    if (Test-Path $EC2Launchv2SysprepFile) {
        Set-Variable -Name SysprepFile -Value $EC2Launchv2SysprepFile
        Write-Log ("# [Windows - OS Settings] Found sysprep file [EC2Launch v2] : " + $SysprepFile)
    }
    elseif (Test-Path $EC2LaunchSysprepFile) {
        Set-Variable -Name SysprepFile -Value $EC2LaunchSysprepFile
        Write-Log ("# [Windows - OS Settings] Found sysprep file [EC2Launch] : " + $SysprepFile)
    }
    elseif (Test-Path $EC2ConfigSysprepFile) {
        Set-Variable -Name SysprepFile -Value $EC2ConfigSysprepFile
        Write-Log ("# [Windows - OS Settings] Found sysprep file [EC2Config] : " + $SysprepFile)
    }
    else {
        Write-Log "# [Warning] Not Found - Sysprep files"
    }

    # Update Sysprep Answer File
    if (Test-Path $SysprepFile) {
        Write-Log "# [Windows - OS Settings] Update Sysprep Answer File (Before)"
        Get-Content -Path $SysprepFile | ConvertTo-Xml | Out-File "$LOGS_DIR\WindowsConfigurationFiles_Sysprep(Before).xml" -Append -Force

        Update-SysprepAnswerFile $SysprepFile

        Write-Log "# [Windows - OS Settings] Update Sysprep Answer File (After)"
        Get-Content -Path $SysprepFile | ConvertTo-Xml | Out-File "$LOGS_DIR\WindowsConfigurationFiles_Sysprep(After).xml" -Append -Force
    }

}
else {
    Write-Log ("# [Information] No Target [OS-Language - Japanese] - Windows Language Information : " + $WindowsOSLanguage)
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [IPv6 Setting]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [IPv6 Setting]"

if ($WindowsOSVersion -match "^6.1") {
    Write-Log "Windows Server OS Configuration [IPv6 Setting] : START"

    # Display IPv6 Information
    netsh.exe interface ipv6 show interface | Out-Default
    netsh.exe interface ipv6 show prefixpolicies | Out-Default
    netsh.exe interface ipv6 show global | Out-Default

    # Disable IPv6 Binding (ISATAP Interface)
    netsh.exe interface ipv6 isatap set state disabled | Out-Default

    # Disable IPv6 Binding (6to4 Interface)
    netsh.exe interface ipv6 6to4 set state disabled | Out-Default

    # Disable IPv6 Binding (Teredo Interface)
    netsh.exe interface ipv6 set teredo disabled | Out-Default

    # Display IPv6 Information
    netsh.exe interface ipv6 show interface | Out-Default
    netsh.exe interface ipv6 show prefixpolicies | Out-Default
    netsh.exe interface ipv6 show global | Out-Default

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
    Write-Log ("# [Warning] No Target - Windows Server OS Version Information : " + $WindowsOSVersion)
}


#-----------------------------------------------------------------------------------------------------------------------
# Windows Server OS Configuration [System PowerPlan]
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Windows Server OS Configuration [System PowerPlan]"

# Setting Paramter [PowerShell script "high performance" in Japanese]
$Word_HighPower_Base64 = "6auY44OR44OV44Kp44O844Oe44Oz44K5"                             # A string of "high performance" was Base64 encoded in Japanese
$Word_HighPower_Byte = [System.Convert]::FromBase64String($Word_HighPower_Base64)       # Conversion from base64 to byte sequence
$Word_HighPower_String = [System.Text.Encoding]::UTF8.GetString($Word_HighPower_Byte)   # To convert a sequence of bytes into a string of UTF-8 encoding

# Setting Paramter [GUID parameter "high performance" of powercfg.exe]
$Guid_HighPower = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"                                # https://docs.microsoft.com/en-us/windows/desktop/power/power-policy-settings

# Logging Windows Server OS Parameter [System Power Plan Information]
Get-PowerPlanInformation

if ($WindowsOSVersion -match "^6.1|^6.2|^6.3") {
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
}
elseif ($WindowsOSVersion -match "^10.0") {
    # Change System PowerPlan (High Performance)
    if (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq $Word_HighPower_String }) {
        Write-Log "# [Windows - OS Settings] PowerPlan : Change System PowerPlan - $Word_HighPower_String"
        Start-Process "powercfg.exe" -Verb runas -Wait -ArgumentList @("/setactive", "$Guid_HighPower")
        Start-Sleep -Seconds 5
    }
    elseif (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq "High performance" }) {
        Write-Log "# [Windows - OS Settings] PowerPlan : Change System PowerPlan - High performance"
        Start-Process "powercfg.exe" -Verb runas -Wait -ArgumentList @("/setactive", "$Guid_HighPower")
        Start-Sleep -Seconds 5
    }
    else {
        Write-Log "# [Windows - OS Settings] PowerPlan : Change System PowerPlan - No change"
    }
}
else {
    Write-Log ("# [Warning] No Target - Windows Server OS Version Information : " + $WindowsOSVersion)
}

# Logging Windows Server OS Parameter [System Power Plan Information]
Get-PowerPlanInformation


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Install (AWS-CLI v2)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Package Install System Utility (AWS-CLI v2)"

# Check Windows OS Version[Windows Server 2008 R2, 2012, 2012 R2, 2016]
if ($WindowsOSVersion -match "^6.1|^6.2|^6.3|^10.0") {

    # Package Download System Utility (AWS-CLI v2)
    # https://aws.amazon.com/jp/cli/
    # https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-windows.html
    Write-Log "# Package Download System Utility (AWS-CLI v2)"
    Get-WebContentToFile -Uri 'https://awscli.amazonaws.com/AWSCLIV2.msi' -OutFile "$TOOL_DIR\AWSCLIV2.msi"

    # Package Install System Utility (AWS-CLI v2)
    Write-Log "# Package Install System Utility (AWS-CLI v2)"
    Start-Process "msiexec.exe" -Verb runas -Wait -ArgumentList @("/i $TOOL_DIR\AWSCLIV2.msi", "/qn", "/L*v $LOGS_DIR\APPS_AWS_AWSCLI_V2_Setup.log")

    Start-Sleep -Seconds 5
}
else {
    # Amazon CloudWatch Agent Support Windows OS Version (None)
    Write-Log ("# [AWS - EC2-AWSCLI] Windows OS Version : " + $WindowsOSVersion + " - Not Suppoort Windows OS Version")
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package ReInstall[Uninstall and Install] (AWS CloudFormation Helper Scripts)
#  - Workaround processing for multiple aws-cfn-bootstrap package information conflicts -
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Package ReInstall[Uninstall and Install] (AWS CloudFormation Helper Scripts)"

# Set Initialize Parameter
Set-Variable -Name ServiceStatusForCloudFormation -Scope Script -Value ($Null)

# Logging Install Windows Application List (Before Uninstall)
Write-Log "# Get Install Windows Application List (Before Uninstall)"
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | ConvertTo-Json -Depth 100 | Out-File (Join-Path $LOGS_DIR ("AWS-EC2_WindowsInstallApplicationList_" + $(Get-Date).ToString("yyyyMMdd_hhmmss") + ".txt")) -Append -Force

# Uninstall AWS CloudFormation Helper Scripts
Write-Log "# Uninstall AWS CloudFormation Helper Scripts"
(Get-WmiObject -Class Win32_Product -Filter "Name='aws-cfn-bootstrap'" -ComputerName . ).Uninstall() | Out-Null
Start-Sleep -Seconds 5

# Logging Install Windows Application List (After Uninstall)
Write-Log "# Get Install Windows Application List (After Uninstall)"
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | ConvertTo-Json -Depth 100 | Out-File (Join-Path $LOGS_DIR ("AWS-EC2_WindowsInstallApplicationList_" + $(Get-Date).ToString("yyyyMMdd_hhmmss") + ".txt")) -Append -Force

# Package Download System Utility (AWS CloudFormation Helper Scripts)
# http://docs.aws.amazon.com/ja_jp/AWSCloudFormation/latest/UserGuide/cfn-helper-scripts-reference.html
Set-Variable -Name CLOUDFORMATION_BOOTSTRAP_INSTALLER_URL -Scope Script -Value "https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-py3-win64-latest.exe"
Set-Variable -Name CLOUDFORMATION_BOOTSTRAP_INSTALLER_FILE -Scope Script -Value ($CLOUDFORMATION_BOOTSTRAP_INSTALLER_URL.Substring($CLOUDFORMATION_BOOTSTRAP_INSTALLER_URL.LastIndexOf("/") + 1))

Write-Log "# Package Download System Utility (AWS CloudFormation Helper Scripts)"
Get-WebContentToFile -Uri "$CLOUDFORMATION_BOOTSTRAP_INSTALLER_URL" -OutFile "$TOOL_DIR\$CLOUDFORMATION_BOOTSTRAP_INSTALLER_FILE"

# Package Install System Utility (AWS CloudFormation Helper Scripts)
Write-Log "# Package Install System Utility (AWS CloudFormation Helper Scripts)"
Start-Process -FilePath "$TOOL_DIR\$CLOUDFORMATION_BOOTSTRAP_INSTALLER_FILE" -Verb runas -Wait -ArgumentList @('/install', '/quiet', '/log C:\EC2-Bootstrap\Logs\APPS_AWS_AWSCloudFormationHelperScriptSetup.log') | Out-Null

Start-Sleep -Seconds 10

# Get Service Status
$ServiceStatusForCloudFormation = (Get-Service -Name "cfn-hup" | Select-Object Displayname, Status, ServiceName)
Write-Log ("# [Windows - OS Settings] Service - [Displayname - {0}] [ServiceName - {1}] [Status - {2}]" -f $ServiceStatusForCloudFormation.Displayname, $ServiceStatusForCloudFormation.ServiceName, $ServiceStatusForCloudFormation.Status)

# Logging Install Windows Application List (After Install)
Write-Log "# Get Install Windows Application List (After Install)"
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | ConvertTo-Json -Depth 100 | Out-File (Join-Path $LOGS_DIR ("AWS-EC2_WindowsInstallApplicationList_" + $(Get-Date).ToString("yyyyMMdd_hhmmss") + ".txt")) -Append -Force


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Update (AWS Systems Manager agent (aka SSM agent))
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Package Update System Utility (AWS Systems Manager agent)"

# Set Initialize Parameter
Set-Variable -Name ServiceStatusForAmazonSSMAgent -Scope Script -Value ($Null)
Set-Variable -Name AmazonSSMAgentUrl -Scope Script -Value ($Null)

# Package Download System Utility (AWS Systems Manager agent)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/systems-manager-managedinstances.html#sysman-install-managed-win
Write-Log "# Package Download System Utility (AWS Systems Manager agent)"
if ($Region) {
    $AmazonSSMAgentUrl = "https://amazon-ssm-" + ${Region} + ".s3.amazonaws.com/latest/windows_amd64/AmazonSSMAgentSetup.exe"
    Get-WebContentToFile -Uri $AmazonSSMAgentUrl -OutFile "$TOOL_DIR\AmazonSSMAgentSetup.exe"
}
else {
    Get-WebContentToFile -Uri 'https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe' -OutFile "$TOOL_DIR\AmazonSSMAgentSetup.exe"
}

# Logging Windows Server OS Parameter [AWS Systems Manager agent Information]
Get-Ec2SystemManagerAgentVersion

# Package Update System Utility (AWS Systems Manager agent)
Write-Log "# Package Update System Utility (AWS Systems Manager agent)"
Start-Process -FilePath "$TOOL_DIR\AmazonSSMAgentSetup.exe" -Verb runas -Wait -ArgumentList @('ALLOWEC2INSTALL=YES', '/install', '/norstart', '/log C:\EC2-Bootstrap\Logs\APPS_AWS_AmazonSSMAgentSetup.log', '/quiet') | Out-Null

Start-Sleep -Seconds 5

# Get Service Status
$ServiceStatusForAmazonSSMAgent = (Get-Service -Name "AmazonSSMAgent" | Select-Object Displayname, Status, ServiceName)
Write-Log ("# [Windows - OS Settings] Service - [Displayname - {0}] [ServiceName - {1}] [Status - {2}]" -f $ServiceStatusForAmazonSSMAgent.Displayname, $ServiceStatusForAmazonSSMAgent.ServiceName, $ServiceStatusForAmazonSSMAgent.Status)

# Service Automatic Startup Setting (AWS Systems Manager agent)
$AmazonSSMAgentStatus = (Get-WmiObject Win32_Service -Filter "Name='AmazonSSMAgent'").StartMode

if ($AmazonSSMAgentStatus -ne "Auto") {
    Write-Log "# [Windows - OS Settings] [AWS Systems Manager agent] Service Startup Type : $AmazonSSMAgentStatus -> Auto"
    Set-Service -Name "AmazonSSMAgent" -StartupType Automatic

    Start-Sleep -Seconds 5

    $AmazonSSMAgentStatus = (Get-WmiObject Win32_Service -Filter "Name='AmazonSSMAgent'").StartMode
    Write-Log "# [Windows - OS Settings] [AWS Systems Manager agent] Service Startup Type : $AmazonSSMAgentStatus"
}

# Logging Windows Server OS Parameter [AWS Systems Manager agent Information]
Get-Ec2SystemManagerAgentVersion

# Forced cleanup of AWS Systems Manager agent's local data
Stop-Service -Name "AmazonSSMAgent" | Out-Null
Start-Sleep -Seconds 15

Remove-Item -Path "C:\ProgramData\Amazon\SSM\InstanceData" -Recurse -Force

if (Test-Path $SSMAgentLogFile) {
    Clear-Content -Path $SSMAgentLogFile -Force -ErrorAction SilentlyContinue
}

Start-Service -Name "AmazonSSMAgent" | Out-Null
Start-Sleep -Seconds 15

# Get Service Status
$ServiceStatusForAmazonSSMAgent = (Get-Service -Name "AmazonSSMAgent" | Select-Object Displayname, Status, ServiceName)
Write-Log ("# [Windows - OS Settings] Service - [Displayname - {0}] [ServiceName - {1}] [Status - {2}]" -f $ServiceStatusForAmazonSSMAgent.Displayname, $ServiceStatusForAmazonSSMAgent.ServiceName, $ServiceStatusForAmazonSSMAgent.Status)

# View Log File
Get-Content -Path $SSMAgentLogFile  | Out-File "$LOGS_DIR\AWS-Systems-Manager-agent.log" -Append -Force

# Display Windows Server OS Parameter [AWS Systems Manager agent Information]
if ($RoleName) {
    Start-Process -FilePath "C:\Program Files\Amazon\SSM\ssm-cli.exe" -Verb runas -ArgumentList "get-instance-information"
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Install (Amazon CloudWatch Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Package Install System Utility (Amazon CloudWatch Agent)"

# Set Initialize Parameter
Set-Variable -Name ServiceStatusForAmazonCloudWatchAgent -Scope Script -Value ($Null)

# ConfigFile Download System Utility (Amazon CloudWatch Agent)
Write-Log "# Package Download System Utility (Amazon CloudWatch Agent)"
if ($WindowsOSVersion -eq "6.1") {
    Write-Log ("# Save Amazon CloudWatch Agent Config Files [Windows Server 2008 R2] : Windows OS Version : " + $WindowsOSVersion)
    Get-WebContentToFile -Uri 'https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_WindowsServer-2008R2.json' -OutFile "$TOOL_DIR\AmazonCloudWatchAgent-Config.json"
}
elseif ($WindowsOSVersion -eq "6.2") {
    Write-Log ("# Save Amazon CloudWatch Agent Config Files [Windows Server 2012] : Windows OS Version : " + $WindowsOSVersion)
    Get-WebContentToFile -Uri 'https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_WindowsServer-2012.json' -OutFile "$TOOL_DIR\AmazonCloudWatchAgent-Config.json"
}
elseif ($WindowsOSVersion -eq "6.3") {
    Write-Log ("# Save Amazon CloudWatch Agent Config Files [Windows Server 2012 R2] : Windows OS Version : " + $WindowsOSVersion)
    Get-WebContentToFile -Uri 'https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_WindowsServer-2012R2.json' -OutFile "$TOOL_DIR\AmazonCloudWatchAgent-Config.json"
}
elseif ($WindowsOSVersion -eq "10.0") {
    switch ($WindowsOSName) {
        'Windows Server 2016' {
            Write-Log ("# Save Amazon CloudWatch Agent Config Files [Windows Server 2016] : Windows OS Version : " + $WindowsOSVersion)
            Get-WebContentToFile -Uri 'https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_WindowsServer-2016.json' -OutFile "$TOOL_DIR\AmazonCloudWatchAgent-Config.json"
        }
        'Windows Server 2019' {
            Write-Log ("# Save Amazon CloudWatch Agent Config Files [Windows Server 2019] : Windows OS Version : " + $WindowsOSVersion)
            Get-WebContentToFile -Uri 'https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_WindowsServer-2019.json' -OutFile "$TOOL_DIR\AmazonCloudWatchAgent-Config.json"
        }
        'Windows Server 2022' {
            Write-Log ("# Save Amazon CloudWatch Agent Config Files [Windows Server 2022] : Windows OS Version : " + $WindowsOSVersion)
            Get-WebContentToFile -Uri 'https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_WindowsServer-2022.json' -OutFile "$TOOL_DIR\AmazonCloudWatchAgent-Config.json"
        }
        default {
            Write-Log ("# Save Amazon CloudWatch Agent Config Files [Windows Server 2022] : Windows OS Version : " + $WindowsOSVersion)
            Get-WebContentToFile -Uri 'https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_WindowsServer-2022.json' -OutFile "$TOOL_DIR\AmazonCloudWatchAgent-Config.json"
        }
    }
}
else {
    # [No Target Server OS]
    Write-Log ("# [Information] [Save Amazon CloudWatch Agent Config Files] No Target Windows OS Version : " + $WindowsOSVersion)
}

# Check Windows OS Version[Windows Server 2008 R2, 2012, 2012 R2, 2016, 2019]
if ($WindowsOSVersion -match "^6.1|^6.2|^6.3|^10.0") {

    # Amazon CloudWatch Agent Support Windows OS Version
    # http://docs.aws.amazon.com/ja_jp/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html
    Write-Log "# [AWS - EC2-AmazonCloudWatchAgent] Windows OS Version : $WindowsOSVersion"

    # Package Download System Utility (Amazon CloudWatch Agent)
    # http://docs.aws.amazon.com/ja_jp/AmazonCloudWatch/latest/monitoring/install-CloudWatch-Agent-on-EC2-Instance-fleet.html
    Write-Log "# Package Download System Utility (Amazon CloudWatch Agent)"
    Get-WebContentToFile -Uri 'https://s3.amazonaws.com/amazoncloudwatch-agent/windows/amd64/latest/amazon-cloudwatch-agent.msi' -OutFile "$TOOL_DIR\amazon-cloudwatch-agent.msi"

    # Package Install System Utility (Amazon CloudWatch Agent)
    Write-Log "# Package Install System Utility (Amazon CloudWatch Agent)"
    Start-Process "msiexec.exe" -Verb runas -Wait -ArgumentList @("/i $TOOL_DIR\amazon-cloudwatch-agent.msi", "/qn", "/L*v $LOGS_DIR\APPS_AWS_AmazonCloudWatchAgentSetup.log")

    Start-Sleep -Seconds 5

    # Get Service Status
    $ServiceStatusForAmazonCloudWatchAgent = (Get-Service -Name "AmazonCloudWatchAgent" | Select-Object Displayname, Status, ServiceName)
    Write-Log ("# [Windows - OS Settings] Service - [Displayname - {0}] [ServiceName - {1}] [Status - {2}]" -f $ServiceStatusForAmazonCloudWatchAgent.Displayname, $ServiceStatusForAmazonCloudWatchAgent.ServiceName, $ServiceStatusForAmazonCloudWatchAgent.Status)

    # Package Configuration System Utility (Amazon CloudWatch Agent)
    Write-Log "# Package Configuration System Utility (Amazon CloudWatch Agent)"
    powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" -a fetch-config -m ec2 -c file:"$TOOL_DIR\AmazonCloudWatchAgent-Config.json" -s

    Start-Sleep -Seconds 10

    # Display Windows Server OS Parameter [Amazon CloudWatch Agent Information]
    powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" -m ec2 -a status

    # Get Service Status
    $ServiceStatusForAmazonCloudWatchAgent = (Get-Service -Name "AmazonCloudWatchAgent" | Select-Object Displayname, Status, ServiceName)
    Write-Log ("# [Windows - OS Settings] Service - [Displayname - {0}] [ServiceName - {1}] [Status - {2}]" -f $ServiceStatusForAmazonCloudWatchAgent.Displayname, $ServiceStatusForAmazonCloudWatchAgent.ServiceName, $ServiceStatusForAmazonCloudWatchAgent.Status)

    # Service Automatic Startup Setting (Amazon CloudWatch Agent)
    $AmazonCloudWatchAgentStatus = (Get-WmiObject Win32_Service -Filter "Name='AmazonCloudWatchAgent'").StartMode

    if ($AmazonCloudWatchAgentStatus -ne "Auto") {
        Write-Log "# [AWS - EC2-AmazonCloudWatchAgent] Service Startup Type : $AmazonCloudWatchAgentStatus -> Auto"
        Set-Service -Name "AmazonCloudWatchAgent" -StartupType Automatic

        Start-Sleep -Seconds 5

        $AmazonCloudWatchAgentStatus = (Get-WmiObject Win32_Service -Filter "Name='AmazonCloudWatchAgent'").StartMode
        Write-Log "# [AWS - EC2-AmazonCloudWatchAgent] Service Startup Type : $AmazonCloudWatchAgentStatus"
    }
}
else {
    # Amazon CloudWatch Agent Support Windows OS Version (None)
    Write-Log ("# [AWS - EC2-AmazonCloudWatchAgent] Windows OS Version : " + $WindowsOSVersion + " - Not Suppoort Windows OS Version")
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Install (Amazon EC2 Elastic GPU Software)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Package Install System Utility (Amazon EC2 Elastic GPU Software)"

# Initialize Parameter
Set-Variable -Name ElasticGpuId -Scope Script -Value ($Null)
Set-Variable -Name ElasticGpuResponseError -Scope Script -Value ($Null)

# Check Region
if ($Region -match "^ap-northeast-1|^ap-southeast-1|^ap-southeast-2|^eu-central-1|^eu-west-1|^us-east-1|^us-east-2|^us-west-2") {

    # Amazon EC2 Elastic GPUs Support AWS Regions
    # https://aws.amazon.com/ec2/elastic-gpus/pricing/?nc1=h_ls
    Write-Log "# [AWS - EC2-ElasticGPU] AWS Region : $Region"

    # Check Amazon EC2 Elastic GPUs Support InstanceType
    # https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/elastic-gpus.html
    Write-Log "# Check Amazon EC2 Elastic GPUs Support InstanceType"
    if ($InstanceType -match "^c3.*|^c4.*|^c5.*|^m3.*|^m4.*|^m5.*|^r3.*|^r4.*|^x1.*|^d2.*|^i3.*|^t2.medium|^t2.large|^t2.xlarge|^t2.2xlarge") {
        # Amazon EC2 Elastic GPUs Support InstanceType
        Write-Log "# [AWS - EC2-ElasticGPU] InstanceType : $InstanceType"
    }
    else {
        # Amazon EC2 Elastic GPUs Support InstanceType (None)
        Write-Log ("# [AWS - EC2-ElasticGPU] InstanceType : " + $InstanceType + " - Not Suppoort Instance Type")
    }

    # Check Amazon EC2 Elastic GPU ID
    $ElasticGpuResponseError = try { Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/elastic-gpus/associations" -UseBasicParsing } catch { $_.Exception.Response.StatusCode.Value__ }
    if ([String]::IsNullOrEmpty($ElasticGpuResponseError)) {
        # The Amazon EC2 Elastic GPU is attached
        Write-Log "# [AWS - EC2-ElasticGPU] Elastic GPU is attached"
        Set-Variable -Name ElasticGpuId -Option Constant -Scope Script -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/elastic-gpus/associations")
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

        # Logging Amazon EC2 Elastic GPU Information from EC2 Instance MetaData
        Write-Log "# [AWS - EC2-ElasticGPU] ElasticGpuId : $ElasticGpuId"
        Write-Log "# [AWS - EC2-ElasticGPU] ElasticGpuType : $ElasticGpuType"
        Write-Log "# [AWS - EC2-ElasticGPU] ElasticGpuEniIpAddress : $ElasticGpuEniIpAddress"

        $ElasticGpuInformation | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-EC2_ElasticGPU_EC2InstanceMetaData-Information.txt" -Append -Force

        # Logging Amazon EC2 Elastic GPU Information from AWS Tools for Windows PowerShell
        if ($RoleName) {
            Get-EC2ElasticGpu -Filter @{Name = "instance-id"; Values = $InstanceId } | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-EC2_ElasticGPU-Information.txt" -Append -Force
        }

        # Logging Amazon EC2 Elastic GPU ENI Information from AWS Tools for Windows PowerShell
        if ($RoleName) {
            Set-Variable -Name ElasticGpuEniInsterface -Scope Script -Value (Get-EC2NetworkInterface | Where-Object { $_.Description -eq "EC2 Elastic GPU ENI" } | Where-Object { $_.PrivateIpAddress -eq ${ElasticGpuEniIpAddress} })
            Set-Variable -Name ElasticGpuEniId -Scope Script -Value ($ElasticGpuEniInsterface.NetworkInterfaceId)

            Write-Log "# [AWS - EC2-ElasticGPU] ElasticGpuEniId : $ElasticGpuEniId"

            $ElasticGpuEniInsterface | ConvertTo-Json -Depth 100 | Out-File "$LOGS_DIR\AWS-EC2_ElasticGPU_ENI-Information.txt" -Append -Force
        }

        # Check Windows OS Version[Windows Server 2012 R2, 2016]
        if ($WindowsOSVersion -match "^6.3|^10.0") {

            # Amazon EC2 Elastic GPUs Support Windows OS Version
            # https://aws.amazon.com/jp/ec2/elastic-gpus/faqs/
            Write-Log "# [AWS - EC2-ElasticGPU] Windows OS Version : $WindowsOSVersion"

            # Package Download System Utility (Amazon EC2 Elastic GPU Software)
            # https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/working-with-elastic-gpus.html
            Write-Log "# Package Download System Utility (Amazon EC2 Elastic GPU Software)"
            Get-WebContentToFile -Uri 'http://ec2-elasticgpus.s3-website-us-east-1.amazonaws.com/latest' -OutFile "$TOOL_DIR\EC2ElasticGPUs_Manager.msi"

            # Package Install System Utility (Amazon EC2 Elastic GPU Software)
            Write-Log "# Package Install System Utility (Amazon EC2 Elastic GPU Software)"
            Start-Process "msiexec.exe" -Verb runas -Wait -ArgumentList @("/i $TOOL_DIR\EC2ElasticGPUs_Manager.msi", "/qn", "/L*v $LOGS_DIR\APPS_EC2ElasticGPUs_Manager.log")
            Start-Sleep -Seconds 10

            # Setting Application Path (Amazon EC2 Elastic GPU Software)
            [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\Amazon\EC2ElasticGPUs\manager\", [EnvironmentVariableTarget]::Machine)

            # Service Automatic Startup Setting (Amazon EC2 Elastic GPU Manager)
            Get-Service -Name "EC2ElasticGPUs_Manager"

            $EC2ElasticGPUs_ManagerStatus = (Get-WmiObject Win32_Service -Filter "Name='EC2ElasticGPUs_Manager'").StartMode

            if ($EC2ElasticGPUs_ManagerStatus -ne "Auto") {
                Write-Log "# [AWS - EC2-ElasticGPU Manager] Service Startup Type : $EC2ElasticGPUs_ManagerStatus -> Auto"
                Set-Service -Name "EC2ElasticGPUs_Manager" -StartupType Automatic

                Start-Sleep -Seconds 5

                $EC2ElasticGPUs_ManagerStatus = (Get-WmiObject Win32_Service -Filter "Name='EC2ElasticGPUs_Manager'").StartMode
                Write-Log "# [AWS - EC2-ElasticGPU Manager] Service Startup Type : $EC2ElasticGPUs_ManagerStatus"
            }

            # Display Windows Server OS Parameter [Amazon EC2 Elastic GPU Manager Information]
            cmd.exe /c "C:\Program Files\Amazon\EC2ElasticGPUs\manager\egcli.exe" 2>&1

            Start-Process -FilePath "C:\Program Files\Amazon\EC2ElasticGPUs\manager\egcli.exe" -Verb runas -RedirectStandardOutput "$LOGS_DIR\APPS_AmazonEC2ElasticGpuManagerStatus.log" -RedirectStandardError "$LOGS_DIR\APPS_AmazonEC2ElasticGpuManagerStatusError.log"
        }
        else {
            # Amazon EC2 Elastic GPUs Support InstanceType (None)
            Write-Log ("# [AWS - EC2-ElasticGPU] Windows OS Version : " + $WindowsOSVersion + " - Not Suppoort Windows OS Version")
        }
    }
}
else {
    # Amazon EC2 Elastic GPUs Support AWS Regions (None)
    Write-Log ("# [AWS - EC2-ElasticGPU] AWS Region : " + $Region + " - Not Suppoort AWS Region")
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Install (PowerShell 7.3)
# https://docs.microsoft.com/ja-jp/powershell/scripting/install/installing-powershell-core-on-windows?view=powershell-7
# https://github.com/PowerShell/PowerShell
#
# [Stable Version]
# https://aka.ms/powershell-release?tag=stable
#
# [LTS Version]
# https://aka.ms/powershell-release?tag=lts
#
# https://docs.aws.amazon.com/ja_jp/powershell/latest/userguide/pstools-getting-set-up-windows.html
# https://www.powershellgallery.com/packages/AWSPowerShell.NetCore/
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Package Install System Utility (PowerShell 7.3)"

# Initialize Parameter [# Depends on PowerShell v7.2 version information]
Set-Variable -Name PWSH -Scope Script -Value "C:\Program Files\PowerShell\7\pwsh.exe"
Set-Variable -Name PWSH_INSTALLER_URL -Scope Script -Value "https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/PowerShell-7.3.4-win-x64.msi"
Set-Variable -Name PWSH_INSTALLER_FILE -Scope Script -Value ($PWSH_INSTALLER_URL.Substring($PWSH_INSTALLER_URL.LastIndexOf("/") + 1))

# Check Windows OS Version [Windows Server 2008R2, 2012, 2012 R2, 2016, 2019]
if ($WindowsOSVersion -match "^6.1|^6.2|^6.3|^10.0") {

    # Package Download Commnand-Line Shell (PowerShell 7.3)
    Write-Log "# Package Download Commnand-Line Shell (PowerShell 7.3)"
    Get-WebContentToFile -Uri "$PWSH_INSTALLER_URL" -OutFile "$TOOL_DIR\$PWSH_INSTALLER_FILE"

    # Package Install Commnand-Line Shell (PowerShell 7.3)
    Write-Log "# Package Install Commnand-Line Shell (PowerShell 7.3)"
    Start-Process "msiexec.exe" -Verb runas -Wait -ArgumentList @("/i $TOOL_DIR\$PWSH_INSTALLER_FILE", "/qn", "/L*v $LOGS_DIR\APPS_MicrosoftPowerShellSetup.log")
    Start-Sleep -Seconds 10

    # Package Configure Commnand-Line Shell (PowerShell 7.3)
    Write-Log "# Package Configure Commnand-Line Shell (PowerShell 7.3)"

    # Install AWSPowerShell.NetCore
    # Start-Process -FilePath $PWSH -Verb runas -PassThru -Wait -WindowStyle Hidden -ArgumentList @("-Command", "Get-Module -ListAvailable")
    # Start-Process -FilePath $PWSH -Verb runas -PassThru -Wait -WindowStyle Hidden -ArgumentList @("-Command", "Install-Module -Name AWSPowerShell.NetCore -AllowClobber -Force")
    # Start-Process -FilePath $PWSH -Verb runas -PassThru -Wait -WindowStyle Hidden -ArgumentList @("-Command", "Get-Module -ListAvailable")
    # Start-Process -FilePath $PWSH -Verb runas -PassThru -Wait -WindowStyle Hidden -ArgumentList @("-Command", "Get-AWSPowerShellVersion")

    # Install AWS.Tools.Common
    # Start-Process -FilePath $PWSH -Verb runas -PassThru -Wait -WindowStyle Hidden -ArgumentList @("-Command", "Get-Module -ListAvailable")
    # Start-Process -FilePath $PWSH -Verb runas -PassThru -Wait -WindowStyle Hidden -ArgumentList @("-Command", "Install-Module -Name AWS.Tools.Common -AllowClobber -Force")
    # Start-Process -FilePath $PWSH -Verb runas -PassThru -Wait -WindowStyle Hidden -ArgumentList @("-Command", "Get-Module -ListAvailable")
    # Start-Process -FilePath $PWSH -Verb runas -PassThru -Wait -WindowStyle Hidden -ArgumentList @("-Command", "Get-AWSPowerShellVersion")
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Install (Windows Admin Center)
# https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/overview
# https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Package Install System Utility (Windows Admin Center)"

# Initialize Parameter
Set-Variable -Name WAC_INSTALLER_URL -Scope Script -Value "https://aka.ms/wacdownload"
Set-Variable -Name WAC_INSTALLER_FILE -Scope Script -Value "WindowsAdminCenter.msi"
Set-Variable -Name WAC_HTTPS_PORT -Scope Script -Value "443"

# Check Windows OS Version [Windows Server 2012, 2012 R2, 2016]
if ($WindowsOSVersion -match "^6.2|^6.3|^10.0") {

    # Package Download Web-based System Administrator Tool (Windows Admin Center)
    Write-Log "# Package Download Web-based System Administrator Tool (Windows Admin Center)"
    Get-WebContentToFile -Uri "$WAC_INSTALLER_URL" -OutFile "$TOOL_DIR\$WAC_INSTALLER_FILE"

    # Package Install Web-based System Administrator Tool (Windows Admin Center)
    ## Write-Log "# Package Install Web-based System Administrator Tool (Windows Admin Center)"
    ## Start-Process "msiexec.exe" -Verb runas -Wait -ArgumentList @("/i $TOOL_DIR\$WAC_INSTALLER_FILE", "/qn", "/L*v $LOGS_DIR\APPS_PowerShellCoreSetup.log", "SME_PORT=$WAC_HTTPS_PORT", "SSL_CERTIFICATE_OPTION=generate")
    ## Start-Sleep -Seconds 10

}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Install (SQL Server Management Studio)
# https://docs.microsoft.com/ja-jp/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Package Install Database Administration Tool (SQL Server Management Studio)"

# Initialize Parameter
Set-Variable -Name SSMS_INSTALLER_URL -Scope Script -Value "https://go.microsoft.com/fwlink/?linkid=870039"
Set-Variable -Name SSMS_INSTALLER_FILE -Scope Script -Value "SSMS-Setup-JPN.exe"

# Check Windows OS Version [Windows Server 2008R2, 2012, 2012 R2, 2016]
if ($WindowsOSVersion -match "^6.1|^6.2|^6.3|^10.0") {

    # Package Download Database Administration Tool (SQL Server Management Studio)
    ## Write-Log "# Package Download Database Administration Tool (SQL Server Management Studio)"
    ## Get-WebContentToFile -Uri "$SSMS_INSTALLER_URL" -OutFile "$TOOL_DIR\$SSMS_INSTALLER_FILE"


    # Package Install Database Administration Tool (SQL Server Management Studio)
    ## Write-Log "# Package Install Database Administration Tool (SQL Server Management Studio)"
    ## Start-Process -FilePath "$TOOL_DIR\$SSMS_INSTALLER_FILE" -Verb runas -ArgumentList @("/install ", "/quiet", "/passive", "/norestart", "/LOG=C:\EC2-Bootstrap\Logs\APPS_SSMS_Setup.log")
    ## Start-Sleep -Seconds 10

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
#  [Amazon EC2 G4(G4dn) Instance Family]
#  NVIDIA T4 Tensor Core GPU
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1
#    -> Tesla : 7
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=7
#    -> [psid] T-Series : 110
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=110
#    -> [pfid] Tesla T4 : 883
#
#  [Amazon EC2 G4(G4ad) Instance Family]
#  AMD Radeon Pro V520 GPU
#   https://www.amd.com/en/products/server-accelerators/amd-radeon-pro-v520
#
#  [Amazon EC2 G5 Instance Family]
#  NVIDIA A10G Tensor Core GPU
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1
#    -> Tesla : 7
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=7
#    -> [psid] A-Series : 118
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=118
#    -> [pfid] NVIDIA A10 : 955
#
#  [Amazon EC2 G5(G5g) Instance Family]
#  NVIDIA T4G Tensor Core GPU
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1
#    -> Tesla : 7
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=7
#    -> [psid] T-Series : 110
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=110
#    -> [pfid] Tesla T4 : 883
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
#  [Amazon EC2 P4 Instance Family]
#  NVIDIA A100 Tensor Core GPU
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=1
#    -> Tesla : 7
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2&ParentID=7
#    -> [psid] A-Series : 118
#   http://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3&ParentID=118
#    -> [pfid] NVIDIA A100 : 923
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
#    -> Windows Server 2019       : 119
#    -> Windows Server 2022       : 134
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

Write-Log "# [CUDA] Check Amazon EC2 G2 & G3 & P2 & P3 Instance Family"

# Package Download NVIDIA CUDA Toolkit (for Amazon EC2 G2/G3/P2/P3 Instance Family)
# http://docs.nvidia.com/cuda/cuda-installation-guide-microsoft-windows/index.html
# https://developer.nvidia.com/cuda-downloads
if ($InstanceType -match "^g2.*|^g3.*|^g4dn.*|^p2.*|^p3.*") {
    Write-Log "# Package Download NVIDIA CUDA Toolkit (for Amazon EC2 G2/G3/G4/P2/P3 Instance Family)"
    if ($WindowsOSVersion) {
        if ($WindowsOSVersion -eq "10.0") {
            # [Windows Server 2016]
            # $CUDA_toolkit = Invoke-RestMethod -Uri 'https://developer.nvidia.com/cuda-downloads?target_os=Windows&target_arch=x86_64&target_version=Server2016&target_type=exelocal'
            $CUDA_toolkit_url = "https://developer.download.nvidia.com/compute/cuda/11.1.0/local_installers/cuda_11.1.0_456.43_win10.exe"
            Write-Log ("# [Information] Package Download NVIDIA CUDA Toolkit URL : " + $CUDA_toolkit_url)
            Get-WebContentToFile -Uri $CUDA_toolkit_url -OutFile "$TOOL_DIR\NVIDIA-CUDA-Toolkit_v10_for_WindowsServer2016.exe"
            # [Windows Server 2019]
            # $CUDA_toolkit = Invoke-RestMethod -Uri 'https://developer.nvidia.com/cuda-downloads?target_os=Windows&target_arch=x86_64&target_version=Server2019&target_type=exelocal'
            # $CUDA_toolkit_url = "https://developer.download.nvidia.com/compute/cuda/11.1.0/local_installers/cuda_11.1.0_456.43_win10.exe"
            # Write-Log ("# [Information] Package Download NVIDIA CUDA Toolkit URL : " + $CUDA_toolkit_url)
            # Get-WebContentToFile -Uri $CUDA_toolkit_url -OutFile "$TOOL_DIR\NVIDIA-CUDA-Toolkit_v10_for_WindowsServer2019.exe"
        }
        else {
            # [No Target Server OS]
            Write-Log ("# [Information] [NVIDIA CUDA Toolkit] No Target Server OS Version : " + $WindowsOSVersion)
        }
    }
    else {
        # [Undefined Server OS]
        Write-Log "# [Warning] [NVIDIA CUDA Toolkit] Undefined Server OS"
    }
}


Write-Log "# [GPU Driver:NVIDIA GRID K520] Check Amazon EC2 G2 Instance Family"

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
            Get-WebContentToFile -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2008R2.exe"
        }
        elseif ($WindowsOSVersion -eq "6.2") {
            # [Windows Server 2012]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=32&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/GRID/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "quadro-tesla-grid-winserv2008-2008r2-2012-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID K520 GPU Driver URL : " + $K520_driverurl)
            Get-WebContentToFile -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2012.exe"
        }
        elseif ($WindowsOSVersion -eq "6.3") {
            # [Windows Server 2012 R2]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/GRID/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "quadro-tesla-grid-winserv2008-2008r2-2012-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID K520 GPU Driver URL : " + $K520_driverurl)
            Get-WebContentToFile -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2012R2.exe"
        }
        elseif ($WindowsOSVersion -eq "10.0") {
            # [Windows Server 2016]
            $K520_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=94&pfid=704&osid=74&lid=1&whql=1&lang=en-us&ctk=0'
            $K520_driverversion = $($K520_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K520_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/GRID/" + ${K520_driverversion} + "/" + ${K520_driverversion} + "-quadro-winserv-2016-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID K520 GPU Driver URL : " + $K520_driverurl)
            Get-WebContentToFile -Uri $K520_driverurl -OutFile "$TOOL_DIR\NVIDIA-GRID-K520-GPU-Driver_for_WindowsServer2016.exe"
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


Write-Log "# [GPU Driver:NVIDIA GRID M60] Check Amazon EC2 G3 Instance Family"

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
            Get-WebContentToFile -Uri $M60_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-M60-GPU-Driver_for_WindowsServer2008R2.exe"
        }
        elseif ($WindowsOSVersion -eq "6.3") {
            # [Windows Server 2012 R2]
            $M60_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=75&pfid=783&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $M60_driverversion = $($M60_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $M60_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${M60_driverversion} + "/" + ${M60_driverversion} + "-tesla-desktop-winserver2008-2012r2-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID M60 GPU Driver URL : " + $M60_driverurl)
            Get-WebContentToFile -Uri $M60_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-M60-GPU-Driver_for_WindowsServer2012R2.exe"
        }
        elseif ($WindowsOSVersion -eq "10.0") {
            # [Windows Server 2016]
            $M60_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=75&pfid=783&osid=74&lid=1&whql=1&lang=en-us&ctk=0'
            $M60_driverversion = $($M60_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $M60_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${M60_driverversion} + "/" + ${M60_driverversion} + "-tesla-desktop-winserver2016-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA GRID M60 GPU Driver URL : " + $M60_driverurl)
            Get-WebContentToFile -Uri $M60_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-M60-GPU-Driver_for_WindowsServer2016.exe"
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


Write-Log "# [GPU Driver:NVIDIA T4 Tensor Core GPU] Check Amazon EC2 G4 Instance Family"

# Package Download NVIDIA T4 Tensor Core GPU Driver (for Amazon EC2 G4 Instance Family)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/accelerated-computing-instances.html
if ($InstanceType -match "^g4dn.*") {
    Write-Log "# Package Download NVIDIA T4 Tensor Core GPU Driver (for Amazon EC2 G4 Instance Family)"
    if ($WindowsOSVersion) {
        if ($WindowsOSVersion -eq "6.3") {
            # [Windows Server 2012 R2]
            $T4_drivers = Invoke-RestMethod -Uri 'https://www.nvidia.com/Download/processFind.aspx?psid=110&pfid=883&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $T4_driverversion = $($T4_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $T4_driverurl = "http://us.download.nvidia.com/tesla/" + ${T4_driverversion} + "/" + ${T4_driverversion} + "-tesla-desktop-winserver2008-2012r2-64bit-international.exe"
            Write-Log ("# [Information] Package Download NVIDIA T4 Tensor Core GPU Driver URL : " + $T4_driverurl)
            Get-WebContentToFile -Uri $T4_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-T4-GPU-Driver_for_WindowsServer2012R2.exe"
        }
        elseif ($WindowsOSVersion -eq "10.0") {
            # [Windows Server 2016]
            $T4_drivers = Invoke-RestMethod -Uri 'https://www.nvidia.com/Download/processFind.aspx?psid=110&pfid=883&osid=74&lid=1&whql=1&lang=en-us&ctk=0'
            $T4_driverversion = $($T4_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $T4_driverurl = "http://us.download.nvidia.com/tesla/" + ${T4_driverversion} + "/" + ${T4_driverversion} + "-tesla-desktop-winserver-2019-2016-international.exe"
            Write-Log ("# [Information] Package Download NVIDIA T4 Tensor Core GPU Driver URL : " + $T4_driverurl)
            Get-WebContentToFile -Uri $T4_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-T4-GPU-Driver_for_WindowsServer2016.exe"

            # [Windows Server 2019]
            # $T4_drivers = Invoke-RestMethod -Uri 'https://www.nvidia.com/Download/processFind.aspx?psid=110&pfid=883&osid=119&lid=1&whql=1&lang=en-us&ctk=0'
            # $T4_driverversion = $($T4_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            # $T4_driverurl = "http://us.download.nvidia.com/tesla/" + ${T4_driverversion} + "/" + ${T4_driverversion} + "-tesla-desktop-winserver-2019-2016-international.exe"
            # Write-Log ("# [Information] Package Download NVIDIA T4 Tensor Core GPU Driver URL : " + $T4_driverurl)
            # Get-WebContentToFile -Uri $T4_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-T4-GPU-Driver_for_WindowsServer2019.exe"
        }
        else {
            # [No Target Server OS]
            Write-Log ("# [Information] [NVIDIA T4 Tensor Core GPU Driver] No Target Server OS Version : " + $WindowsOSVersion)
        }
    }
    else {
        # [Undefined Server OS]
        Write-Log "# [Warning] [NVIDIA T4 Tensor Core GPU Driver] Undefined Server OS"
    }
}


Write-Log "# [GPU Driver:NVIDIA Tesla K80] Check Amazon EC2 P2 Instance Family"

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
            Get-WebContentToFile -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2008R2.exe"
        }
        elseif ($WindowsOSVersion -eq "6.3") {
            # [Windows Server 2012 R2]
            $K80_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=91&pfid=762&osid=44&lid=1&whql=1&lang=en-us&ctk=0'
            $K80_driverversion = $($K80_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K80_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K80_driverversion} + "/" + ${K80_driverversion} + "-tesla-desktop-winserver2008-2012r2-64bit-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA Tesla K80 GPU Driver URL : " + $K80_driverurl)
            Get-WebContentToFile -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2012R2.exe"
        }
        elseif ($WindowsOSVersion -eq "10.0") {
            # [Windows Server 2016]
            $K80_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=91&pfid=762&osid=74&lid=1&whql=1&lang=en-us&ctk=0'
            $K80_driverversion = $($K80_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $K80_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${K80_driverversion} + "/" + ${K80_driverversion} + "-tesla-desktop-winserver2016-international-whql.exe"
            Write-Log ("# [Information] Package Download NVIDIA Tesla K80 GPU Driver URL : " + $K80_driverurl)
            Get-WebContentToFile -Uri $K80_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-K80-GPU-Driver_for_WindowsServer2016.exe"
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


Write-Log "# [GPU Driver:NVIDIA Tesla V100] Check Amazon EC2 P3 Instance Family"

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
            Get-WebContentToFile -Uri $V100_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-V100-GPU-Driver_for_WindowsServer2012R2.exe"
        }
        elseif ($WindowsOSVersion -eq "10.0") {
            # [Windows Server 2016]
            $V100_drivers = Invoke-RestMethod -Uri 'http://www.nvidia.com/Download/processFind.aspx?psid=105&pfid=857&osid=74&lid=1&whql=1&lang=en-us&ctk=0'
            $V100_driverversion = $($V100_drivers -match '<td class="gridItem">(\d\d\d\.\d\d)</td>' | Out-Null; $Matches[1])
            $V100_driverurl = "http://us.download.nvidia.com/Windows/Quadro_Certified/" + ${V100_driverversion} + "/" + ${V100_driverversion} + "-tesla-desktop-winserver2016-international.exe"
            Write-Log ("# [Information] Package Download NVIDIA Tesla V100 GPU Driver URL : " + $V100_driverurl)
            Get-WebContentToFile -Uri $V100_driverurl -OutFile "$TOOL_DIR\NVIDIA-Tesla-V100-GPU-Driver_for_WindowsServer2016.exe"
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


Write-Log "# [GPU Profiler] Check Amazon EC2 G2 & G3 & G4 & P2 & P3 Instance Family"

# Package Download NVIDIA GPUProfiler (for Amazon EC2 G2/G3/P2/P3 Instance Family)
# https://github.com/JeremyMain/GPUProfiler
if ($InstanceType -match "^g2.*|^g3.*|^g4dn.*|^p2.*|^p3.*") {
    Write-Log "# Package Download NVIDIA GPUProfiler (for Amazon EC2 G2/G3/P2 Instance Family)"
    Get-WebContentToFile -Uri 'https://github.com/JeremyMain/GPUProfiler/releases/download/v1.07a/GPUProfiler_v1.07a_x64.zip' -OutFile "$TOOL_DIR\GPUProfiler_v1.07a_x64.zip"
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Storage & Network Driver)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Download (Storage & Network Driver)"

# Package Download Amazon Windows Paravirtual Drivers
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/xen-drivers-overview.html
Write-Log "# Package Download Amazon Windows Paravirtual Drivers"
Get-WebContentToFile -Uri 'https://s3.amazonaws.com/ec2-windows-drivers-downloads/AWSPV/Latest/AWSPVDriver.zip' -OutFile "$TOOL_DIR\AWSPVDriver.zip"

# Package Download AWS NVMe Drivers
# https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/aws-nvme-drivers.html
Write-Log "# Package Download AWS NVMe Drivers"
Get-WebContentToFile -Uri 'https://s3.amazonaws.com/ec2-windows-drivers-downloads/NVMe/Latest/AWSNVMe.zip' -OutFile "$TOOL_DIR\AWSNVMe.zip"

# Package Download Amazon Elastic Network Adapter Driver
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/enhanced-networking-ena.html
Write-Log "# Package Download Amazon Elastic Network Adapter Driver"
Get-WebContentToFile -Uri 'https://s3.amazonaws.com/ec2-windows-drivers-downloads/ENA/Latest/AwsEnaNetworkDriver.zip' -OutFile "$TOOL_DIR\AwsEnaNetworkDriver.zip"

# Package Download Intel Network Driver
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    if ($WindowsOSVersion -eq "6.1") {
        # [Windows Server 2008 R2]
        # https://www.intel.com/content/www/us/en/download/15591/intel-network-adapter-driver-for-windows-server-2008-r2-final-release.html
        Write-Log "# Package Download Intel Network Driver (Windows Server 2008 R2)"
        Get-WebContentToFile -Uri 'https://downloadmirror.intel.com/18725/eng/prowinx64legacy.exe' -OutFile "$TOOL_DIR\Intel-NetworkDriver-PROWinx64_For_WindowsServer2008R2.exe"
    }
    elseif ($WindowsOSVersion -eq "6.2") {
        # [Windows Server 2012]
        # https://www.intel.com/content/www/us/en/download/16789/intel-network-adapter-driver-for-windows-server-2012.html
        Write-Log "# Package Download Intel Network Driver (Windows Server 2012)"
        Get-WebContentToFile -Uri 'https://downloadmirror.intel.com/772075/Wired_driver_28.0_x64.zip' -OutFile "$TOOL_DIR\Intel-NetworkDriver-PROSetx64_For_WindowsServer2012.zip"
    }
    elseif ($WindowsOSVersion -eq "6.3") {
        # [Windows Server 2012 R2]
        # https://www.intel.com/content/www/us/en/download/17480/intel-network-adapter-driver-for-windows-server-2012-r2.html
        Write-Log "# Package Download Intel Network Driver (Windows Server 2012 R2)"
        Get-WebContentToFile -Uri 'https://downloadmirror.intel.com/772074/Wired_driver_28.0_x64.zip' -OutFile "$TOOL_DIR\Intel-NetworkDriver-PROSetx64_For_WindowsServer2012R2.zip"
    }
    elseif ($WindowsOSVersion -eq "10.0") {
        switch ($WindowsOSName) {
            'Windows Server 2016' {
                # [Windows Server 2016]
                # https://www.intel.com/content/www/us/en/download/18737/intel-network-adapter-driver-for-windows-server-2016.html
                Write-Log "# Package Download Intel Network Driver (Windows Server 2016)"
                Get-WebContentToFile -Uri 'https://downloadmirror.intel.com/772073/Wired_driver_28.0_x64.zip' -OutFile "$TOOL_DIR\Intel-NetworkDriver-PROSetx64_For_WindowsServer2016.zip"
            }
            'Windows Server 2019' {
                # [Windows Server 2019]
                # https://www.intel.com/content/www/us/en/download/19372/intel-network-adapter-driver-for-windows-server-2019.html
                Write-Log "# Package Download Intel Network Driver (Windows Server 2019)"
                Get-WebContentToFile -Uri 'https://downloadmirror.intel.com/772072/Wired_driver_28.0_x64.zip' -OutFile "$TOOL_DIR\Intel-NetworkDriver-PROSetx64_For_WindowsServer2019.zip"
            }
            'Windows Server 2022' {
                # [Windows Server 2022]
                # https://www.intel.com/content/www/us/en/download/706171/intel-network-adapter-driver-for-windows-server-2022.html
                Write-Log "# Package Download Intel Network Driver (Windows Server 2019)"
                Get-WebContentToFile -Uri 'https://downloadmirror.intel.com/772066/Wired_driver_28.0_x64.zip' -OutFile "$TOOL_DIR\Intel-NetworkDriver-PROSetx64_For_WindowsServer2022.zip"
            }
            default {
                # [No Target Server OS]
                Write-Log ("# [Information] [Intel Network Driver] No Target Server OS Version : " + $WindowsOSVersion)
            }
        }
    }
    else {
        # [No Target Server OS]
        Write-Log ("# [Information] [Intel Network Driver] No Target Server OS Version : " + $WindowsOSVersion)
    }
}


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Installation (Application)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Installation (Application)"

# Custom Package Installation (Google Chrome 64bit Edition)
# https://cloud.google.com/chrome-enterprise/browser/download/#chrome-browser-download
if ($FLAG_APP_INSTALL -eq $TRUE) {
    # Initialize Parameter
    Set-Variable -Name CHROME_INSTALLER_URL -Scope Script -Value "https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi"
    Set-Variable -Name CHROME_INSTALLER_FILE -Scope Script -Value ($CHROME_INSTALLER_URL.Substring($CHROME_INSTALLER_URL.LastIndexOf("/") + 1))

    # Package Download Modern Web Browser (Google Chrome 64bit Edition)
    Write-Log "# Package Download Modern Web Browser (Google Chrome 64bit Edition)"
    Get-WebContentToFile -Uri "$CHROME_INSTALLER_URL" -OutFile "$TOOL_DIR\$CHROME_INSTALLER_FILE"

    # Package Install Modern Web Browser (Google Chrome 64bit Edition)
    Write-Log "# Package Install Modern Web Browser (Google Chrome 64bit Edition)"
    Start-Process "msiexec.exe" -Verb runas -Wait -ArgumentList @("/i $TOOL_DIR\$CHROME_INSTALLER_FILE", "/quiet", "/norestart", "/L*v $LOGS_DIR\APPS_GoogleChromeSetup.log")
    Start-Sleep -Seconds 5
}

# Custom Package Installation (Microsoft Edge 64bit Edition)
# https://www.microsoft.com/en-us/edge/business/download
if ($FLAG_APP_INSTALL -eq $TRUE) {
    # Initialize Parameter
    Set-Variable -Name EDGE_INSTALLER_URL -Scope Script -Value "http://go.microsoft.com/fwlink/?LinkID=2093437"
    Set-Variable -Name EDGE_INSTALLER_FILE -Scope Script -Value "MicrosoftEdgeEnterpriseX64.msi"

    # Package Download Modern Web Browser (Microsoft Edge 64bit Edition)
    Write-Log "# Package Download Modern Web Browser (Microsoft Edge 64bit Edition)"
    Get-WebContentToFile -Uri "$EDGE_INSTALLER_URL" -OutFile "$TOOL_DIR\$EDGE_INSTALLER_FILE"

    # Package Install Modern Web Browser (Microsoft Edge 64bit Edition)
    Write-Log "# Package Install Modern Web Browser (Microsoft Edge 64bit Edition)"
    Start-Process "msiexec.exe" -Verb runas -Wait -ArgumentList @("/i $TOOL_DIR\$EDGE_INSTALLER_FILE", "/quiet", "/norestart", "/L*v $LOGS_DIR\APPS_MicrosoftEdgeSetup.log")
    Start-Sleep -Seconds 5
}

# Custom Package Installation (7-Zip)
# http://www.7-zip.org/
# https://www.7-zip.org/faq.html
if ($FLAG_APP_INSTALL -eq $TRUE) {
    # Initialize Parameter [# Depends on 7-Zip version information]
    Set-Variable -Name 7ZIP_INSTALLER_URL -Scope Script -Value "https://www.7-zip.org/a/7z2201-x64.exe"
    Set-Variable -Name 7ZIP_INSTALLER_FILE -Scope Script -Value ($7ZIP_INSTALLER_URL.Substring($7ZIP_INSTALLER_URL.LastIndexOf("/") + 1))

    # Package Download File archiver (7-Zip)
    Write-Log "# Package Download File archiver (7-Zip)"
    Get-WebContentToFile -Uri "$7ZIP_INSTALLER_URL" -OutFile "$TOOL_DIR\$7ZIP_INSTALLER_FILE"

    # Package Install File archiver (7-Zip)
    Write-Log "# Package Install File archiver (7-Zip)"
    Start-Process -FilePath "$TOOL_DIR\$7ZIP_INSTALLER_FILE" -Verb runas -Wait -ArgumentList @("/S") | Out-Null
    Start-Sleep -Seconds 5
}

# Custom Package Installation (Tera Term)
# https://ja.osdn.net/projects/ttssh2/
if ($FLAG_APP_INSTALL -eq $TRUE) {
    # Initialize Parameter [# Depends on Tera Term version information]
    Set-Variable -Name TERATERM_INSTALLER_URL -Scope Script -Value "https://osdn.mirror.constant.com//ttssh2/74780/teraterm-4.106.exe"
    Set-Variable -Name TERATERM_INSTALLER_FILE -Scope Script -Value ($TERATERM_INSTALLER_URL.Substring($TERATERM_INSTALLER_URL.LastIndexOf("/") + 1))

    # Package Download Terminal emulator (Tera Term)
    Write-Log "# Package Download Terminal emulator (Tera Term)"
    Get-WebContentToFile -Uri "$TERATERM_INSTALLER_URL" -OutFile "$TOOL_DIR\$TERATERM_INSTALLER_FILE"

    # Package Install Terminal emulator (Tera Term)
    Write-Log "# Package Install Terminal emulator (Tera Term)"
    Start-Process -FilePath "$TOOL_DIR\$TERATERM_INSTALLER_FILE" -Verb runas -Wait -ArgumentList @("/VERYSILENT", "/NORESTART", "/LOG=C:\EC2-Bootstrap\Logs\APPS_TeraTermSetup.log") | Out-Null
    Start-Sleep -Seconds 5
}

# Custom Package Installation (IrfanView)
# https://www.irfanview.net/
# https://www.irfanview.com/faq.htm#PAGE12
# if ($FLAG_APP_INSTALL -eq $TRUE) {

#     # Initialize Parameter [# Depends on IrfanView version information]
#     Set-Variable -Name IRFANVIEW_INSTALLER_URL -Scope Script -Value "https://dforest.watch.impress.co.jp/library/i/irfanview/11557/iview456_x64_setup.exe"
#     Set-Variable -Name IRFANVIEW_INSTALLER_FILE -Scope Script -Value ($IRFANVIEW_INSTALLER_URL.Substring($IRFANVIEW_INSTALLER_URL.LastIndexOf("/") + 1))
#     Set-Variable -Name IRFANVIEW_PLUGIN_INSTALLER_URL -Scope Script -Value "https://dforest.watch.impress.co.jp/library/i/irfanview/11592/iview456_plugins_x64_setup.exe"
#     Set-Variable -Name IRFANVIEW_PLUGIN_INSTALLER_FILE -Scope Script -Value ($IRFANVIEW_PLUGIN_INSTALLER_URL.Substring($IRFANVIEW_PLUGIN_INSTALLER_URL.LastIndexOf("/") + 1))

#     # Package Download Graphic Viewer (IrfanView)
#     Write-Log "# Package Download Graphic Viewer (IrfanView)"
#     Get-WebContentToFile -Uri "$IRFANVIEW_INSTALLER_URL" -OutFile "$TOOL_DIR\$IRFANVIEW_INSTALLER_FILE"

#     # Package Install Graphic Viewer (IrfanView)
#     Write-Log "# Package Install Graphic Viewer (IrfanView)"
#     Start-Process -FilePath "$TOOL_DIR\$IRFANVIEW_INSTALLER_FILE" -Verb runas -Wait -ArgumentList @("/silent", "/desktop=1", "/thumbs=0", "/group=1", "/allusers=1", "/assoc=1", "/allusers=1", "/ini=%APPDATA%\IrfanView") | Out-Null
#     Start-Sleep -Seconds 5

#     # Package Download Graphic Viewer (IrfanView All Plugins)
#     Write-Log "# Package Download Graphic Viewer (IrfanView All Plugins)"
#     Get-WebContentToFile -Uri "$IRFANVIEW_PLUGIN_INSTALLER_URL" -OutFile "$TOOL_DIR\$IRFANVIEW_PLUGIN_INSTALLER_FILE"

#     # Package Install Graphic Viewer (IrfanView All Plugins)
#     Write-Log "# Package Install Graphic Viewer (IrfanView All Plugins)"
#     Start-Process -FilePath "$TOOL_DIR\$IRFANVIEW_PLUGIN_INSTALLER_FILE" -Verb runas -Wait -ArgumentList @("/silent") | Out-Null
#     Start-Sleep -Seconds 5
# }

# [Caution : Finally the installation process]
# Custom Package Installation (Visual Studio Code 64bit Edition)
if ($FLAG_APP_INSTALL -eq $TRUE) {
    # Initialize Parameter
    Set-Variable -Name VSCODE_INSTALLER_URL -Scope Script -Value "https://go.microsoft.com/fwlink/?linkid=852157"
    Set-Variable -Name VSCODE_INSTALLER_FILE -Scope Script -Value "VSCodeSetup-x64.exe"

    # Package Download Text Editor (Visual Studio Code 64bit Edition)
    Write-Log "# Package Download Text Editor (Visual Studio Code 64bit Edition)"
    Get-WebContentToFile -Uri "$VSCODE_INSTALLER_URL" -OutFile "$TOOL_DIR\$VSCODE_INSTALLER_FILE"

    # Package Install Text Editor (Visual Studio Code 64bit Edition)
    Write-Log "# Package Install Text Editor (Visual Studio Code 64bit Edition)"
    Start-Process -FilePath "$TOOL_DIR\$VSCODE_INSTALLER_FILE" -Verb runas -Wait -ArgumentList @("/verysilent", "/norestart", "/suppressmsgboxes", "/mergetasks=!runCode, desktopicon, addcontextmenufiles, addcontextmenufolders, associatewithfiles, addtopath", "/LOG=C:\EC2-Bootstrap\Logs\APPS_MicrosoftVisualStudioCodeSetup.log") | Out-Null
}



#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (System Utility - AWS Tools)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Download (System Utility - AWS Tools)"

# Package Download System Utility (EC2Config)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/UsingConfig_Install.html
# if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
#     if ($WindowsOSVersion -match "^5.*|^6.*") {
#         Write-Log "# Package Download System Utility (EC2Config)"
#         Get-WebContentToFile -Uri 'https://s3.amazonaws.com/ec2-downloads-windows/EC2Config/EC2Install.zip' -OutFile "$TOOL_DIR\EC2Install.zip"
#     }
# }

# Package Download System Utility (EC2Launch)
# http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2launch.html
# if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
#     if ($WindowsOSVersion -match "^10.*") {
#         Write-Log "# Package Download System Utility (EC2Launch)"
#         Get-WebContentToFile -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Launch/latest/EC2-Windows-Launch.zip' -OutFile "$TOOL_DIR\EC2-Windows-Launch.zip"
#         Get-WebContentToFile -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/EC2Launch/latest/install.ps1' -OutFile "$TOOL_DIR\EC2-Windows-Launch-install.ps1"
#     }
# }

# Package Download System Utility (EC2Launch v2)
# https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/ec2launch-v2.html
# https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/ec2launch-v2-install.html
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    if ($WindowsOSVersion -match "^5.*|^6.*|^10.0") {
        Write-Log "# Package Download System Utility (EC2Launch v2)"
        Get-WebContentToFile -Uri 'https://s3.amazonaws.com/amazon-ec2launch-v2/windows/amd64/latest/AmazonEC2Launch.msi' -OutFile "$TOOL_DIR\AmazonEC2Launch.msi"

        Write-Log "# Package Download System Utility (EC2Launch v2 - Migration Tool)"
        Get-WebContentToFile -Uri 'https://s3.amazonaws.com/amazon-ec2launch-v2-utils/MigrationTool/windows/amd64/latest/EC2LaunchMigrationTool.zip' -OutFile "$TOOL_DIR\EC2LaunchMigrationTool.zip"
    }
}

# Package Download System Utility (AWS Tools for Windows PowerShell)
# https://aws.amazon.com/jp/powershell/
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    Write-Log "# Package Download System Utility (AWS Tools for Windows PowerShell)"
    Get-WebContentToFile -Uri 'https://sdk-for-net.amazonwebservices.com/latest/AWSToolsAndSDKForNet.msi' -OutFile "$TOOL_DIR\AWSToolsAndSDKForNet.msi"
}

# Package Download System Utility (Session Manager Plugin for the AWS CLI)
# https://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    Write-Log "# Package Download System Utility (Session Manager Plugin for the AWS CLI)"
    Get-WebContentToFile -Uri 'https://s3.amazonaws.com/session-manager-downloads/plugin/latest/windows/SessionManagerPluginSetup.exe' -OutFile "$TOOL_DIR\SessionManagerPluginSetup.exe"
}

# Package Download System Utility (NoSQL Workbench for Amazon DynamoDB)
# https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/workbench.settingup.html
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    Write-Log "# Package Download System Utility (NoSQL Workbench for Amazon DynamoDB)"
    Get-WebContentToFile -Uri 'https://s3.amazonaws.com/nosql-workbench/WorkbenchDDBLocal-win.exe' -OutFile "$TOOL_DIR\WorkbenchDDBLocal-win.exe"
}

# Package Download System Utility (AWS Directory Service PortTest Application)
# http://docs.aws.amazon.com/ja_jp/workspaces/latest/adminguide/connect_verification.html
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    Write-Log "# Package Download System Utility (AWS Directory Service PortTest Application)"
    Get-WebContentToFile -Uri 'http://docs.aws.amazon.com/directoryservice/latest/admin-guide/samples/DirectoryServicePortTest.zip' -OutFile "$TOOL_DIR\DirectoryServicePortTest.zip"
}

# Package Download System Utility (AWSLogCollector)
#
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    Write-Log "# Package Download System Utility (AWSLogCollector)"
    Get-WebContentToFile -Uri 'https://ec2-downloads-windows.s3.amazonaws.com/Scripts/AWSLogCollector.zip' -OutFile "$TOOL_DIR\AWSLogCollector.zip"
}

# Package Download System Utility (AWS Diagnostics for Windows Server)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/Windows-Server-Diagnostics.html
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    Write-Log "# Package Download System Utility (AWS Diagnostics for Windows Server)"
    Get-WebContentToFile -Uri 'https://s3.amazonaws.com/ec2-downloads-windows/AWSDiagnostics/AWSDiagnostics.zip' -OutFile "$TOOL_DIR\AWSDiagnostics.zip"
}

# Package Download System Utility (AWS ElasticWolf Client Console)
# https://aws.amazon.com/jp/tools/aws-elasticwolf-client-console/
# if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
#     Write-Log "# Package Download System Utility (AWS ElasticWolf Client Console)"
#     Get-WebContentToFile -Uri 'https://s3-us-gov-west-1.amazonaws.com/elasticwolf/ElasticWolf-win-5.1.7.zip' -OutFile "$TOOL_DIR\ElasticWolf-win-5.1.7.zip"
# }


#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (System Utility - 3rd Party)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Download (System Utility - 3rd Party)"

# Package Download System Utility (Sysinternals Suite)
# https://docs.microsoft.com/ja-jp/sysinternals/downloads/sysinternals-suite
# https://technet.microsoft.com/ja-jp/sysinternals/bb842062.aspx
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    Write-Log "# Package Download System Utility (Sysinternals Suite)"
    Get-WebContentToFile -Uri 'https://download.sysinternals.com/files/SysinternalsSuite.zip' -OutFile "$TOOL_DIR\SysinternalsSuite.zip"
}

# Package Download System Utility (System Explorer)
# http://systemexplorer.net/
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    Write-Log "# Package Download System Utility (System Explorer)"
    Get-WebContentToFile -Uri 'http://systemexplorer.net/download/SystemExplorerSetup.exe' -OutFile "$TOOL_DIR\SystemExplorerSetup.exe"
}

# Package Download System Utility (WinAuth)
# https://winauth.github.io/winauth/index.html
# https://winauth.github.io/winauth/download.html
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    # Initialize Parameter [# Depends on WinAuth version information]
    Set-Variable -Name WINAUTH_INSTALLER_URL -Scope Script -Value "https://github.com/winauth/winauth/releases/download/3.5.1/WinAuth-3.5.1.zip"
    Set-Variable -Name WINAUTH_INSTALLER_FILE -Scope Script -Value ($WINAUTH_INSTALLER_URL.Substring($WINAUTH_INSTALLER_URL.LastIndexOf("/") + 1))

    Write-Log "# Package Download System Utility (WinAuth)"
    Get-WebContentToFile -Uri "$WINAUTH_INSTALLER_URL" -OutFile "$TOOL_DIR\$WINAUTH_INSTALLER_FILE"
}

# Package Download System Utility (PuTTY)
# https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    # Initialize Parameter [# Depends on PuTTY version information]
    Set-Variable -Name PUTTY_INSTALLER_URL -Scope Script -Value "https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.78-installer.msi"
    Set-Variable -Name PUTTY_INSTALLER_FILE -Scope Script -Value ($PUTTY_INSTALLER_URL.Substring($PUTTY_INSTALLER_URL.LastIndexOf("/") + 1))

    Write-Log "# Package Download System Utility (PuTTY)"
    Get-WebContentToFile -Uri "$PUTTY_INSTALLER_URL" -OutFile "$TOOL_DIR\$PUTTY_INSTALLER_FILE"
}

# Package Download System Utility (WinSCP)
# https://winscp.net/
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    # Initialize Parameter [# Depends on WinSCP version information]
    Set-Variable -Name WINSCP_INSTALLER_URL -Scope Script -Value "https://jaist.dl.sourceforge.net/project/winscp/WinSCP/5.21.8/WinSCP-5.21.8-Setup.exe"
    Set-Variable -Name WINSCP_INSTALLER_FILE -Scope Script -Value ($WINSCP_INSTALLER_URL.Substring($WINSCP_INSTALLER_URL.LastIndexOf("/") + 1))

    Write-Log "# Package Download System Utility (WinSCP)"
    Get-WebContentToFile -Uri "$WINSCP_INSTALLER_URL" -OutFile "$TOOL_DIR\$WINSCP_INSTALLER_FILE"
}

# Package Download System Utility (Wireshark)
# https://www.wireshark.org/
# https://www.wireshark.org/download.html
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    Write-Log "# Package Download System Utility (Wireshark)"
    Get-WebContentToFile -Uri 'https://1.as.dl.wireshark.org/win64/Wireshark-win64-latest.exe' -OutFile "$TOOL_DIR\Wireshark-win64-latest.exe"
}

# Package Download System Utility (Fluentd)
# https://www.fluentd.org/
# https://td-agent-package-browser.herokuapp.com/4/windows
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    if ($WindowsOSVersion -match "^6.2|^6.3|^10.0") {
        # Initialize Parameter [# Depends on Fluentd version information]
        Set-Variable -Name FLUENTD_INSTALLER_URL -Scope Script -Value "https://s3.amazonaws.com/packages.treasuredata.com/4/windows/td-agent-4.4.2-x64.msi"
        Set-Variable -Name FLUENTD_INSTALLER_FILE -Scope Script -Value ($FLUENTD_INSTALLER_URL.Substring($FLUENTD_INSTALLER_URL.LastIndexOf("/") + 1))

        Write-Log "# Package Download System Utility (Fluentd)"
        Get-WebContentToFile -Uri "$FLUENTD_INSTALLER_URL" -OutFile "$TOOL_DIR\$FLUENTD_INSTALLER_FILE"
    }
}

# Package Download System Utility (Python 3.11)
# https://www.python.org/
# https://www.python.org/downloads/windows/
# if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
#     # Initialize Parameter [# Depends on Python 3.10 version information]
#     Set-Variable -Name PYTHON3_INSTALLER_URL -Scope Script -Value "https://www.python.org/ftp/python/3.11.3/python-3.11.3-amd64.exe"
#     Set-Variable -Name PYTHON3_INSTALLER_FILE -Scope Script -Value ($PYTHON3_INSTALLER_URL.Substring($PYTHON3_INSTALLER_URL.LastIndexOf("/") + 1))

#     Write-Log "# Package Download System Utility (Python 3.11)"
#     Get-WebContentToFile -Uri "$PYTHON3_INSTALLER_URL" -OutFile "$TOOL_DIR\$PYTHON3_INSTALLER_FILE"
# }

# # Package Download System Utility (WinMerge)
# # https://winmerge.org/
# if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
#     # Initialize Parameter [# Depends on WinMerge version information]
#     Set-Variable -Name WINMERGE_INSTALLER_URL -Scope Script -Value "https://github.com/WinMerge/winmerge/releases/download/v2.16.30/WinMerge-2.16.30-x64-Setup.exe"
#     Set-Variable -Name WINMERGE_INSTALLER_FILE -Scope Script -Value ($WINMERGE_INSTALLER_URL.Substring($WINMERGE_INSTALLER_URL.LastIndexOf("/") + 1))

#     Write-Log "# Package Download System Utility (WinMerge)"
#     Get-WebContentToFile -Uri "$WINMERGE_INSTALLER_URL" -OutFile "$TOOL_DIR\$WINMERGE_INSTALLER_FILE"
# }

# Package Download System Utility (WinMerge - Japanese)
# https://winmergejp.bitbucket.io/
if ($FLAG_APP_DOWNLOAD -eq $TRUE) {
    # Initialize Parameter [# Depends on WinMerge -Japanese version information]
    Set-Variable -Name WINMERGE_JP_INSTALLER_URL -Scope Script -Value "https://jaist.dl.osdn.jp/winmerge-jp/78711/WinMerge-2.16.30-jp-1-x64-Setup.exe"
    Set-Variable -Name WINMERGE_JP_INSTALLER_FILE -Scope Script -Value ($WINMERGE_JP_INSTALLER_URL.Substring($WINMERGE_JP_INSTALLER_URL.LastIndexOf("/") + 1))

    Write-Log "# Package Download System Utility (WinMerge - Japanese)"
    Get-WebContentToFile -Uri "$WINMERGE_JP_INSTALLER_URL" -OutFile "$TOOL_DIR\$WINMERGE_JP_INSTALLER_FILE"
}


#-----------------------------------------------------------------------------------------------------------------------
# Change the hostname to a host name using a private IP address
#-----------------------------------------------------------------------------------------------------------------------
# Log Separator
Write-LogSeparator "Change the hostname to a host name using a private IP address"

# Setting Hostname
Set-Variable -Name Hostname -Option Constant -Scope Local -Value ($PrivateIp.Replace(".", "-"))

Write-Log ("# [Information] [HostName (Before) : " + (Get-CimInstance -Class Win32_ComputerSystem).Name + "]")
Rename-Computer $Hostname -Force
Start-Sleep -Seconds 10
Write-Log ("# [Information] [HostName (After) : " + $Hostname + "]")


#-----------------------------------------------------------------------------------------------------------------------
# Collect Script/Config Files & Logging Data Files
#----------------------------------------------------------------------------------------------------------------------
# Log Separator
Write-LogSeparator "Collect Script/Config Files & Logging Data Files"

# Get System & User Variables
Write-Log "# Get System & User Variables"
Get-Variable | Export-Csv -Encoding default $BASE_DIR\Bootstrap-Variable.csv

# Logging Install Windows Application List (Final Information)
Write-Log "# Get Install Windows Application List (Final Information)"
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | ConvertTo-Json -Depth 100 | Out-File (Join-Path $LOGS_DIR ("AWS-EC2_WindowsInstallApplicationList_" + $(Get-Date).ToString("yyyyMMdd_hhmmss") + ".txt")) -Append -Force


# Package Download System Utility (EC2Rescue)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/Windows-Server-EC2Rescue.html
Write-Log "# Package Download System Utility (EC2Rescue)"
Get-WebContentToFile -Uri 'https://s3.amazonaws.com/ec2rescue/windows/EC2Rescue_latest.zip' -OutFile "$TOOL_DIR\EC2Rescue_latest.zip"

# Package Uncompress System Utility (EC2Rescue)
if ($WindowsOSVersion -match "^6.1|^6.2|^6.3") {
    Add-Type -AssemblyName 'System.IO.Compression.Filesystem'
    [System.IO.Compression.ZipFile]::ExtractToDirectory("$TOOL_DIR\EC2Rescue_latest.zip", "$TOOL_DIR\EC2Rescue_latest")
}
elseif ($WindowsOSVersion -match "^10.0") {
    Expand-Archive -Path "$TOOL_DIR\EC2Rescue_latest.zip" -DestinationPath "$TOOL_DIR\EC2Rescue_latest" -Force | Out-Null
}
else {
    # EC2Rescue Support Windows OS Version (None)
    Write-Log ("# [AWS - EC2Rescue] Windows OS Version : " + $WindowsOSVersion + " - Not Suppoort Windows OS Version")
}

# Log Collect (EC2Rescue)
# https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/ec2rw-cli.html
Write-Log "# Execution System Utility (EC2Rescue) - Start"
Start-Process -FilePath "$TOOL_DIR\EC2Rescue_latest\EC2RescueCmd.exe" -Verb runas -PassThru -Wait -ArgumentList @("/accepteula", "/online", "/collect:all", "/output:$LOGS_DIR\EC2RescueCmd.zip") | Out-Null
Write-Log "# Execution System Utility (EC2Rescue) - Complete"


# Save Userdata Script, Bootstrap Script, Logging Data Files - Start
Write-Log "# Save Userdata Script, Bootstrap Script, Logging Data Files) - Start"

# Save UserData Script File (EC2config)
Set-Variable -Name Ec2ConfigUserdataScript -Scope Script -Value "C:\Program Files\Amazon\Ec2ConfigService\Scripts\UserScript.ps1"
if (Test-Path $Ec2ConfigUserdataScript) {
    Copy-Item -Path $Ec2ConfigUserdataScript -Destination $BASE_DIR
}

# Save UserData Script File (EC2Launch)
Copy-Item -Path "$TEMP_DIR\*.ps1" -Destination $BASE_DIR

# Save Sysprep Configuration Files
if (Test-Path $SysprepFile) {
    Copy-Item -Path $SysprepFile -Destination $BASE_DIR
}

# Save EC2-Bootstrap Application Configuration Files
if (Test-Path $EC2ConfigFile) {
    Copy-Item -Path $EC2ConfigFile -Destination $BASE_DIR
}

if (Test-Path $EC2LaunchFile) {
    Copy-Item -Path $EC2LaunchFile -Destination $BASE_DIR
    Copy-Item -Path "C:\ProgramData\Amazon\EC2-Windows\Launch\Config\*.json" -Destination $BASE_DIR
}

if (Test-Path $EC2Launchv2File) {
    Copy-Item -Path $EC2Launchv2File -Destination $BASE_DIR
}

# Save CloudWatch Agent Configuration Files
Copy-Item -Path "C:\ProgramData\Amazon\AmazonCloudWatchAgent\*.json" -Destination $BASE_DIR
Copy-Item -Path "C:\ProgramData\Amazon\AmazonCloudWatchAgent\*.tmol" -Destination $BASE_DIR

# Save Logging Files
Copy-Item -Path "$TEMP_DIR\*.tmp" -Destination $LOGS_DIR

# Save Userdata Script, Bootstrap Script, Logging Data Files - Complete
Write-Log "# Save Userdata Script, Bootstrap Script, Logging Data Files) - Complete"


# Log Separator
Write-LogSeparator "Complete Script Execution 3rd-Bootstrap Script"

# Complete Logging
Write-Log "# Script Execution 3rd-Bootstrap Script [COMPLETE] : $ScriptFullPath"

# Save Logging Files(Write-Log Function LogFiles)
Copy-Item -Path $USERDATA_LOG -Destination $LOGS_DIR

# Stop Transcript Logging
Stop-Transcript
Start-Sleep -Seconds 15

# Save Logging Files(Start-Transcript Function LogFiles)
Copy-Item -Path "$TEMP_DIR\userdata-transcript-*.log" -Destination $LOGS_DIR


#-----------------------------------------------------------------------------------------------------------------------
# Instance Reboot
#-----------------------------------------------------------------------------------------------------------------------

# EC2 Instance Reboot
Restart-Computer -Force


#-----------------------------------------------------------------------------------------------------------------------
# End of Script
#-----------------------------------------------------------------------------------------------------------------------
