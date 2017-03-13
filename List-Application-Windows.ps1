
#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Update (Amazon EC2 Systems Manager Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Package Download System Utility (Amazon EC2 Systems Manager Agent)
# http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/WindowsGuide/systems-manager-managedinstances.html#sysman-install-managed-win
Write-Log "# Package Download System Utility (Amazon EC2 Systems Manager Agent)"
$AmazonSSMAgentUrl = "https://amazon-ssm-" + ${Region} + ".s3.amazonaws.com/latest/windows_amd64/AmazonSSMAgentSetup.exe"
Invoke-WebRequest -Uri $AmazonSSMAgentUrl -OutFile "$TOOL_DIR\AmazonSSMAgentSetup.exe"

#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (System Utility)
#-----------------------------------------------------------------------------------------------------------------------

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

# Package Download Monitoring Service Agent (Zabbix Agent)
# http://www.zabbix.com/download
Write-Log "# Package Download Monitoring Service Agent (Zabbix Agent)"
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
# https://help.deepsecurity.trendmicro.com/Get-Started/Install/install-dsa.html
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

