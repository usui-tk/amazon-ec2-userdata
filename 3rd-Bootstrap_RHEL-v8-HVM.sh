#!/bin/bash -v

set -e -x

# Logger
exec > >(tee /var/log/user-data_3rd-bootstrap.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Set UserData Parameter
#-------------------------------------------------------------------------------

if [ -f /tmp/userdata-parameter ]; then
    source /tmp/userdata-parameter
fi

if [[ -z "${Language}" || -z "${Timezone}" || -z "${VpcNetwork}" ]]; then
    # Default Language
	Language="en_US.UTF-8"
    # Default Timezone
	Timezone="Asia/Tokyo"
	# Default VPC Network
	VpcNetwork="IPv4"
fi

# echo
echo $Language
echo $Timezone
echo $VpcNetwork

#-------------------------------------------------------------------------------
# Parameter Settings
#-------------------------------------------------------------------------------

# Parameter Settings
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_RHEL-v8-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - RHEL v8
#    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/
#    https://access.redhat.com/support/policy/updates/extras
#    https://access.redhat.com/articles/1150793
#    https://access.redhat.com/solutions/3358
#
#    https://access.redhat.com/articles/3135121
#
#    https://aws.amazon.com/marketplace/pp/B07T4SQ5RZ
#
#-------------------------------------------------------------------------------

# Cleanup repository information
dnf clean all

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
    lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
cat /etc/os-release

cat /etc/redhat-release

# Default installation package [rpm command]
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/command-log_rpm_installed-package.txt

# Default installation package [dnf command]
dnf list installed > /tmp/command-log_dnf_installed-package.txt

# Default repository package [dnf command]
dnf list all > /tmp/command-log_dnf_repository-package-list.txt

# Default repository package group [dnf command]
dnf group list -v > /tmp/command-log_dnf_repository-package-group-list.txt

# systemd service config
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

# Default repository list [dnf command]
dnf repolist all > /tmp/command-log_dnf_repository-list.txt

# Default repository module [dnf command]
dnf module list > /tmp/command-log_dnf_module-list.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------
#  - RHEL v8 - Red Hat Dnf/Yum Repository Default Status (Enable/Disable)
#
#    [Default - Enable]
#        rhel-8-baseos-rhui-rpms
#        rhel-8-appstream-rhui-rpms
#        rhui-client-config-server-8
#    [Default - Disable]
#        rhui-codeready-builder-for-rhel-8-rhui-rpms
#-------------------------------------------------------------------------------

# Red Hat Update Infrastructure Client Package Update
dnf clean all
dnf update -y rh-amazon-rhui-client
dnf update -y dnf dnf-data dnf-utils

# Checking repository information
dnf repolist all
dnf module list

# Get Dnf/Yum Repository List (Exclude Dnf/Yum repository related to "beta, debug, source, test")
repolist=$(dnf repolist all --quiet | grep -ie "enabled" -ie "disabled" | grep -ve "beta" -ve "debug" -ve "source" -ve "test" | awk '{print $1}' | awk '{ sub("/.*$",""); print $0; }' | sort)

# Enable Dnf/Yum Repository Data from RHUI (Red Hat Update Infrastructure)
for repo in $repolist
do
	echo "[Target repository Name (Enable dnf/yum repository)] :" $repo
	dnf config-manager --enable ${repo}
	sleep 3
done

# Checking repository information
dnf repolist all
dnf module list

# Cleanup repository information
dnf clean all

# RHEL/RHUI repository package [dnf command]
for repo in $repolist
do
	echo "[Target repository Name (Collect dnf/yum repository package list)] :" $repo
	dnf repository-packages ${repo} list > /tmp/command-log_dnf_repository-package-list_${repo}.txt
	sleep 3
done

# Cleanup repository information
dnf clean all

# Default Package Update
dnf update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install RHEL System Administration Tools (from Red Hat Official Repository)
dnf install -y acpid arptables bash-completion bc bcc bcc-tools bind-utils blktrace bpftool crash-trace-command crypto-policies curl dstat ebtables ethtool expect fio gdisk git gnutls-utils hdparm intltool iotop iperf3 iptraf-ng jq kexec-tools libicu lsof lvm2 lzop man-pages mcelog mdadm mlocate mtr nc ncompress net-snmp-utils nftables nmap numactl nvme-cli nvmetcli patchutils pmempool psacct psmisc rsync smartmontools sos strace symlinks sysfsutils sysstat tcpdump tlog traceroute tree unzip util-linux vdo vim-enhanced wget xfsdump xfsprogs zip zsh
dnf install -y cifs-utils nfs-utils nfs4-acl-tools
dnf install -y iscsi-initiator-utils lsscsi sg3_utils
dnf install -y setroubleshoot-server selinux-policy* setools-console checkpolicy policycoreutils policycoreutils-python-utils policycoreutils-restorecond
dnf install -y pcp pcp-export-pcp2json pcp-manager pcp-pmda* pcp-selinux pcp-system-tools pcp-zeroconf

# Package Install Red Hat Enterprise Linux support tools (from Red Hat Official Repository)
dnf install -y redhat-lsb-core redhat-support-tool insights-client

# Package Install Red Hat Enterprise Linux kernel live-patching tools (from Red Hat Official Repository)
dnf install -y kpatch

# Package Install Python 3 Runtime (from Red Hat Official Repository)
dnf install -y @python36
dnf install -y python3 python3-pip python3-rpm-generators python3-rpm-macros python3-setuptools python3-test python3-wheel

# Package Install Red Hat Enterprise Linux Web-Based support tools (from Red Hat Official Repository)
# dnf install -y cockpit cockpit-dashboard cockpit-packagekit cockpit-session-recording cockpit-storaged cockpit-system cockpit-ws

#-------------------------------------------------------------------------------
# Custom Package Installation [EPEL]
#-------------------------------------------------------------------------------

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
# dnf localinstall -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

cat > /etc/yum.repos.d/epel-bootstrap.repo << __EOF__
[epel-bootstrap]
name=Extra Packages for Enterprise Linux \$releasever - \$basearch
#baseurl=https://download.fedoraproject.org/pub/epel/\$releasever/Everything/\$basearch
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-\$releasever&arch=\$basearch&infra=\$infra&content=\$contentdir
failovermethod=priority
enabled=0
gpgcheck=0
__EOF__

dnf clean all

dnf --enablerepo=epel-bootstrap -y install epel-release

# Delete dnf/yum temporary data
rm -f /etc/yum.repos.d/epel-bootstrap.repo

# Disable EPEL yum repository
egrep '^\[|enabled' /etc/yum.repos.d/epel*
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel-*.repo
egrep '^\[|enabled' /etc/yum.repos.d/epel*

# Cleanup repository information
dnf clean all

# EPEL repository package [dnf command]
dnf repository-packages epel list > /tmp/command-log_dnf_repository-package-list_epel.txt
dnf repository-packages epel-playground list > /tmp/command-log_dnf_repository-package-list_epel-playground.txt

# Package Install RHEL System Administration Tools (from EPEL Repository)
dnf --enablerepo=epel install -y atop iftop zstd

# Package Install RHEL System Administration Tools (from EPEL-Playground Repository)
# dnf --enablerepo=epel-playground install -y collectd collectd-python collectd-utils moreutils moreutils-parallel

#-------------------------------------------------------------------------------
# Set AWS Instance MetaData
#-------------------------------------------------------------------------------

# Instance MetaData
AZ=$(curl -s "http://169.254.169.254/latest/meta-data/placement/availability-zone")
Region=$(echo $AZ | sed -e 's/.$//g')
InstanceId=$(curl -s "http://169.254.169.254/latest/meta-data/instance-id")
InstanceType=$(curl -s "http://169.254.169.254/latest/meta-data/instance-type")
PrivateIp=$(curl -s "http://169.254.169.254/latest/meta-data/local-ipv4")
AmiId=$(curl -s "http://169.254.169.254/latest/meta-data/ami-id")

# IAM Role & STS Information
if [ $(compgen -ac | sort | uniq | grep jq) ]; then
	RoleArn=$(curl -s "http://169.254.169.254/latest/meta-data/iam/info" | jq -r '.InstanceProfileArn')
	RoleName=$(echo $RoleArn | cut -d '/' -f 2)
fi

if [ -n "$RoleName" ]; then
	StsCredential=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
	if [ $(compgen -ac | sort | uniq | grep jq) ]; then
		StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
		StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
		StsToken=$(echo $StsCredential | jq -r '.Token')
	fi
fi

# AWS Account ID
if [ $(compgen -ac | sort | uniq | grep jq) ]; then
	AwsAccountId=$(curl -s "http://169.254.169.254/latest/dynamic/instance-identity/document" | jq -r '.accountId')
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI]
#-------------------------------------------------------------------------------

# Python package introduction and setting
dnf module list | grep python3
dnf install -y @python36
dnf install -y python3-asn1crypto python3-dateutil python3-docutils python3-humanize python3-jmespath python3-pip python3-pyasn1 python3-pyasn1-modules python3-pyyaml python3-six python3-urllib3
dnf module list | grep python3

alternatives --list
alternatives --set python "/usr/bin/python3"
alternatives --list
which python
python --version

# Package Install AWS-CLI Tools (from Python Package Index (PyPI) Repository)
pip3 install awscli
pip3 show awscli

# Configuration AWS-CLI tools [AWS-CLI/Python3]
alternatives --list
alternatives --install "/usr/bin/aws" aws "/usr/local/bin/aws" 1
alternatives --install "/usr/bin/aws_completer" aws_completer "/usr/local/bin/aws_completer" 1
alternatives --list

cat > /etc/bash_completion.d/aws_bash_completer << __EOF__
# Typically that would be added under one of the following paths:
# - /etc/bash_completion.d
# - /usr/local/etc/bash_completion.d
# - /usr/share/bash-completion/completions

complete -C aws_completer aws
__EOF__

aws --version

# Setting AWS-CLI default Region & Output format
aws configure << __EOF__


${Region}
json

__EOF__

# Setting AWS-CLI Logging
aws configure set cli_history enabled

# Getting AWS-CLI default Region & Output format
aws configure list
cat ~/.aws/config

# Get AWS Region Information
if [ -n "$RoleName" ]; then
	echo "# Get AWS Region Infomation"
	aws ec2 describe-regions --region ${Region}
fi

# Get AMI information of this EC2 instance
if [ -n "$RoleName" ]; then
	echo "# Get AMI information of this EC2 instance"
	aws ec2 describe-images --image-ids ${AmiId} --output json --region ${Region}
fi

# Get the latest AMI information of the OS type of this EC2 instance from Public AMI
if [ -n "$RoleName" ]; then
	echo "# Get Newest AMI Information from Public AMI"
	NewestAmiInfo=$(aws ec2 describe-images --owner "309956199498" --filter "Name=name,Values=RHEL-8.*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)|[0]' --output json --region ${Region})
	NewestAmiId=$(echo $NewestAmiInfo| jq -r '.ImageId')
	aws ec2 describe-images --image-ids ${NewestAmiId} --output json --region ${Region}
fi

# Get EC2 Instance Information
if [ -n "$RoleName" ]; then
	echo "# Get EC2 Instance Information"
	aws ec2 describe-instances --instance-ids ${InstanceId} --output json --region ${Region}
fi

# Get EC2 Instance attached EBS Volume Information
if [ -n "$RoleName" ]; then
	echo "# Get EC2 Instance attached EBS Volume Information"
	aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=${InstanceId} --output json --region ${Region}
fi

# Get EC2 Instance attached VPC Security Group Information
if [ -n "$RoleName" ]; then
	echo "# Get EC2 Instance attached VPC Security Group Information"
	aws ec2 describe-security-groups --group-ids $(aws ec2 describe-instances --instance-id ${InstanceId} --query "Reservations[].Instances[].SecurityGroups[].GroupId[]" --output text --region ${Region}) --output json --region ${Region}
fi

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
#
# - Summary of Networking and Storage Features
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#instance-type-summary-table
# - ENA (Elastic Network Adapter)
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
# - SR-IOV
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sriov-networking.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(a1.*|c5.*|c5d.*|c5n.*|e3.*|f1.*|g3.*|g3s.*|g4dn.*|h1.*|i3.*|i3en.*|i3p.*|m5.*|m5a.*|m5ad.*|m5d.*|m5dn.*|m5n.*|p2.*|p3.*|p3dn.*|r4.*|r5.*|r5a.*|r5ad.*|r5d.*|r5dn.*|r5n.*|t3.*|t3a.*|x1.*|x1e.*|z1d.*|m4.16xlarge|u-*tb1.metal)$ ]]; then
		# Get EC2 Instance Attribute(Elastic Network Adapter Status)
		echo "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
		aws ec2 describe-instances --instance-id ${InstanceId} --query Reservations[].Instances[].EnaSupport --output json --region ${Region}

		# Get Linux Kernel Module(modinfo ena)
		echo "# Get Linux Kernel Module(modinfo ena)"
		if [ $(lsmod | awk '{print $1}' | grep -x ena) ]; then
			modinfo ena
		fi
	elif [[ "$InstanceType" =~ ^(c3.*|c4.*|d2.*|i2.*|r3.*|m4.*)$ ]]; then
		# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
		echo "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}

		# Get Linux Kernel Module(modinfo ixgbevf)
		echo "# Get Linux Kernel Module(modinfo ixgbevf)"
		if [ $(lsmod | awk '{print $1}' | grep -x ixgbevf) ]; then
			modinfo ixgbevf
		fi
	else
		echo "# Not Target Instance Type :" $InstanceType
	fi
fi

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
#
# - Summary of Networking and Storage Features
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#instance-type-summary-table
# - EBS Optimized Instance
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSOptimized.html
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSPerformance.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(a1.*|c1.*|c3.*|c4.*|c5.*|c5d.*|c5n.*|d2.*|e3.*|f1.*|g2.*|g3.*|g3s.*|g4dn.*|h1.*|i2.*|i3.*|i3en.*|i3p.*|m1.*|m2.*|m3.*|m4.*|m5.*|m5a.*|m5ad.*|m5d.*|m5dn.*|m5n.*|p2.*|p3.*|p3dn.*|r3.*|r4.*|r5.*|r5a.*|r5ad.*|r5d.*|r5dn.*|r5n.*|t3.*|t3a.*|x1.*|x1e.*|z1d.*|u-*tb1.metal)$ ]]; then
		# Get EC2 Instance Attribute(EBS-optimized instance Status)
		echo "# Get EC2 Instance Attribute(EBS-optimized instance Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute ebsOptimized --output json --region ${Region}

		# Get Linux Block Device Read-Ahead Value(blockdev --report)
		echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
		blockdev --report
	else
		# Get Linux Block Device Read-Ahead Value(blockdev --report)
		echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
		blockdev --report
	fi
fi

# Get EC2 Instance attached NVMe Device Information
#
# - Summary of Networking and Storage Features
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#instance-type-summary-table
#
# - Nitro-based Instances
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#ec2-nitro-instances
# - Amazon EBS and NVMe Volumes
#   http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nvme-ebs-volumes.html
# - SSD Instance Store Volumes
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ssd-instance-store.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(a1.*|c5.*|c5d.*|c5n.*|f1.*|g4dn.*|i3.*|i3en.*|i3p.*|m5.*|m5a.*|m5ad.*|m5d.*|m5dn.*|m5n.*|p3dn.*|r5.*|r5a.*|r5ad.*|r5d.*|r5dn.*|r5n.*|t3.*|t3a.*|z1d.*|u-*tb1.metal)$ ]]; then

		# Get Linux Kernel Module(modinfo nvme)
		echo "# Get Linux Kernel Module(modinfo nvme)"
		if [ $(lsmod | awk '{print $1}' | grep -x nvme) ]; then
			modinfo nvme
		fi

		# Get NVMe Device(nvme list)
		# http://www.spdk.io/doc/nvme-cli.html
		# https://github.com/linux-nvme/nvme-cli
		if [ $(lsmod | awk '{print $1}' | grep -x nvme) ]; then
			if [ $(command -v nvme) ]; then
				echo "# Get NVMe Device(nvme list)"
				nvme list
			fi
		fi

		# Get PCI-Express Device(lspci -v)
		if [ $(command -v lspci) ]; then
			echo "# Get PCI-Express Device(lspci -v)"
			lspci -v
		fi

		# Get Disk[MountPoint] Information (lsblk -a)
		if [ $(command -v lsblk) ]; then
			echo "# Get Disk[MountPoint] Information (lsblk -a)"
			lsblk -a
		fi

	else
		echo "# Not Target Instance Type :" $InstanceType
	fi
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------

dnf install --nogpgcheck -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

rpm -qi amazon-ssm-agent

systemctl daemon-reload

systemctl restart amazon-ssm-agent

systemctl status -l amazon-ssm-agent

# Configure AWS Systems Manager Agent software (Start Daemon awsagent)
if [ $(systemctl is-enabled amazon-ssm-agent) = "disabled" ]; then
	systemctl enable amazon-ssm-agent
	systemctl is-enabled amazon-ssm-agent
fi

ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Inspector Agent]
# https://docs.aws.amazon.com/inspector/latest/userguide/inspector_installing-uninstalling-agents.html
#-------------------------------------------------------------------------------

# # Variable initialization
# InspectorInstallStatus="0"

# # Run Amazon Inspector Agent installer script
# curl -fsSL "https://inspector-agent.amazonaws.com/linux/latest/install" | bash -ex || InspectorInstallStatus=$?

# # Check the exit code of the Amazon Inspector Agent installer script
# if [ $InspectorInstallStatus -eq 0 ]; then
# 	rpm -qi AwsAgent

# 	systemctl daemon-reload

# 	systemctl restart awsagent

# 	systemctl status -l awsagent

# 	# Configure Amazon Inspector Agent software (Start Daemon awsagent)
# 	if [ $(systemctl is-enabled awsagent) = "disabled" ]; then
# 		systemctl enable awsagent
# 		systemctl is-enabled awsagent
# 	fi

#	sleep 15

# 	/opt/aws/awsagent/bin/awsagent status
# else
# 	echo "Failed to execute Amazon Inspector Agent installer script"
# fi

#-------------------------------------------------------------------------------
# Custom Package Install [Amazon CloudWatch Agent]
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/download-cloudwatch-agent-commandline.html
#-------------------------------------------------------------------------------

dnf install --nogpgcheck -y "https://s3.amazonaws.com/amazoncloudwatch-agent/redhat/amd64/latest/amazon-cloudwatch-agent.rpm"

rpm -qi amazon-cloudwatch-agent

cat /opt/aws/amazon-cloudwatch-agent/bin/CWAGENT_VERSION

cat /opt/aws/amazon-cloudwatch-agent/etc/common-config.toml

systemctl daemon-reload

# Configure Amazon CloudWatch Agent software (Start Daemon awsagent)
if [ $(systemctl is-enabled amazon-cloudwatch-agent) = "disabled" ]; then
	systemctl enable amazon-cloudwatch-agent
	systemctl is-enabled amazon-cloudwatch-agent
fi

# Configure Amazon CloudWatch Agent software (Monitor settings)
curl -sS ${CWAgentConfig} -o "/tmp/config.json"
cat "/tmp/config.json"

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/tmp/config.json -s

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a stop
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a start

systemctl status -l amazon-cloudwatch-agent

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status

# View Amazon CloudWatch Agent config files
cat /opt/aws/amazon-cloudwatch-agent/etc/common-config.toml

cat /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Rescue for Linux (ec2rl)]
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Linux-Server-EC2Rescue.html
# https://github.com/awslabs/aws-ec2rescue-linux
#-------------------------------------------------------------------------------

# Package Amazon EC2 Administration Tools (from S3 Bucket)
curl -sS "https://s3.amazonaws.com/ec2rescuelinux/ec2rl-bundled.tgz" -o "/tmp/ec2rl-bundled.tgz"

mkdir -p "/opt/aws"

rm -rf /opt/aws/ec2rl*

tar -xzf "/tmp/ec2rl-bundled.tgz" -C "/opt/aws"

mv --force /opt/aws/ec2rl* "/opt/aws/ec2rl"

cat > /etc/profile.d/ec2rl.sh << __EOF__
export PATH=\$PATH:/opt/aws/ec2rl
__EOF__

source /etc/profile.d/ec2rl.sh

# Check Version
/opt/aws/ec2rl/ec2rl version

/opt/aws/ec2rl/ec2rl list

# Required Software Package
/opt/aws/ec2rl/ec2rl software-check

# Diagnosis [dig modules]
# /opt/aws/ec2rl/ec2rl run --only-modules=dig --domain=amazon.com

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
#-------------------------------------------------------------------------------

# Package Install RHEL System Administration Tools (from Red Hat Official Repository)
# dnf install -y ansible ansible-doc rhel-system-roles

# ansible --version

# ansible localhost -m setup

# Package Install Ansible (from Python Package Index (PyPI) Repository)
dnf install -y python3-cryptography python3-pyyaml
pip3 install ansible
pip3 show ansible

alternatives --list
alternatives --install "/usr/bin/ansible" ansible "/usr/local/bin/ansible" 1
alternatives --list

which ansible
ansible --version

ansible localhost -m setup

#-------------------------------------------------------------------------------
# Custom Package Installation [PowerShell Core(pwsh)]
# https://docs.microsoft.com/ja-jp/powershell/scripting/setup/Installing-PowerShell-Core-on-macOS-and-Linux?view=powershell-6
# https://github.com/PowerShell/PowerShell
#
# https://packages.microsoft.com/rhel/8/prod/
#
# https://docs.aws.amazon.com/ja_jp/powershell/latest/userguide/pstools-getting-set-up-linux-mac.html
# https://www.powershellgallery.com/packages/AWSPowerShell.NetCore/
#-------------------------------------------------------------------------------

# Register the Microsoft RedHat repository
curl https://packages.microsoft.com/config/rhel/8/prod.repo | tee /etc/yum.repos.d/microsoft.repo

# Cleanup repository information
dnf clean all
dnf makecache

# # Install PowerShell
# dnf install -y powershell

# rpm -qi powershell

# # Check Version
# pwsh -Version

# # Operation check of PowerShell command
# pwsh -Command "Get-Module -ListAvailable"

# pwsh -Command "Install-Module -Name AWSPowerShell.NetCore -AllowClobber -Force"
# pwsh -Command "Import-Module AWSPowerShell.NetCore"

# pwsh -Command "Get-Module -ListAvailable"

# pwsh -Command "Get-AWSPowerShellVersion"
# pwsh -Command "Get-AWSPowerShellVersion -ListServiceVersionInfo"

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
dnf clean all

#-------------------------------------------------------------------------------
# System information collection
#-------------------------------------------------------------------------------

# CPU Information [cat /proc/cpuinfo]
cat /proc/cpuinfo

# CPU Information [lscpu]
lscpu

lscpu --extended

# Memory Information [cat /proc/meminfo]
cat /proc/meminfo

# Memory Information [free]
free

# Disk Information(Partition) [parted -l]
parted -l

# Disk Information(MountPoint) [lsblk -f]
lsblk -f

# Disk Information(File System) [df -khT]
df -khT

# Network Information(Network Interface) [ip addr show]
ip addr show

# Network Information(Routing Table) [ip route show]
ip route show

# Network Information(Firewall Service) [firewalld]
if [ $(command -v firewall-cmd) ]; then
    # Network Information(Firewall Service) [systemctl status -l firewalld]
    systemctl status -l firewalld
    # Network Information(Firewall Service) [firewall-cmd --list-all]
    firewall-cmd --list-all
fi

# Linux Security Information(SELinux) [getenforce] [sestatus]
getenforce

sestatus

#-------------------------------------------------------------------------------
# Configure Amazon Time Sync Service
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
#-------------------------------------------------------------------------------

# Configure NTP Client software (Install chrony Package)
dnf install -y chrony

rpm -qi chrony

systemctl daemon-reload

systemctl restart chronyd

systemctl status -l chronyd

# Configure NTP Client software (Start Daemon chronyd)
if [ $(systemctl is-enabled chronyd) = "disabled" ]; then
	systemctl enable chronyd
	systemctl is-enabled chronyd
fi

# Configure NTP Client software (Configure chronyd)
cat /etc/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

sed -i 's/#log measurements statistics tracking/log measurements statistics tracking/g' /etc/chrony.conf
sed -i "/pool 2.rhel.pool.ntp.org iburst/a server 169.254.169.123 prefer iburst" /etc/chrony.conf

cat /etc/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

# Configure NTP Client software (Time adjustment)
systemctl restart chronyd

sleep 3
chronyc tracking
sleep 3
chronyc sources -v
sleep 3
chronyc sourcestats -v

#-------------------------------------------------------------------------------
# Configure Tuned
#-------------------------------------------------------------------------------

# Package Install Tuned (from Red Hat Official Repository)
dnf install -y tuned tuned-utils tuned-profiles-oracle

rpm -qi tuned

systemctl daemon-reload

systemctl restart tuned

systemctl status -l tuned

# Configure Tuned software (Start Daemon tuned)
if [ $(systemctl is-enabled tuned) = "disabled" ]; then
	systemctl enable tuned
	systemctl is-enabled tuned
fi

# Configure Tuned software (select profile - throughput-performance)
tuned-adm list

tuned-adm active
tuned-adm profile throughput-performance
tuned-adm active

#-------------------------------------------------------------------------------
# Configure ACPI daemon (Advanced Configuration and Power Interface)
#-------------------------------------------------------------------------------

# Configure ACPI daemon software (Install acpid Package)
dnf install -y acpid

rpm -qi acpid

systemctl daemon-reload

systemctl restart acpid

systemctl status -l acpid

# Configure NTP Client software (Start Daemon chronyd)
if [ $(systemctl is-enabled acpid) = "disabled" ]; then
	systemctl enable acpid
	systemctl is-enabled acpid
fi

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting SELinux permissive mode
getenforce
sestatus
cat /etc/selinux/config
sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
cat /etc/selinux/config
setenforce 0
getenforce

# Setting System crypto policy (Default -> FUTURE)
update-crypto-policies --show
# update-crypto-policies --set FUTURE
# update-crypto-policies --is-applied

# Setting SystemClock and Timezone
if [ "${Timezone}" = "Asia/Tokyo" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl status --all --no-pager
	timedatectl set-timezone Asia/Tokyo
	timedatectl status --all --no-pager
	date
elif [ "${Timezone}" = "UTC" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl status --all --no-pager
	timedatectl set-timezone UTC
	timedatectl status --all --no-pager
	date
else
	echo "# Default SystemClock and Timezone"
	timedatectl status --all --no-pager
	date
fi

# Setting System Language
if [ "${Language}" = "ja_JP.UTF-8" ]; then
	# Custom Package Installation
	dnf install -y langpacks-ja glibc-langpack-ja

	echo "# Setting System Language -> $Language"
	locale
	localectl status --no-pager
	localectl list-locales --no-pager | grep ja_
	localectl set-locale LANG=ja_JP.utf8
	localectl status --no-pager
	locale
	strings /etc/locale.conf
	source /etc/locale.conf
elif [ "${Language}" = "en_US.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
	locale
	localectl status --no-pager
	localectl list-locales --no-pager | grep en_
	localectl set-locale LANG=en_US.utf8
	localectl status --no-pager
	locale
	strings /etc/locale.conf
	source /etc/locale.conf
else
	echo "# Default Language"
	locale
	localectl status --no-pager
	strings /etc/locale.conf
fi

# Setting IP Protocol Stack (IPv4 Only) or (IPv4/IPv6 Dual stack)
if [ "${VpcNetwork}" = "IPv4" ]; then
	echo "# Setting IP Protocol Stack -> $VpcNetwork"

	# Disable IPv6 Kernel Module
	echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf

	# Disable IPv6 Kernel Parameter
	sysctl -a

	DisableIPv6Conf="/etc/sysctl.d/90-ipv6-disable.conf"

	cat /dev/null > $DisableIPv6Conf
	echo '# Custom sysctl Parameter for ipv6 disable' >> $DisableIPv6Conf
	echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> $DisableIPv6Conf
	echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> $DisableIPv6Conf

	sysctl --system
	sysctl -p

	sysctl -a | grep -ie "local_port" -ie "ipv6" | sort
elif [ "${VpcNetwork}" = "IPv6" ]; then
	echo "# Show IP Protocol Stack -> $VpcNetwork"
	echo "# Show IPv6 Network Interface Address"
	ifconfig
	echo "# Show IPv6 Kernel Module"
	lsmod | awk '{print $1}' | grep ipv6
	echo "# Show Network Listen Address and report"
	netstat -an -A inet6
	echo "# Show Network Routing Table"
	netstat -r -A inet6
else
	echo "# Default IP Protocol Stack"
	echo "# Show IPv6 Network Interface Address"
	ifconfig
	echo "# Show IPv6 Kernel Module"
	lsmod | awk '{print $1}' | grep ipv6
	echo "# Show Network Listen Address and report"
	netstat -an -A inet6
	echo "# Show Network Routing Table"
	netstat -r -A inet6
fi

#-------------------------------------------------------------------------------
# Reboot
#-------------------------------------------------------------------------------

# Instance Reboot
reboot
