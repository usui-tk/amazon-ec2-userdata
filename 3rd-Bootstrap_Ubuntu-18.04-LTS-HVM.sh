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
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_Ubuntu-18.04-LTS-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - Ubuntu 18.04 LTS
#    https://help.ubuntu.com/
#    https://help.ubuntu.com/lts/serverguide/index.html
#    https://help.ubuntu.com/lts/installation-guide/amd64/index.html
#    http://packages.ubuntu.com/ja/
#    
#	 https://cloud-images.ubuntu.com/locator/ec2/
#    https://help.ubuntu.com/community/EC2StartersGuide
#
#    https://aws.amazon.com/marketplace/pp/
#
#-------------------------------------------------------------------------------

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
    lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
cat /etc/os-release

# Default installation package [apt command]
apt list --installed > /tmp/command-log_apt_installed-package.txt

# Default repository package [apt command]
apt list > /tmp/command-log_apt_repository-package-list.txt

# systemd service config
systemctl list-unit-files --no-pager -all > /tmp/command-log_systemctl_list-unit-files.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# Command Non-Interactive Mode
export DEBIAN_FRONTEND=noninteractive

# apt repository metadata Clean up
apt clean -y

# Default Package Update
apt update -y && apt upgrade -y && apt dist-upgrade -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Ubuntu apt Administration Tools (from Ubuntu Official Repository)
apt install -y apt-transport-https ca-certificates curl gnupg software-properties-common

# Package Install Ubuntu System Administration Tools (from Ubuntu Official Repository)
apt install -y arptables atop bash-completion binutils debian-goodies dstat ebtables fio gdisk git hdparm ipv6toolkit jq kexec-tools lsof lzop iotop mtr-tiny needrestart nmap nvme-cli sosreport sysstat tcpdump traceroute unzip update-motd wget zip

#-------------------------------------------------------------------------------
# Custom Package Installation [Special package for AWS]
#-------------------------------------------------------------------------------

# Package Install Special package for AWS (from Ubuntu Official Repository)
apt install -y linux-aws linux-image-aws linux-tools-aws

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
if [ $(compgen -ac | grep jq) ]; then
    RoleArn=$(curl -s "http://169.254.169.254/latest/meta-data/iam/info" | jq -r '.InstanceProfileArn')
	RoleName=$(echo $RoleArn | cut -d '/' -f 2)
fi

if [ -n "$RoleName" ]; then
	StsCredential=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
	if [ $(compgen -ac | grep jq) ]; then
		StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
		StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
		StsToken=$(echo $StsCredential | jq -r '.Token')
	fi
fi

# AWS Account ID
if [ $(compgen -ac | grep jq) ]; then
    AwsAccountId=$(curl -s "http://169.254.169.254/latest/dynamic/instance-identity/document" | jq -r '.accountId')
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI]
#-------------------------------------------------------------------------------
apt install -y awscli

cat > /etc/profile.d/aws-cli.sh << __EOF__
if [ -n "\$BASH_VERSION" ]; then
   complete -C /usr/bin/aws_completer aws
fi
__EOF__

source /etc/profile.d/aws-cli.sh

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
	NewestAmiInfo=$(aws ec2 describe-images --owner "099720109477" --filter "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)|[0]' --output json --region ${Region})
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
	if [[ "$InstanceType" =~ ^(a1.*|c5.*|c5d.*|c5n.*|e3.*|f1.*|g3.*|g3s.*|h1.*|i3.*|i3en.*|i3p.*|m5.*|m5a.*|m5ad.*|m5d.*|p2.*|p3.*|p3dn.*|r4.*|r5.*|r5a.*|r5ad.*|r5d.*|t3.*|t3a.*|x1.*|x1e.*|z1d.*|m4.16xlarge|u-6tb1.metal|u-9tb1.metal|u-12tb1.metal)$ ]]; then
		# Get EC2 Instance Attribute(Elastic Network Adapter Status)
		echo "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
		aws ec2 describe-instances --instance-id ${InstanceId} --query Reservations[].Instances[].EnaSupport --output json --region ${Region}

		# Get Linux Kernel Module(modinfo ena)
		echo "# Get Linux Kernel Module(modinfo ena)"
		if [ $(lsmod | awk '{print $1}' | grep ena) ]; then
    		modinfo ena
		fi
	elif [[ "$InstanceType" =~ ^(c3.*|c4.*|d2.*|i2.*|r3.*|m4.*)$ ]]; then
		# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
		echo "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}
		
		# Get Linux Kernel Module(modinfo ixgbevf)
		echo "# Get Linux Kernel Module(modinfo ixgbevf)"
		if [ $(lsmod | awk '{print $1}' | grep ixgbevf) ]; then
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
	if [[ "$InstanceType" =~ ^(a1.*|c1.*|c3.*|c4.*|c5.*|c5d.*|c5n.*|d2.*|e3.*|f1.*|g2.*|g3.*|g3s.*|h1.*|i2.*|i3.*|i3en.*|i3p.*|m1.*|m2.*|m3.*|m4.*|m5.*|m5a.*|m5ad.*|m5d.*|p2.*|p3.*|p3dn.*|r3.*|r4.*|r5.*|r5a.*|r5ad.*|r5d.*|t3.*|t3a.*|x1.*|x1e.*|z1d.*|u-6tb1.metal|u-9tb1.metal|u-12tb1.metal)$ ]]; then
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
	if [[ "$InstanceType" =~ ^(a1.*|c5.*|c5d.*|c5n.*|f1.*|i3.*|i3en.*|i3p.*|m5.*|m5a.*|m5ad.*|m5d.*|p3dn.*|r5.*|r5a.*|r5ad.*|r5d.*|t3.*|t3a.*|z1d.*|u-6tb1.metal|u-9tb1.metal|u-12tb1.metal)$ ]]; then
		
		# Get Linux Kernel Module(modinfo nvme)
		echo "# Get Linux Kernel Module(modinfo nvme)"
		if [ $(lsmod | awk '{print $1}' | grep nvme) ]; then
    		modinfo nvme
		fi
		
		# Get NVMe Device(nvme list)
		# http://www.spdk.io/doc/nvme-cli.html
		# https://github.com/linux-nvme/nvme-cli
		if [ $(lsmod | awk '{print $1}' | grep nvme) ]; then
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

snap list --all

snap install amazon-ssm-agent --classic

snap list amazon-ssm-agent

snap restart amazon-ssm-agent

snap services amazon-ssm-agent

/snap/bin/amazon-ssm-agent.ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Inspector Agent]
# https://docs.aws.amazon.com/inspector/latest/userguide/inspector_installing-uninstalling-agents.html
#-------------------------------------------------------------------------------

# Variable initialization
InspectorInstallStatus="0"

# Run Amazon Inspector Agent installer script
curl -fsSL "https://inspector-agent.amazonaws.com/linux/latest/install" | bash -ex || InspectorInstallStatus=$?

# Check the exit code of the Amazon Inspector Agent installer script
if [ $InspectorInstallStatus -eq 0 ]; then
    apt show AwsAgent
	
	systemctl daemon-reload

	systemctl restart awsagent

	systemctl status -l awsagent

	# Configure Amazon Inspector Agent software (Start Daemon awsagent)
	if [ $(systemctl is-enabled awsagent) = "disabled" ]; then
		systemctl enable awsagent
		systemctl is-enabled awsagent
	fi

	systemctl restart awsagent

	systemctl status -l awsagent

	/opt/aws/awsagent/bin/awsagent status
else
	echo "Failed to execute Amazon Inspector Agent installer script"
fi

#-------------------------------------------------------------------------------
# Custom Package Install [Amazon CloudWatch Agent]
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/download-cloudwatch-agent-commandline.html
#-------------------------------------------------------------------------------
curl -sS "https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb" -o "/tmp/amazon-cloudwatch-agent.deb"
dpkg -i "/tmp/amazon-cloudwatch-agent.deb"

apt show amazon-cloudwatch-agent

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

# Package Download Amazon Linux System Administration Tools (from S3 Bucket)
curl -sS "https://s3.amazonaws.com/ec2rescuelinux/ec2rl.tgz" -o "/tmp/ec2rl.tgz"

mkdir -p "/opt/aws"

tar -xzf "/tmp/ec2rl.tgz" -C "/opt/aws"

mv --force /opt/aws/ec2rl-* "/opt/aws/ec2rl"

cat > /etc/profile.d/ec2rl.sh << __EOF__
export PATH=\$PATH:/opt/aws/ec2rl
__EOF__

source /etc/profile.d/ec2rl.sh

# Check Version
/opt/aws/ec2rl/ec2rl version

/opt/aws/ec2rl/ec2rl version-check

# Required Software Package
/opt/aws/ec2rl/ec2rl software-check

# Diagnosis [dig modules]
# /opt/aws/ec2rl/ec2rl run --only-modules=dig --domain=amazon.com

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
# http://docs.ansible.com/ansible/latest/intro_installation.html#latest-releases-via-apt-ubuntu
#-------------------------------------------------------------------------------

apt install -y software-properties-common

apt install -y ansible

apt show ansible

ansible --version

ansible localhost -m setup 

#-------------------------------------------------------------------------------
# Custom Package Installation [PowerShell Core(pwsh)]
# https://docs.microsoft.com/ja-jp/powershell/scripting/setup/Installing-PowerShell-Core-on-macOS-and-Linux?view=powershell-6
# https://github.com/PowerShell/PowerShell
# 
# https://packages.microsoft.com/ubuntu/18.04/prod/
# 
# https://docs.aws.amazon.com/ja_jp/powershell/latest/userguide/pstools-getting-set-up-linux-mac.html
# https://www.powershellgallery.com/packages/AWSPowerShell.NetCore/
#-------------------------------------------------------------------------------

# Import the public repository GPG keys
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
apt-key list

# Register the Microsoft Ubuntu repository
curl https://packages.microsoft.com/config/ubuntu/18.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list

# Update the list of products
apt clean -y
apt update -y

# Install PowerShell
# apt install -y powershell

# apt show powershell

# Check Version
# pwsh -Version

# Operation check of PowerShell command
# pwsh -Command "Get-Module -ListAvailable"

# pwsh -Command "Install-Module -Name AWSPowerShell.NetCore -AllowClobber -Force"
# pwsh -Command "Import-Module AWSPowerShell.NetCore"

# pwsh -Command "Get-Module -ListAvailable"

# pwsh -Command "Get-AWSPowerShellVersion"
# pwsh -Command "Get-AWSPowerShellVersion -ListServiceVersionInfo"

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
apt clean -y

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

# Disk Information(MountPoint) [lsblk]
lsblk

# Disk Information(File System) [df -h]
df -h

# Network Information(Network Interface) [ip addr show]
ip addr show

# Network Information(Routing Table) [ip route show]
ip route show

# Network Information(Firewall Service) [Uncomplicated firewall]
if [ $(command -v ufw) ]; then
    # Network Information(Firewall Service) [systemctl status -l ufw]
    systemctl status -l ufw
    # Network Information(Firewall Service Status) [ufw status]
    ufw status verbose
    # Network Information(Firewall Service Disabled) [ufw disable]
    ufw disable
    # Network Information(Firewall Service Status) [systemctl status -l ufw]
	systemctl status -l ufw
	systemctl disable ufw
	systemctl status -l ufw
fi

# Linux Security Information(AppArmor)
if [ $(command -v aa-status) ]; then
    # Linux Security Information(AppArmor) [systemctl status -l apparmor]
	systemctl status -l apparmor
    # Linux Security Information(AppArmor) [aa-status]
    aa-status
fi

#-------------------------------------------------------------------------------
# Configure Amazon Time Sync Service
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
#-------------------------------------------------------------------------------

# Configure NTP Client software (Install chrony Package)
apt install -y chrony

apt show chrony

systemctl daemon-reload

systemctl status -l chronyd

# Configure NTP Client software (Start Daemon chronyd)
if [ $(systemctl is-enabled chronyd) = "disabled" ]; then
	systemctl enable chronyd
	systemctl is-enabled chronyd
fi

systemctl restart chronyd

systemctl status -l chronyd

# Configure NTP Client software (Configure chronyd)
cat /etc/chrony/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

sed -i 's/#log tracking measurements statistics/log measurements statistics tracking/g' /etc/chrony/chrony.conf

sed -i "17i#\n# use the local instance NTP service, if available\nserver 169.254.169.123 prefer iburst\n" /etc/chrony/chrony.conf

cat /etc/chrony/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

# Configure NTP Client software (Time adjustment)
systemctl restart chronyd

sleep 3

chronyc tracking
chronyc sources -v
chronyc sourcestats -v

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting SystemClock and Timezone
if [ "${Timezone}" = "Asia/Tokyo" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl set-timezone Asia/Tokyo
	date
	dpkg-reconfigure --frontend noninteractive tzdata
elif [ "${Timezone}" = "UTC" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl set-timezone UTC
	date
	dpkg-reconfigure --frontend noninteractive tzdata
else
	echo "# Default SystemClock and Timezone"
	date
	dpkg-reconfigure --frontend noninteractive tzdata
fi

# Setting System Language
if [ "${Language}" = "ja_JP.UTF-8" ]; then
	# Custom Package Installation [language-pack-ja]
	apt install -y language-pack-ja-base language-pack-ja fonts-ipafont
	echo "# Setting System Language -> $Language"
	locale
	# localectl status
	localectl set-locale LANG=ja_JP.UTF-8 LANGUAGE="ja_JP:ja"
	locale
	strings /etc/default/locale
elif [ "${Language}" = "en_US.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
	locale
	# localectl status
	localectl set-locale LANG=en_US.UTF-8
	locale
	strings /etc/default/locale
else
	echo "# Default Language"
	locale
	strings /etc/default/locale
fi

# Setting IP Protocol Stack (IPv4 Only) or (IPv4/IPv6 Dual stack)
if [ "${VpcNetwork}" = "IPv4" ]; then
	echo "# Setting IP Protocol Stack -> $VpcNetwork"
	
	# Disable IPv6 Uncomplicated Firewall (ufw)
	if [ -e /etc/default/ufw ]; then
		sed -i "s/IPV6=yes/IPV6=no/g" /etc/default/ufw
	fi

	# Disable IPv6 Kernel Module
	echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf
	
	# Disable IPv6 Kernel Parameter
	sysctl -a

	DisableIPv6Conf="/etc/sysctl.d/99-ipv6-disable.conf"

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
