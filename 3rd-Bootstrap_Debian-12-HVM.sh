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
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_Debian-12-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - Debian GNU/Linux 12 (Bookworm)
#    https://www.debian.org/
#    https://www.debian.org/releases/
#    https://www.debian.org/distrib/packages
#
#    https://packages.debian.org/bookworm/
#
#    https://wiki.debian.org/FrontPage
#    https://wiki.debian.org/Cloud/AmazonEC2Image
#
#    https://cloud.debian.org/images/cloud/
#    https://salsa.debian.org/cloud-team/debian-cloud-images
#    https://image-finder.debian.net/
#
#    https://aws.amazon.com/marketplace/pp/
#
#-------------------------------------------------------------------------------

# Command Non-Interactive Mode
export DEBIAN_FRONTEND=noninteractive

# Cleanup repository information
apt clean -y -q

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

# systemd unit files
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

# systemd service config
systemctl list-units --type=service --all --no-pager > /tmp/command-log_systemctl_list-service-config.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# apt repository metadata Clean up
apt clean -y -q

# apt repository metadata update
apt update -y -q

# Package Install Debian apt Administration Tools (from Debian Official Repository)
apt install -y -q apt-transport-https ca-certificates curl gnupg-agent software-properties-common

# Default Package Update
apt update -y -q && apt upgrade -y -q && apt full-upgrade -y -q

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# [workaround] Package Install Debian System Administration Tools (from Debian Official Repository)
apt install -y ca-certificates-java

# Package Install Debian System Administration Tools (from Debian Official Repository)
apt install -y -q acpid acpitool arptables atop bash-completion bcc bcftools binutils blktrace bpfcc-tools byobu chrony collectd collectd-utils collectl colordiff crash curl dateutils debian-goodies dstat ebtables ethtool expect file fio fping fzf gdisk git hardinfo hdparm htop httping iftop inotify-tools intltool inxi iotop ipcalc iperf3 iptraf-ng ipv6calc ipv6toolkit jnettop jc jq kexec-tools locales-all lsb-release lsof lvm2 lzop manpages mc mdadm mlocate moreutils mtr ncdu ncompress needrestart netcat-openbsd netsniff-ng nftables nload nmap numactl numatop nvme-cli parted psmisc python3-bpfcc rsync screen secure-delete shellcheck snmp sosreport strace stressapptest symlinks sysfsutils sysstat tcpdump time timelimit traceroute tree tzdata unzip usermode util-linux wdiff wget zip zstd
apt install -y -q cifs-utils nfs-common nfs4-acl-tools nfstrace nfswatch
apt install -y -q open-iscsi open-isns-utils lsscsi scsitools sdparm sg3-utils
apt install -y -q apparmor apparmor-easyprof apparmor-profiles apparmor-profiles-extra apparmor-utils dh-apparmor
apt install -y -q pcp pcp-conf pcp-manager

# Package Install Python 3 Runtime (from Debian Official Repository)
apt install -y -q python3 python3-pip python3-setuptools python3-testtools python3-toolz python3-wheel

# Package Install EC2 instance optimization tools (from Debian Official Repository)
apt install -y -q python3 amazon-ec2-utils

#-------------------------------------------------------------------------------
# Get AWS Instance MetaData Service (IMDS v1, v2)
# https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
# https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
#-------------------------------------------------------------------------------

# Getting an Instance Metadata Service v2 (IMDS v2) token
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`

if [ -n "$TOKEN" ]; then
	#-----------------------------------------------------------------------
	# Retrieving Metadata Using the Instance Metadata Service v2 (IMDS v2)
	#-----------------------------------------------------------------------

	# Instance MetaData
	Az=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/placement/availability-zone")
	AzId=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/placement/availability-zone-id")
	Region=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/placement/region")
	InstanceId=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/instance-id")
	InstanceType=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/instance-type")
	PrivateIp=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/local-ipv4")
	AmiId=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/ami-id")

	# IAM Role & STS Information
	if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
		RoleArn=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/iam/info" | jq -r '.InstanceProfileArn')
		RoleName=$(echo $RoleArn | cut -d '/' -f 2)
	fi

	if [ -n "$RoleName" ]; then
		StsCredential=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
		if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
			StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
			StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
			StsToken=$(echo $StsCredential | jq -r '.Token')
		fi
	fi

	# AWS Account ID
	if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
		AwsAccountId=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/dynamic/instance-identity/document" | jq -r '.accountId')
	fi

else
	#-----------------------------------------------------------------------
	# Retrieving Metadata Using the Instance Metadata Service v1 (IMDS v1)
	#-----------------------------------------------------------------------

	# Instance MetaData
	Az=$(curl -s "http://169.254.169.254/latest/meta-data/placement/availability-zone")
	AzId=$(curl -s "http://169.254.169.254/latest/meta-data/placement/availability-zone-id")
	Region=$(curl -s "http://169.254.169.254/latest/meta-data/placement/region")
	InstanceId=$(curl -s "http://169.254.169.254/latest/meta-data/instance-id")
	InstanceType=$(curl -s "http://169.254.169.254/latest/meta-data/instance-type")
	PrivateIp=$(curl -s "http://169.254.169.254/latest/meta-data/local-ipv4")
	AmiId=$(curl -s "http://169.254.169.254/latest/meta-data/ami-id")

	# IAM Role & STS Information
	if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
		RoleArn=$(curl -s "http://169.254.169.254/latest/meta-data/iam/info" | jq -r '.InstanceProfileArn')
		RoleName=$(echo $RoleArn | cut -d '/' -f 2)
	fi

	if [ -n "$RoleName" ]; then
		StsCredential=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
		if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
			StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
			StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
			StsToken=$(echo $StsCredential | jq -r '.Token')
		fi
	fi

	# AWS Account ID
	if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
		AwsAccountId=$(curl -s "http://169.254.169.254/latest/dynamic/instance-identity/document" | jq -r '.accountId')
	fi

fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI v2]
# https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html
#-------------------------------------------------------------------------------

# Package Uninstall AWS-CLI v1 Tools (from DEB Package)
if [ $(compgen -ac | sort | uniq | grep -x aws) ]; then
	aws --version

	which aws

	if [ $(dpkg -l awscli) ]; then
		apt show awscli

		apt remove -y -q awscli
	fi

fi

# Prohibit installation/update of AWS-CLI v1 package from repository
apt-mark showhold
apt-mark hold awscli
apt-mark showhold

# Package download AWS-CLI v2 Tools (from Bundle Installer)
curl -sS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
unzip -oq "/tmp/awscliv2.zip" -d /tmp/

# Package Install AWS-CLI v2 Tools (from Bundle Installer)
/tmp/aws/install -i "/opt/aws/awscli" -b "/usr/bin" --update

aws --version

# Configuration AWS-CLI tools
cat > /etc/bash_completion.d/aws_bash_completer << __EOF__
# Typically that would be added under one of the following paths:
# - /etc/bash_completion.d
# - /usr/local/etc/bash_completion.d
# - /usr/share/bash-completion/completions

complete -C aws_completer aws
__EOF__

# Setting AWS-CLI default Region & Output format
aws configure << __EOF__


${Region}
json

__EOF__

# Setting AWS-CLI Logging
aws configure set cli_history enabled

# Setting AWS-CLI Pager settings
aws configure set cli_pager ''

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
	NewestAmiInfo=$(aws ec2 describe-images --owner "136693071363" --filter "Name=name,Values=debian-11-amd64-*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)|[0]' --output json --region ${Region})
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
	if [[ "$InstanceType" =~ ^(a1.*|c5.*|c5a.*|c5ad.*|c5adn.*|c5an.*|c5d.*|c5n.*|e3.*|f1.*|g3.*|g3s.*|g4dn.*|h1.*|i3.*|i3en.*|i3p.*|m5.*|m5a.*|m5ad.*|m5d.*|m5dn.*|m5n.*|p2.*|p3.*|p3dn.*|r4.*|r5.*|r5a.*|r5ad.*|r5d.*|r5dn.*|r5n.*|t3.*|t3a.*|x1.*|x1e.*|z1d.*|m4.16xlarge|u-*tb1.metal)$ ]]; then
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
	if [[ "$InstanceType" =~ ^(a1.*|c1.*|c3.*|c4.*|c5.*|c5a.*|c5ad.*|c5adn.*|c5an.*|c5d.*|c5n.*|d2.*|e3.*|f1.*|g2.*|g3.*|g3s.*|g4dn.*|h1.*|i2.*|i3.*|i3en.*|i3p.*|m1.*|m2.*|m3.*|m4.*|m5.*|m5a.*|m5ad.*|m5d.*|m5dn.*|m5n.*|p2.*|p3.*|p3dn.*|r3.*|r4.*|r5.*|r5a.*|r5ad.*|r5d.*|r5dn.*|r5n.*|t3.*|t3a.*|x1.*|x1e.*|z1d.*|u-*tb1.metal)$ ]]; then
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
	if [[ "$InstanceType" =~ ^(a1.*|c5.*|c5a.*|c5ad.*|c5adn.*|c5an.*|c5d.*|c5n.*|f1.*|g4dn.*|i3.*|i3en.*|i3p.*|m5.*|m5a.*|m5ad.*|m5d.*|m5dn.*|m5n.*|p3dn.*|r5.*|r5a.*|r5ad.*|r5d.*|r5dn.*|r5n.*|t3.*|t3a.*|z1d.*|u-*tb1.metal)$ ]]; then

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
curl -sS "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb" -o "/tmp/amazon-ssm-agent.deb"
dpkg -i "/tmp/amazon-ssm-agent.deb"

apt show amazon-ssm-agent

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
# Custom Package Install [Amazon CloudWatch Agent]
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/download-cloudwatch-agent-commandline.html
# https://github.com/aws/amazon-cloudwatch-agent
#-------------------------------------------------------------------------------
curl -sS "https://s3.amazonaws.com/amazoncloudwatch-agent/debian/amd64/latest/amazon-cloudwatch-agent.deb" -o "/tmp/amazon-cloudwatch-agent.deb"
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

# Configure Amazon CloudWatch Agent software (OpenTelemetry Collector settings)
/usr/bin/amazon-cloudwatch-agent-ctl -a fetch-config -o default -s

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
# /opt/aws/ec2rl/ec2rl software-check

# Diagnosis [dig modules]
# /opt/aws/ec2rl/ec2rl run --only-modules=dig --domain=amazon.com

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
#-------------------------------------------------------------------------------

apt install -y -q ansible

ansible --version

ansible localhost -m setup

#-------------------------------------------------------------------------------
# Custom Package Installation [fluentd]
# https://docs.fluentd.org/installation/install-by-deb
#-------------------------------------------------------------------------------

# curl -fsSL "https://toolbelt.treasuredata.com/sh/install-debian-bullseye-td-agent4.sh" | sh

# apt show td-agent

# systemctl daemon-reload

# systemctl restart td-agent

# systemctl status -l td-agent

# # Configure fluentd software (Start Daemon td-agent)
# if [ $(systemctl is-enabled td-agent) = "disabled" ]; then
# 	systemctl enable td-agent
# 	systemctl is-enabled td-agent
# fi

# # Package bundled ruby gem package information
# /opt/td-agent/bin/fluent-gem list

#-------------------------------------------------------------------------------
# Custom Package Installation [Terraform]
# https://www.terraform.io/docs/cli/install/apt.html
#-------------------------------------------------------------------------------

# Import GPG Key File
curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add -

# Add the HashiCorp Linux Repository
apt-add-repository "deb [arch=$(dpkg --print-architecture)] https://apt.releases.hashicorp.com $(lsb_release -cs) main"

# apt repository metadata Clean up
apt clean -y

# Update and install Terraform Infrastructure as Code (IaC) Tools (from HashiCorp Linux Repository)
apt update -y -q && apt install -y -q terraform

# Package Information
apt show terraform

terraform version

# Configure terraform software

## terraform -install-autocomplete
cat > /etc/profile.d/terraform.sh << __EOF__
if [ -n "\$BASH_VERSION" ]; then
	complete -C /usr/bin/terraform terraform
fi
__EOF__

source /etc/profile.d/terraform.sh

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------

# apt repository metadata Clean up
apt clean -y -q

# Default Package Update
apt update -y -q && apt upgrade -y -q && apt full-upgrade -y -q

# Clean up package
apt autoremove -y -q

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
	if [ $(cat /proc/cmdline | grep -x apparmor) ]; then
		# Linux Security Information(AppArmor) [aa-status]
		aa-status
	fi
fi

#-------------------------------------------------------------------------------
# Configure Amazon Time Sync Service
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
#-------------------------------------------------------------------------------

# Configure NTP Client software (Install chrony Package)
apt install -y -q chrony

apt show chrony

if [ $(systemctl is-active chronyd) = "active" ]; then
	systemctl daemon-reload
	systemctl restart chronyd
	sleep 3
	systemctl status -l chronyd
else
	systemctl daemon-reload
	systemctl start chronyd
	sleep 3
	systemctl status -l chronyd
fi

# Configure NTP Client software (Start Daemon chronyd)
if [ $(systemctl is-enabled chronyd) = "disabled" ]; then
	systemctl enable chronyd
	systemctl is-enabled chronyd
fi

# Contents of the configuration file
ChronyConfigFile="/etc/chrony/chrony.conf"
cat ${ChronyConfigFile}

# Configure NTP Client software (Enable log settings in Chrony configuration file)
sed -i 's/#log tracking measurements statistics/log measurements statistics tracking/g' ${ChronyConfigFile}

# Configure NTP Client software (Activate Amazon Time Sync Service settings in the Chrony configuration file)
if [ $(cat ${ChronyConfigFile} | grep -ie "169.254.169.123" | wc -l) = "0" ]; then
	echo "NTP server (169.254.169.123) for Amazon Time Sync Service is not configured in the configuration file."

	# Configure the NTP server (169.254.169.123) for Amazon Time Sync Service in the configuration file.
	if [ $(cat ${ChronyConfigFile} | grep -ie ".pool.ntp.org" | wc -l) = "0" ]; then
		# Variables (for editing the Chrony configuration file)
		VAR_CHRONY_NUM="1"

		# Change settings (Chrony configuration file)
		sed -i "${VAR_CHRONY_NUM}"'s/^/# Use the Amazon Time Sync Service.\nserver 169.254.169.123 prefer iburst minpoll 4 maxpoll 4\n\n/' ${ChronyConfigFile}
	else
		# Variables (for editing the Chrony configuration file)
		VAR_CHRONY_STR=$(cat ${ChronyConfigFile} | grep -ie "pool" -ie "server" | tail -n 1)
		VAR_CHRONY_NUM=`expr $(grep -e "$VAR_CHRONY_STR" -n ${ChronyConfigFile} | sed -e 's/:.*//g') + 1`

		# Change settings (Chrony configuration file)
		sed -i "${VAR_CHRONY_NUM}"'s/^/\n# Use the Amazon Time Sync Service.\nserver 169.254.169.123 prefer iburst minpoll 4 maxpoll 4\n\n/' ${ChronyConfigFile}
	fi

	# Contents of the configuration file
	cat ${ChronyConfigFile}
fi

# Configure NTP Client software (Check the status of time synchronization by Chrony)
if [ $(systemctl is-active chronyd) = "active" ]; then
	systemctl daemon-reload
	systemctl restart chronyd
else
	systemctl daemon-reload
	systemctl start chronyd
fi

if [ $(command -v chronyc) ]; then
	sleep 3
	chronyc tracking
	sleep 3
	chronyc sources -v
	sleep 3
	chronyc sourcestats -v
fi

#-------------------------------------------------------------------------------
# Configure Tuned
#-------------------------------------------------------------------------------

# Package Install Tuned
apt install -y -q tuned tuned-utils

apt show tuned

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
apt install -y -q acpid acpitool

apt show acpid

systemctl daemon-reload

systemctl restart acpid

systemctl status -l acpid

# Configure NTP Client software (Start Daemon chronyd)
if [ $(systemctl is-enabled acpid) = "disabled" ]; then
	systemctl enable acpid
	systemctl is-enabled acpid
fi

#-------------------------------------------------------------------------------
# Configure AppArmor daemon
# https://debian-handbook.info/browse/ja-JP/stable/sect.apparmor.html
#-------------------------------------------------------------------------------

# Configure AppArmor
cat /etc/default/grub

perl -pi -e 's,GRUB_CMDLINE_LINUX="(.*)"$,GRUB_CMDLINE_LINUX="$1 apparmor=1 security=apparmor",' /etc/default/grub

cat /etc/default/grub

update-grub

# Configure AppArmor daemon (Start Daemon apparmor)
if [ $(systemctl is-enabled apparmor) = "disabled" ]; then
	systemctl enable apparmor
	systemctl is-enabled apparmor
fi

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting SystemClock and Timezone
if [ "${Timezone}" = "Asia/Tokyo" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl status --all --no-pager
	timedatectl set-timezone Asia/Tokyo
	timedatectl status --all --no-pager
	dpkg-reconfigure --frontend noninteractive tzdata
	date
elif [ "${Timezone}" = "UTC" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl status --all --no-pager
	timedatectl set-timezone UTC
	timedatectl status --all --no-pager
	dpkg-reconfigure --frontend noninteractive tzdata
	date
else
	echo "# Default SystemClock and Timezone"
	date
	timedatectl status --all --no-pager
	dpkg-reconfigure --frontend noninteractive tzdata
	date
fi

# Setting System Language
if [ "${Language}" = "ja_JP.UTF-8" ]; then
	# Custom Package Installation
	apt install -y -q task-japanese

	echo "# Setting System Language -> $Language"
	locale
	localectl status --no-pager
	localectl list-locales --no-pager | grep ja_
	localectl set-locale LANG=ja_JP.UTF-8 LANGUAGE="ja_JP:ja"
	dpkg-reconfigure --frontend noninteractive locales
	localectl status --no-pager
	locale
	strings /etc/default/locale
	source /etc/default/locale
elif [ "${Language}" = "en_US.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
	locale
	localectl status --no-pager
	localectl list-locales --no-pager | grep en_
	localectl set-locale LANG=en_US.UTF-8
	dpkg-reconfigure --frontend noninteractive locales
	localectl status --no-pager
	locale
	strings /etc/default/locale
	source /etc/default/locale
else
	echo "# Default Language"
	locale
	localectl status --no-pager
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
