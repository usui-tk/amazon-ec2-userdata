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
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_Photon-3-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - Photon OS 3
#    https://vmware.github.io/photon/
#    https://vmware.github.io/photon/#documentation
#
#    https://github.com/vmware/photon
#    https://github.com/vmware/photon/wiki
#
#-------------------------------------------------------------------------------

# Cleanup repository information
tdnf clean all

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
    lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
cat /etc/os-release

# Default installation package [rpm command]
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/command-log_rpm_installed-package.txt

# Default installation package [tdnf command]
tdnf list installed > /tmp/command-log_tdnf_installed-package.txt

# Default repository package [tdnf command]
tdnf list all > /tmp/command-log_tdnf_repository-package-list.txt

# Default repository list [tdnf command]
tdnf repolist all > /tmp/command-log_tdnf_repository-list.txt

# systemd unit files
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

# systemd service config
systemctl list-units --type=service --all --no-pager > /tmp/command-log_systemctl_list-service-config.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# Cleanup repository information
tdnf clean all

# Default Package Update (Packages Related to tdnf)
tdnf update -y tdnf

# Checking repository information
tdnf repolist all

# Get tdnf Repository List (Exclude tdnf repository related to "beta, debug, source, test, iso")
# repolist=$(tdnf repolist all --quiet | grep -ie "enabled" -ie "disabled" | grep -ve "beta" -ve "debug" -ve "source" -ve "test" -ve "iso" | awk '{print $1}' | awk '{ sub("/.*$",""); print $0; }' | sort)

# Cleanup repository information
tdnf clean all

# Default Package Update
tdnf update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Photon Linux-Kernel Modules and Tools (from VMware Photon OS Official Repository)
tdnf install -y linux-aws-oprofile

# Package Install Photon System Administration Tools (from VMware Photon OS Official Repository)
tdnf install -y bc bcc bcc-tools blktrace curl dstat ebtables ethtool expect hdparm intltool iotop jq kexec-tools lsof lvm2 man-pages mlocate nvme-cli parted pmd pmd-cli pmd-python3 psmisc rsync strace sysstat tcpdump traceroute tree unzip wget xfsprogs zip zsh
tdnf install -y cifs-utils nfs-utils
tdnf install -y lsscsi sg3_utils

# Package Install Python 3 Runtime (from VMware Photon OS Official Repository)
tdnf install -y python3 python3-devel python3-pip python3-setuptools python3-test python3-tools python3-virtualenv
tdnf install -y python3-asn1crypto python3-bcc python3-curses python3-dateutil python3-docutils python3-jmespath python3-jsonschema python3-pyasn1 python3-pyasn1-modules python3-PyYAML python3-requests python3-simplejson python3-six python3-urllib3 python3-websocket-client

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

# Package download AWS-CLI v2 Tools (from Bundle Installer)
curl -sS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
unzip -oq "/tmp/awscliv2.zip" -d /tmp/

# Package Install AWS-CLI v2 Tools (from Bundle Installer)
/tmp/aws/install -i "/opt/aws/awscli" -b "/usr/bin" --update

aws --version

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


#------------------------------------------------------------------------------
# Getting information about AWS services
#------------------------------------------------------------------------------

# Get AWS Security Token Service (AWS STS) Information
if [ -n "$RoleName" ]; then
	echo "# Get AWS Security Token Service (AWS STS) Information"
	aws sts get-caller-identity --output json
fi

# Get AWS Region List
if [ -n "$RoleName" ]; then
	echo "# Get AWS Region List"
	aws ec2 describe-regions --region ${Region} > "/var/log/user-data_aws-cli_aws-services_describe-regions.txt"
fi

# Get Amazon EC2 Instance Type List
if [ -n "$RoleName" ]; then
	echo "# Get Amazon EC2 Instance Type List"
    aws ec2 describe-instance-types --query 'InstanceTypes[?Hypervisor==`nitro`]' --output json --region ${Region} > "/var/log/user-data_aws-cli_aws-services_describe-instance-types_nitro-hypervisor.txt"
    aws ec2 describe-instance-types --query 'InstanceTypes[?Hypervisor==`xen`]' --output json --region ${Region} > "/var/log/user-data_aws-cli_aws-services_describe-instance-types_xen-hypervisor.txt"
fi

#------------------------------------------------------------------------------
# Getting information about Amazon EC2 Instance
#------------------------------------------------------------------------------

# Get Amazon EC2 Instance Information
if [ -n "$RoleName" ]; then
	echo "# Get Amazon EC2 Instance Information"
    aws ec2 describe-instances --instance-ids ${InstanceId} --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instances.txt"
fi

# Get Amazon EC2 Instance Type Information
if [ -n "$RoleName" ]; then
	echo "# Get Amazon EC2 Instance Type Information"
    aws ec2 describe-instance-types --query "InstanceTypes[?InstanceType==\`${InstanceType}\`]" --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types.txt"
fi

# Get Amazon EC2 Instance attached EBS Volume Information
if [ -n "$RoleName" ]; then
	echo "# Get Amazon EC2 Instance attached EBS Volume Information"
    aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=${InstanceId} --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-volumes.txt"
fi

# Get Amazon EC2 Instance attached VPC Security Group Information
if [ -n "$RoleName" ]; then
	echo "# Get Amazon EC2 Instance attached VPC Security Group Information"
    aws ec2 describe-security-groups --group-ids $(aws ec2 describe-instances --instance-id ${InstanceId} --query "Reservations[].Instances[].SecurityGroups[].GroupId[]" --output text --region ${Region}) --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-security-groups.txt"
fi

# Get AMI information of this Amazon EC2 instance
if [ -n "$RoleName" ]; then
	echo "# Get AMI information of this Amazon EC2 instance"
    aws ec2 describe-images --image-ids ${AmiId} --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-images.txt"
fi

#------------------------------------------------------------------------------
# Getting information about Amazon EC2 Instance Attribute
# [Network Interface Performance Attribute]
#------------------------------------------------------------------------------
# - Summary of Networking and Storage Features
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#instance-type-summary-table
# - ENA (Elastic Network Adapter)
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
# - Elastic Fabric Adapter (EFA)
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/efa.html
# - Single-root I/O virtualization (SR-IOV)
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sriov-networking.html
#------------------------------------------------------------------------------

# Get EC2 Instance Attribute [Network Interface Performance Attribute]
if [ -n "$RoleName" ]; then
	echo "# Get EC2 Instance Attribute [Network Interface Performance Attribute]"

    # Get EC2 Instance Attribute [Network Interface Performance Attribute - ENA (Elastic Network Adapter)]
    if [[ $(aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo.EnaSupport" --output text --region ${Region}) == "required" ]]; then
        echo "EnaSupport is available for $InstanceType"

        echo "# Get EC2 Instance Attribute [Network Interface Performance Attribute - ENA (Elastic Network Adapter)]"
        aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo" --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types_NetworkInfo_ENA.txt"

		# Get Linux Kernel Module(modinfo ena)
		echo "# Get Linux Kernel Module(modinfo ena)"
		if [ $(lsmod | awk '{print $1}' | grep -x ena) ]; then
			modinfo ena
		fi
    fi

    # Get EC2 Instance Attribute [Network Interface Performance Attribute - Elastic Fabric Adapter (EFA)]
    if [[ $(aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo.EfaSupported" --output text --region ${Region}) == "true" ]]; then
        echo "EfaSupported is available for $InstanceType"

        echo "# Get EC2 Instance Attribute [Network Interface Performance Attribute - Elastic Fabric Adapter (EFA)]"
        aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo" --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types_NetworkInfo_EFA.txt"
    fi

    # Get EC2 Instance Attribute [Network Interface Performance Attribute - Single-root I/O virtualization (SR-IOV)]
    if [[ $(aws ec2 describe-instance-attribute --instance-id $InstanceId --attribute sriovNetSupport --query 'SriovNetSupport.Value' --output text --region ${Region}) == "simple" ]]; then
        echo "SriovNetSupport is available for $InstanceType"

        echo "# Get EC2 Instance Attribute [Network Interface Performance Attribute - Single-root I/O virtualization (SR-IOV)]"
        aws ec2 describe-instance-attribute --instance-id $InstanceId --attribute sriovNetSupport --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types_NetworkInfo_SR-IOV.txt"

		# Get Linux Kernel Module(modinfo ixgbevf)
		echo "# Get Linux Kernel Module(modinfo ixgbevf)"
		if [ $(lsmod | awk '{print $1}' | grep -x ixgbevf) ]; then
			modinfo ixgbevf
		fi
    fi
fi

#------------------------------------------------------------------------------
# Getting information about Amazon EC2 Instance Attribute
# [Storage Interface Performance Attribute]
#------------------------------------------------------------------------------
# - Summary of Networking and Storage Features
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#instance-type-summary-table
# - EBS Optimized Instance
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSOptimized.html
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSPerformance.html
# - Nitro-based Instances
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#ec2-nitro-instances
# - Amazon EBS and NVMe Volumes
#   http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nvme-ebs-volumes.html
# - SSD Instance Store Volumes
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ssd-instance-store.html
#------------------------------------------------------------------------------

# Get EC2 Instance Attribute [Storage Interface Performance Attribute]
if [ -n "$RoleName" ]; then
	echo "# Get EC2 Instance Attribute [Storage Interface Performance Attribute]"

    # Get EC2 Instance Attribute [Storage Interface Performance Attribute - EBS Optimized Instance]
    if [[ $(aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].EbsInfo.EbsOptimizedSupport" --output text --region ${Region}) == "default" ]]; then
        echo "EbsOptimizedSupport is available for $InstanceType"

        echo "# Get EC2 Instance Attribute [Storage Interface Performance Attribute - EBS Optimized Instance]"
        aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].EbsInfo" --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types_EbsInfo.txt"
    fi

    # Get EC2 Instance Attribute [Storage Interface Performance Attribute - Amazon EBS and NVMe Volumes]
    if [[ $(aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].EbsInfo.NvmeSupport" --output text --region ${Region}) == "required" ]]; then
        echo "NvmeSupport is available for $InstanceType"

		# Get Linux Kernel Module(modinfo nvme)
		echo "# Get Linux Kernel Module(modinfo nvme)"
		if [ $(lsmod | awk '{print $1}' | grep -x nvme) ]; then
			modinfo nvme
		fi

		# Get NVMe Device(nvme list)
		# http://www.spdk.io/doc/nvme-cli.html
		# https://github.com/linux-nvme/nvme-cli
		if [ $(command -v nvme) ]; then
			echo "# Get NVMe Device(nvme list)"
			nvme list
		fi
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


# Get Linux Block Device Read-Ahead Value(blockdev --report)
if [ $(command -v blockdev) ]; then
    echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
    blockdev --report
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------

curl -sS "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm" -o "/tmp/amazon-ssm-agent.rpm"

rpm -ivh /tmp/amazon-ssm-agent.rpm

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

# Package Install Photon System Administration Tools (from VMware Photon OS Official Repository)
# tdnf install -y ansible

# ansible --version

# ansible localhost -m setup

# Package Install Ansible (from Python Package Index (PyPI) Repository)
pip3 install ansible
pip3 show ansible

which ansible

ansible --version

ansible localhost -m setup

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
tdnf clean all

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

#-------------------------------------------------------------------------------
# Reboot
#-------------------------------------------------------------------------------

# Instance Reboot
reboot
