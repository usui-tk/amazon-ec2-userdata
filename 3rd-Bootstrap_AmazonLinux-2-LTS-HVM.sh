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
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_AmazonLinux-2-LTS-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - Amazon Linux 2
#    https://aws.amazon.com/jp/amazon-linux-2/
#    https://aws.amazon.com/jp/amazon-linux-2/release-notes/
#    https://aws.amazon.com/jp/amazon-linux-2/faqs/
#    https://cdn.amazonlinux.com/os-images/latest/
#
#    https://github.com/amazonlinux
#
#    https://hub.docker.com/_/amazonlinux/
#
#    http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-linux-ami-basics.html
#-------------------------------------------------------------------------------

# Cleanup repository information
yum --enablerepo="*" --verbose clean all

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
	lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
cat /etc/os-release

cat /etc/system-release

cat /etc/image-id

# Default installation package [rpm command]
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/command-log_rpm_installed-package.txt

# Default installation package [yum command]
yum list installed > /tmp/command-log_yum_installed-package.txt

# Default repository package [yum command]
yum list all > /tmp/command-log_yum_repository-package-list.txt

# Default repository package group [yum command]
yum groups list -v > /tmp/command-log_yum_repository-package-group-list.txt

# Special package information
amazon-linux-extras list

# systemd unit files
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

# systemd service config
systemctl list-units --type=service --all --no-pager > /tmp/command-log_systemctl_list-service-config.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# yum repository metadata Clean up
yum --enablerepo="*" --verbose clean all

# Default Package Update
yum update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Amazon Linux System Administration Tools (from Amazon Official Repository)
yum install -y acpid arptables bash-completion bc bind-utils blktrace bzip2 crash-trace-command crypto-utils curl dmidecode dstat ebtables ethtool expect finger fio gdisk git gnutls-utils hdparm htop intltool iotop iperf3 ipset iptraf-ng jq kexec-tools latencytop-tui libicu linuxptp lsof lvm2 lzop man-pages mc mcelog mdadm mlocate mtr nc ncompress net-snmp-utils netsniff-ng nftables nmap numactl nvme-cli nvmetcli parted patchutils perf psacct psmisc rsync screen smartmontools strace symlinks sysfsutils sysstat system-lsb-core tcpdump time tmpwatch traceroute tree tzdata unzip usermode util-linux uuid vim-enhanced wget wireshark xfsdump xfsprogs yum-plugin-versionlock yum-utils zip zsh zstd

yum install -y amazon-efs-utils cifs-utils nfs-utils nfs4-acl-tools

yum install -y iscsi-initiator-utils lsscsi scsi-target-utils sdparm sg3_utils

yum install -y pcp pcp-export-pcp2json pcp-manager "pcp-pmda*" pcp-system-tools pcp-zeroconf

# Package Install Python 3 Runtime (from Amazon Official Repository)
yum install -y python3 python3-pip python3-rpm-macros python3-setuptools python3-test python3-tools python3-wheel

# Package Install Amazon Linux Specific Tools (from Amazon Official Repository)
yum install -y aws-cfn-bootstrap ec2-hibinit-agent ec2-instance-connect hibagent

#-------------------------------------------------------------------------------
# Custom Package Installation [kernel-livepatch]
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/al2-live-patching.html
#-------------------------------------------------------------------------------

# Package Install Amazon Linux Kernel Live Patching (yum plugin)
yum install -y yum-plugin-kernel-livepatch

yum kernel-livepatch enable -y

# Package Install Amazon Linux Kernel Live Patching (Dynamic kernel patching)
yum install -y kpatch-runtime

# Configure Dynamic kernel patching software (Start Daemon kpatch)
if [ $(systemctl is-enabled kpatch) = "disabled" ]; then
	systemctl enable kpatch
	systemctl is-enabled kpatch
fi

# Package Install Amazon Linux Kernel Live Patching (kernel-livepatch)
amazon-linux-extras list

amazon-linux-extras enable livepatch

amazon-linux-extras list

#-------------------------------------------------------------------------------
# Custom Package Installation [EPEL]
#-------------------------------------------------------------------------------

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package (from Extras Library Repository)
amazon-linux-extras list

amazon-linux-extras install -y epel

amazon-linux-extras list

# Package Information [epel-release]
rpm -qi epel-release

# [Workaround] enable Base URL
egrep '^\[|baseurl=|metalink=' /etc/yum.repos.d/epel*

BaseUrlFlag=$(grep -l '#baseurl=' /etc/yum.repos.d/epel*.repo | wc -l)
if [ $BaseUrlFlag -gt 0 ]; then
	grep -l '#baseurl=' /etc/yum.repos.d/epel*.repo | xargs sed -i -e 's|#baseurl=|baseurl=|g'
fi

egrep '^\[|baseurl=|metalink=' /etc/yum.repos.d/epel*

# [Workaround] disable MetaLink URL
# egrep '^\[|baseurl=|metalink=' /etc/yum.repos.d/epel*
# grep -l 'metalink=' /etc/yum.repos.d/epel*.repo | xargs sed -i -e 's|metalink=|#metalink=|g'
# egrep '^\[|baseurl=|metalink=' /etc/yum.repos.d/epel*

# Disable EPEL yum repository
egrep '^\[|enabled' /etc/yum.repos.d/epel*
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel-*.repo
egrep '^\[|enabled' /etc/yum.repos.d/epel*

# yum repository metadata Clean up
yum --enablerepo="*" --verbose clean all

# EPEL repository package [yum command]
yum --disablerepo="*" --enablerepo="epel" list available > /tmp/command-log_yum_repository-package-list_epel.txt

# Package Install RHEL System Administration Tools (from EPEL Repository)
yum --enablerepo="epel" install -y atop bash-completion-extras bcftools byobu collectd collectl colordiff fping glances htop httping iftop inotify-tools inxi ipv6calc jnettop jq moreutils moreutils-parallel ncdu nload srm tcping wdiff

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

# Package Uninstall AWS-CLI v1 Tools (from RPM Package)
if [ $(compgen -ac | sort | uniq | grep -x aws) ]; then
	aws --version

	which aws

	if [ $(rpm -qa | grep awscli) ]; then
		rpm -qi awscli

		yum remove -y awscli
	fi

fi

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
# - ENA Express (Elastic Network Adapter Express)
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ena-express.html
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

			if [ $(command -v nmcli) ]; then
				# Get Network Interface Information
				ethtool -S $(nmcli -t -f DEVICE device | grep -v lo)
				ethtool -c $(nmcli -t -f DEVICE device | grep -v lo)
			fi
		fi
	fi

	# Get EC2 Instance Attribute [Network Interface Performance Attribute - ENA Express (Elastic Network Adapter Express)]
	if [[ $(aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo.EnaSrdSupported" --output text --region ${Region}) == "true" ]]; then
		echo "EnaSrdSupported is available for $InstanceType"

		echo "# Get EC2 Instance Attribute [Network Interface Performance Attribute - ENA Express (Elastic Network Adapter Express)]"
		aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo" --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types_NetworkInfo_ENA_Express.txt"

		# Get Linux Kernel Module(modinfo ena)
		echo "# Get Linux Kernel Module(modinfo ena)"
		if [ $(lsmod | awk '{print $1}' | grep -x ena) ]; then
			modinfo ena

			if [ $(command -v nmcli) ]; then
				# Get Network Interface Information
				ethtool -S $(nmcli -t -f DEVICE device | grep -v lo)
				ethtool -c $(nmcli -t -f DEVICE device | grep -v lo)
			fi
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

			if [ $(command -v nmcli) ]; then
				# Get Network Interface Information
				ethtool -S $(nmcli -t -f DEVICE device | grep -v lo)
				ethtool -c $(nmcli -t -f DEVICE device | grep -v lo)
			fi
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

#------------------------------------------------------------------------------
# Getting information about Amazon Machine Image
#------------------------------------------------------------------------------

# Get Amazon Machine Image Information
if [ -n "$RoleName" ]; then
	echo "# Get Amazon Machine Image Information"

	# Get the latest AMI information of the OS type of this EC2 instance from Public AMI
	echo "# Get Newest AMI Information from Public AMI"

	LatestAmiId=$(aws ec2 describe-images --owner "amazon" --filter "Name=name,Values=amzn2-ami-hvm-*-gp2" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)' --output json --region ${Region} | jq -r '[.[] | select(contains({Name: "BETA"}) | not)] | .[0].ImageId')

	if [ -n "$LatestAmiId" ]; then
		aws ec2 describe-images --image-ids ${LatestAmiId} --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-machine-images_describe-describe-images.txt"
	fi

	# Get the latest AMI information of the OS type of this EC2 instance from Systems Manager Parameter Store
	echo "# Get Newest AMI Information from Systems Manager Parameter Store"
	aws ssm get-parameters --names "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2" --output json --region ${Region}  > "/var/log/user-data_aws-cli_aws_ssm_get-parameters_amzn2-ami-hvm-x86_64-gp2.txt"
fi

#-------------------------------------------------------------------------------
# Custom Package Update [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------

yum localinstall --nogpgcheck -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

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
# Custom Package Install [Amazon CloudWatch Agent]
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/download-cloudwatch-agent-commandline.html
# https://github.com/aws/amazon-cloudwatch-agent
#-------------------------------------------------------------------------------

yum localinstall --nogpgcheck -y "https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm"

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
# Custom Package Installation [kernel-ng]
#-------------------------------------------------------------------------------

# Package Install Amazon Linux Next-gen Kernel (from Extras Library Repository)
# amazon-linux-extras list

# amazon-linux-extras install -y kernel-ng

# amazon-linux-extras list

# Package Information [kernel]
# rpm -qi kernel

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
#-------------------------------------------------------------------------------

# Package Install Amazon Linux System Administration Tools (from Extras Library Repository)
amazon-linux-extras list

amazon-linux-extras install -y ansible2

amazon-linux-extras list

# Package Information [ansible]
rpm -qi ansible

# Ansible Information
ansible --version
ansible localhost -m setup

#-------------------------------------------------------------------------------
# Custom Package Installation [vim]
#-------------------------------------------------------------------------------

# Package Install Amazon Linux System Administration Tools (from Extras Library Repository)
amazon-linux-extras list

amazon-linux-extras install -y vim

amazon-linux-extras list

# Package Information [vim]
rpm -qi vim-common

#-------------------------------------------------------------------------------
# Custom Package Installation [BCC]
#-------------------------------------------------------------------------------

# Package Install Amazon Linux System Administration Tools (from Extras Library Repository)
amazon-linux-extras list

amazon-linux-extras install -y BCC

amazon-linux-extras list

# Package Information [bcc]
rpm -qi bcc

#-------------------------------------------------------------------------------
# Custom Package Installation [fluentd]
# https://docs.fluentd.org/installation/install-fluent-package/install-by-rpm-fluent-package
#-------------------------------------------------------------------------------

curl -fsSL https://toolbelt.treasuredata.com/sh/install-amazon2-fluent-package5-lts.sh | sh

rpm -qi fluent-package

systemctl daemon-reload

systemctl restart fluentd

systemctl status -l fluentd

# Configure fluentd software (Start Daemon fluentd)
if [ $(systemctl is-enabled fluentd) = "disabled" ]; then
	systemctl enable fluentd
	systemctl is-enabled fluentd
fi

# Package bundled ruby gem package information
/opt/fluent/bin/fluent-gem list

#-------------------------------------------------------------------------------
# Custom Package Installation [Terraform]
# https://www.terraform.io/docs/cli/install/yum.html
#-------------------------------------------------------------------------------

# Repository Configuration (HashiCorp Linux Repository)
yum-config-manager --add-repo "https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo"

cat /etc/yum.repos.d/hashicorp.repo

# Cleanup repository information
yum --enablerepo="*" --verbose clean all

# HashiCorp Linux repository package [yum command]
yum --disablerepo="*" --enablerepo="hashicorp" list available > /tmp/command-log_yum_repository-package-list_hashicorp.txt

# Package Install Infrastructure as Code (IaC) Tools (from HashiCorp Linux Repository)
yum --enablerepo="hashicorp" install -y terraform

rpm -qi terraform

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
yum --enablerepo="*" --verbose clean all

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
yum install -y chrony

rpm -qi chrony

systemctl daemon-reload

systemctl status -l chronyd

# Configure NTP Client software (Start Daemon chronyd)
if [ $(systemctl is-enabled chronyd) = "disabled" ]; then
	systemctl enable chronyd
	systemctl is-enabled chronyd
fi

# Contents of the configuration file
ChronyConfigFile="/etc/chrony.conf"
cat ${ChronyConfigFile}

# Configure NTP Client software (Enable log settings in Chrony configuration file)
sed -i 's/#log measurements statistics tracking/log measurements statistics tracking/g' ${ChronyConfigFile}

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
# Configure Amazon Linux Kernel Autotuning (ec2sys-autotune)
# https://github.com/amazonlinux/autotune
#-------------------------------------------------------------------------------

# Package Install ec2sys-autotune
yum install -y ec2sys-autotune

rpm -qi ec2sys-autotune

systemctl daemon-reload

# Configure ec2sys-autotune software (Start Daemon autotune)
if [ $(systemctl is-enabled autotune) = "disabled" ]; then
	systemctl enable autotune
	systemctl is-enabled autotune
fi

if [ $(systemctl is-active autotune) = "active" ]; then
	autotune status
	autotune list

	# Configure ec2sys-autotune software (Check Current profile)
	autotune active
	autotune showconfig

	# Configure ec2sys-autotune software
	# autotune profile base
	# autotune profile placement-group
	# autotune profile udp-server
	# autotune apply
	# autotune active
	# autotune showconfig
fi

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting SystemClock and Timezone
if [ "${Timezone}" = "Asia/Tokyo" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl status --no-pager
	timedatectl set-timezone Asia/Tokyo
	timedatectl status --no-pager
	date
elif [ "${Timezone}" = "UTC" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl status --no-pager
	timedatectl set-timezone UTC
	timedatectl status --no-pager
	date
else
	echo "# Default SystemClock and Timezone"
	timedatectl status --no-pager
	date
fi

# Setting System Language
if [ "${Language}" = "ja_JP.UTF-8" ]; then
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
