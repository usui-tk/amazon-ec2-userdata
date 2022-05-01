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
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_OracleLinux-v7-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - Oracle Linux v7
#    https://www.oracle.com/technetwork/server-storage/linux/documentation/index.html
#    https://docs.oracle.com/en/operating-systems/oracle-linux/7/
#    http://yum.oracle.com/oracle-linux-7.html
#    https://github.com/oracle/oracle-linux
#
#-------------------------------------------------------------------------------

# Cleanup repository information
yum clean all

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
    lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
cat /etc/os-release

cat /etc/oracle-release
cat /etc/redhat-release

# Default installation package [rpm command]
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/command-log_rpm_installed-package.txt

# Default installation package [yum command]
yum list installed > /tmp/command-log_yum_installed-package.txt

# Default repository package [yum command]
yum list all > /tmp/command-log_yum_repository-package-list.txt

# Default repository package group [yum command]
yum groups list -v > /tmp/command-log_yum_repository-package-group-list.txt

# systemd unit files
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

# systemd service config
systemctl list-units --type=service --all --no-pager > /tmp/command-log_systemctl_list-service-config.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------
# Yum Repositories (Oracle Linux v7)
#  http://yum.oracle.com/oracle-linux-7.html
#-------------------------------------------------------------------------------

# yum repository metadata Clean up
yum --enablerepo="*" --verbose clean all

# Default Package Update (Packages Related to yum)
yum install -y yum yum-utils

# Checking repository information
yum repolist all

# Package Install Oracle Linux yum repository Files (from Oracle Linux Repository)
find /etc/yum.repos.d/

yum list *release-el7

yum install -y oraclelinux-release-el7 oracle-softwarecollection-release-el7 oracle-epel-release-el7 oracle-instantclient-release-el7 oracle-olcne-release-el7 oracle-software-release-el7 oraclelinux-developer-release-el7
yum --enablerepo="*" --verbose clean all

find /etc/yum.repos.d/

# Update AMI Defalut YUM Repositories File
if [ -f /usr/bin/ol_yum_configure.sh ]; then
	/usr/bin/ol_yum_configure.sh

	# Delete AMI Defalut YUM Repositories File
	find /etc/yum.repos.d/
	rm -rf /etc/yum.repos.d/public-yum-ol7.repo*
	find /etc/yum.repos.d/
fi

# Check the OCI variables to be used in YUM
if [ -f /etc/yum/vars/ociregion ]; then
	cat /etc/yum/vars/ociregion
fi

if [ -f /etc/yum/vars/ocidomain ]; then
	cat /etc/yum/vars/ocidomain
fi

# yum repository metadata Clean up
yum --enablerepo="*" --verbose clean all

# Checking repository information
yum repolist all

# Enable Yum Repository Data from Oracle Linux YUM repository (yum.oracle.com)
yum-config-manager --enable ol7_latest
yum-config-manager --enable ol7_UEKR6
yum-config-manager --enable ol7_optional_latest
yum-config-manager --enable ol7_addons
yum-config-manager --enable ol7_software_collections
yum-config-manager --enable ol7_oracle_software
yum-config-manager --enable ol7_oracle_instantclient21
yum-config-manager --enable ol7_developer
yum-config-manager --enable ol7_developer_EPEL
yum-config-manager --enable ol7_olcne14

# Disable Yum Repository Data from Oracle Linux YUM repository (yum.oracle.com)
yum-config-manager --disable ol7_UEKR5
yum-config-manager --disable ol7_olcne
yum-config-manager --disable ol7_olcne11
yum-config-manager --disable ol7_olcne12
yum-config-manager --disable ol7_olcne13
yum-config-manager --disable ol7_developer_UEKR5
yum-config-manager --disable ol7_developer_UEKR6
yum-config-manager --disable ol7_developer_olcne

# yum repository metadata Clean up
yum --enablerepo="*" --verbose clean all

# Checking repository information
yum repolist all

# Get Yum Repository List (Exclude Yum repository related to "Base OS, Archive")
repolist=$(yum repolist all | grep -ie "enabled" -ie "disabled" | grep -ve "Oracle Linux 7Server GA" -ve "7Server Update" -ve "_archive" -ve "ol7_security_validation" -ve "ol7_MODRHCK" -ve "UEKR3" -ve "UEKR4" -ve "UEKR5" | awk '{print $1}' | awk '{ sub("/.*$",""); print $0; }' | sort)

# Oracle Linux YUM repository package [yum command]
for repo in $repolist
do
	echo "[Target repository Name (Collect yum repository package list)] :" $repo
	yum --disablerepo="*" --enablerepo=${repo} list available > /tmp/command-log_yum_repository-package-list_${repo}.txt
	sleep 3
done

# Default Package Update
yum update -y

# Switching Linux-kernel packages (Switch from RHEL compatible kernel to Unbreakable Enterprise Kernel)
# https://docs.oracle.com/en/operating-systems/uek/6/relnotes6.0/index.html

if [ $(grubby --default-kernel | grep -ie "el7uek") ]; then
	echo "Linux Kernel Package Name : kernel-uek"
else
	echo "Linux Kernel Package Name : kernel"
	yum install -y kernel-uek kernel-uek-devel
fi

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Pre-installation package difference of Oracle Linux and RHEL (from Oracle Linux Repository)
yum install -y cloud-utils-growpart

# Package Install Oracle Linux System Administration Tools (from Oracle Linux Repository)
yum install -y abrt abrt-cli acpid arptables bash-completion bc bcc bcc-tools bind-utils blktrace bpftool crash-trace-command crypto-utils curl dstat ebtables ethtool expect fio gdisk git hdparm intltool iotop iperf3 iptraf-ng kexec-tools latencytop-tui libicu lsof lvm2 lzop man-pages mc mcelog mdadm mlocate mtr nc ncompress net-snmp-utils net-tools netsniff-ng nftables nmap numactl nvme-cli nvmetcli parted pmempool psacct psmisc rsync screen smartmontools sos strace symlinks sysfsutils sysstat tcpdump time tmpwatch traceroute tree tzdata unzip usermode util-linux vdo vim-enhanced wget wireshark xfsdump xfsprogs zip zsh
yum install -y cifs-utils nfs-utils nfs4-acl-tools
yum install -y iscsi-initiator-utils lsscsi sdparm sg3_utils
yum install -y setroubleshoot-server "selinux-policy*" setools-console checkpolicy policycoreutils policycoreutils-restorecond
yum install -y pcp pcp-manager "pcp-pmda*" pcp-selinux pcp-system-tools pcp-zeroconf

# Package Install Oracle Linux support tools (from Oracle Linux Repository)
yum install -y redhat-lsb-core

# Package Install Oracle Linux Cleanup tools (from Oracle Linux Repository)
# yum install -y ol-template-config
# yum install -y ovm-template-config*

# Package Install Oracle Linux Cloud Native Environment (from Oracle Linux Repository)
yum install -y olcne-selinux olcne-utils olcnectl yq

#-------------------------------------------------------------------------------
# Custom Package Installation [kernel live-patching tools]
# https://access.redhat.com/solutions/2206511
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/kernel_administration_guide/applying_patches_with_kernel_live_patching
#-------------------------------------------------------------------------------

# Package Install Oracle Linux kernel live-patching tools (from Oracle Linux Repository)
# yum install -y kpatch

# rpm -qi kpatch

# systemctl daemon-reload

# systemctl restart kpatch

# systemctl status -l kpatch

# Configure kpatch software (Start Daemon kpatch)
# if [ $(systemctl is-enabled kpatch) = "disabled" ]; then
# 	systemctl enable kpatch
# 	systemctl is-enabled kpatch
# fi

# kpatch information
# kpatch list

# Package List (kernel live-patch)
# yum list installed | grep kpatch

#-------------------------------------------------------------------------------
# Custom Package Installation [Python3]
#-------------------------------------------------------------------------------

# Package Install Python 3 Runtime (from Oracle Linux Repository)
yum install -y python3 python3-pip python3-devel python3-rpm-generators python3-rpm-macros python3-setuptools python3-test python3-wheel

# Version Information (Python3)
python3 -V
pip3 -V

#-------------------------------------------------------------------------------
# Custom Package Installation [EPEL]
#-------------------------------------------------------------------------------

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
# yum localinstall -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm"

# yum repository metadata Clean up
yum --enablerepo="*" --verbose clean all

# EPEL repository package [yum command]
yum --disablerepo="*" --enablerepo="ol7_developer_EPEL" list available > /tmp/command-log_yum_repository-package-list_ol7_developer_EPEL.txt

# Package Install Oracle Linux System Administration Tools (from EPEL Repository)
yum --enablerepo="ol7_developer_EPEL" install -y atop bash-completion-extras bcftools byobu collectl colordiff fping glances htop httping iftop inotify-tools inxi ipv6calc jnettop jq moreutils moreutils-parallel ncdu nload srm tcping wdiff yamllint zstd

# Package Install Oracle Linux System Administration Tools (from EPEL-Testing Repository)
# yum --enablerepo="ol7_developer_EPEL"  install -y tlog

#-------------------------------------------------------------------------------
# Custom Package Installation [Oracle Software Product]
#-------------------------------------------------------------------------------

# Package Install Oracle Database Utility (from Oracle Linux Repository)
yum install -y kmod-oracleasm oracleasm-support ocfs2-tools
yum install -y pcp-oracle-conf

# Package Install Oracle Database Developer Tool (from Oracle Linux Repository)
# yum install -y ords sqlcl

# Package Install Oracle Database Pre-Installation Tools (from Oracle Linux Repository)
# yum install -y oracle-rdbms-server-11gR2-preinstall
# yum install -y oracle-rdbms-server-12cR1-preinstall
# yum install -y oracle-database-server-12cR2-preinstall
# yum install -y oracle-database-preinstall-18c
# yum install -y oracle-database-preinstall-19c
yum install -y oracle-database-preinstall-21c

# Package Install Oracle Instant Client (from Oracle Linux Repository)
# https://yum.oracle.com/oracle-instant-client.html
yum install -y oracle-instantclient-basic oracle-instantclient-devel oracle-instantclient-jdbc oracle-instantclient-sqlplus oracle-instantclient-tools

# Package Install Oracle Enterprise Manager Agent Pre-Installation Tools (from Oracle Linux Repository)
# yum install -y oracle-em-agent-13cR2-preinstall

# Package Install Oracle E-Business Suite Pre-Installation Tools (from Oracle Linux Repository)
# yum install -y oracle-ebs-server-R12-preinstall

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
	NewestAmiInfo=$(aws ec2 describe-images --owner "131827586825" --filter "Name=name,Values=OL7.*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)|[0]' --output json --region ${Region})
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
# Custom Package Installation [AWS CloudFormation Helper Scripts]
# https://docs.aws.amazon.com/ja_jp/AWSCloudFormation/latest/UserGuide/cfn-helper-scripts-reference.html
# https://docs.aws.amazon.com/ja_jp/AWSCloudFormation/latest/UserGuide/releasehistory-aws-cfn-bootstrap.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-hup.html
# https://github.com/awslabs/aws-cloudformation-templates/blob/master/aws/solutions/HelperNonAmaznAmi/RHEL7_cfn-hup.template
#-------------------------------------------------------------------------------
# yum --enablerepo="epel" localinstall -y https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.amzn1.noarch.rpm

# yum install -y python-setuptools

# easy_install --script-dir "/opt/aws/bin/aws-cfn-bootstrap" https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz

# mkdir -m 755 -p /etc/cfn/hooks.d

# # cfn-hup.conf Configuration File
# cat > /etc/cfn/cfn-hup.conf << __EOF__
# [main]
# stack=
# __EOF__

# # cfn-auto-reloader.conf Configuration File
# cat > /etc/cfn/hooks.d/cfn-auto-reloader.conf << __EOF__
# [hookname]
# triggers=post.update
# path=Resources.EC2Instance.Metadata.AWS::CloudFormation::Init
# action=
# runas=root
# __EOF__

# # cfn-hup.service Configuration File
# cat > /lib/systemd/system/cfn-hup.service << __EOF__
# [Unit]
# Description=cfn-hup daemon

# [Service]
# Type=simple
# ExecStart=/opt/aws/aws-cfn-bootstrap/bin/cfn-hup
# Restart=always

# [Install]
# WantedBy=multi-user.target
# __EOF__

# # Execute AWS CloudFormation Helper software
# systemctl daemon-reload

# systemctl restart cfn-hup

# systemctl status -l cfn-hup

# # Configure AWS CloudFormation Helper software (Start Daemon awsagent)
# if [ $(systemctl is-enabled cfn-hup) = "disabled" ]; then
# 	systemctl enable cfn-hup
# 	systemctl is-enabled cfn-hup
# fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Manager agent (aka SSM agent)]
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
# https://github.com/aws/amazon-cloudwatch-agent
#-------------------------------------------------------------------------------

yum localinstall --nogpgcheck -y "https://s3.amazonaws.com/amazoncloudwatch-agent/oracle_linux/amd64/latest/amazon-cloudwatch-agent.rpm"

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

# Package Install Oracle Linux System Administration Tools (from Oracle Linux EPEL Repository)
yum --enablerepo="ol7_developer*" install -y ansible ansible-doc oci-ansible-collection

ansible --version

ansible localhost -m setup

#-------------------------------------------------------------------------------
# Custom Package Installation [fluentd]
# https://docs.fluentd.org/installation/install-by-rpm
#-------------------------------------------------------------------------------

# curl -fsSL "https://toolbelt.treasuredata.com/sh/install-redhat-td-agent4.sh" | sh

# [workaround - START]

## add GPG key
rpm --import https://packages.treasuredata.com/GPG-KEY-td-agent

## add treasure data repository to yum
cat > /etc/yum.repos.d/td.repo << __EOF__
[treasuredata]
name=TreasureData
baseurl=http://packages.treasuredata.com/4/redhat/RELEASEVER/\$basearch
gpgcheck=1
gpgkey=https://packages.treasuredata.com/GPG-KEY-td-agent
__EOF__

## Updated release version information.
RELEASEVER=$(/usr/bin/python -c 'import yum;yb=yum.YumBase();yb.doConfigSetup(init_plugins=False);print yb.conf.yumvar["releasever"]' | sed -e 's/[^0-9]//g')

cat /etc/yum.repos.d/td.repo

sed -i "s/RELEASEVER/$RELEASEVER/" /etc/yum.repos.d/td.repo

cat /etc/yum.repos.d/td.repo

## yum repository metadata Clean up
yum clean all

## Package Install fluentd
yum install -y td-agent

# [workaround - END]

rpm -qi td-agent

systemctl daemon-reload

systemctl restart td-agent

systemctl status -l td-agent

# Configure fluentd software (Start Daemon td-agent)
if [ $(systemctl is-enabled td-agent) = "disabled" ]; then
	systemctl enable td-agent
	systemctl is-enabled td-agent
fi

# Package bundled ruby gem package information
/opt/td-agent/bin/fluent-gem list

#-------------------------------------------------------------------------------
# Custom Package Installation [Terraform]
# http://yum.oracle.com/repo/OracleLinux/OL7/developer/x86_64/index.html
#-------------------------------------------------------------------------------

# Package Install Infrastructure as Code (IaC) Tools (from Oracle Linux Repository)
yum --enablerepo="ol7_developer" -y install terraform terraform-bundle terraform-provider-oci

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
yum clean all

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
    # firewall-cmd --list-all
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
# Configure Tuned
#-------------------------------------------------------------------------------

# Package Install Tuned (from Oracle Linux Repository)
yum install -y tuned tuned-utils tuned-profiles-oracle

rpm -qi tuned

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
# tuned-adm profile oracle
tuned-adm active

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting SELinux permissive mode
getenforce
sestatus

cat /etc/selinux/config
sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
cat /etc/selinux/config

if [ $(getenforce) = "Enforcing" ]; then
	setenforce 0
	getenforce
fi

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
# System Setting (Root Disk Extension)
#-------------------------------------------------------------------------------

# Disk Information(Partition) [parted -l]
parted -l

# Disk Information(MountPoint) [lsblk -al]
lsblk -al

# Disk Information(File System) [df -h]
df -h

# Configure cloud-init/disk_setup module
cat /etc/cloud/cloud.cfg

if [ $(grep -q disk_setup /etc/cloud/cloud.cfg) ]; then
	cat /etc/cloud/cloud.cfg
else
	sed -i 's/ - migrator/ - disk_setup\n - migrator/' /etc/cloud/cloud.cfg
	cat /etc/cloud/cloud.cfg

	# Extending a Partition and File System
	if [ $(df -hl | awk '{print $1}' | grep -x /dev/xvda1) ]; then
		echo "Amazon EC2 Instance type (Non-Nitro Hypervisor) :" $InstanceType

		# Extending a Partition
		parted -l
		lsblk -al

		LANG=C growpart --dry-run /dev/xvda 1 || GrowPartStatus=$?
		if [ "$GrowPartStatus" -eq 0 ]; then
			LANG=C growpart /dev/xvda 1
		fi

		parted -l
		lsblk -al

		sleep 15

		# Extending the File System
		if [ $(lsblk -fl | grep xvda1 | awk '{print $2}') = "ext4" ]; then
			df -khT
			resize2fs -F /dev/xvda1
			df -khT
		elif [ $(lsblk -fl | grep xvda1 | awk '{print $2}') = "xfs" ]; then
			df -khT
			xfs_growfs -d /
			df -khT
		else
			df -khT
			resize2fs -F /dev/xvda1
			df -khT
		fi

		sleep 30

	elif [ $(df -hl | awk '{print $1}' | grep -x /dev/nvme0n1p1) ]; then
		echo "Amazon EC2 Instance type (Nitro Hypervisor) :" $InstanceType

		# Extending a Partition
		parted -l
		lsblk -al

		LANG=C growpart --dry-run /dev/nvme0n1 1 || GrowPartStatus=$?
		if [ "$GrowPartStatus" -eq 0 ]; then
			LANG=C growpart /dev/nvme0n1 1
		fi

		parted -l
		lsblk -al

		sleep 15

		# Extending the File System
		if [ $(lsblk -fl | grep nvme0n1p1 | awk '{print $2}') = "ext4" ]; then
			df -khT
			resize2fs -F /dev/nvme0n1p1
			df -khT
		elif [ $(lsblk -fl | grep nvme0n1p1 | awk '{print $2}') = "xfs" ]; then
			df -khT
			xfs_growfs -d /
			df -khT
		else
			df -khT
			resize2fs -F /dev/nvme0n1p1
			df -khT
		fi

		sleep 30

	else
		echo "Amazon EC2 Instance type :" $InstanceType

		parted -l
		lsblk -al

		df -khT
	fi
fi

#-------------------------------------------------------------------------------
# Reboot
#-------------------------------------------------------------------------------

# Instance Reboot
reboot
