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
#    https://docs.oracle.com/cd/E77565_01/index.html
#    https://docs.oracle.com/cd/E52668_01/index.html
#    http://yum.oracle.com/oracle-linux-7.html
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

# systemd service config
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------
# Yum Repositories (Oracle Linux v7)
#  http://yum.oracle.com/oracle-linux-7.html
#-------------------------------------------------------------------------------

# yum repository metadata Clean up
yum clean all

# Default Package Update (Packages Related to yum)
yum install -y yum yum-utils

# Checking repository information
yum repolist all

# Package Install Oracle Linux yum repository Files (from Oracle Linux Official Repository)
find /etc/yum.repos.d/

yum search oracle-

yum install -y oraclelinux-release-el7 oraclelinux-developer-release-el7 oracle-epel-release-el7 oracle-softwarecollection-release-el7 oracle-release-el7
yum clean all

find /etc/yum.repos.d/

# Update AMI Defalut YUM Repositories File
/usr/bin/ol_yum_configure.sh

# [Workaround] Fix BaseURL
find /etc/yum.repos.d -type f -print | xargs grep '.oracle.com'
grep -l 'yum$ociregion.oracle.com' /etc/yum.repos.d/*.repo* | xargs sed -i -e 's|yum$ociregion.oracle.com|yum.oracle.com|g'
grep -l 'yum.oracle.com' /etc/yum.repos.d/*.repo* | xargs sed -i -e 's|http://yum.oracle.com|https://yum.oracle.com|g'
find /etc/yum.repos.d -type f -print | xargs grep '.oracle.com'
yum clean all

# Delete AMI Defalut YUM Repositories File
find /etc/yum.repos.d/
rm -rf /etc/yum.repos.d/public-yum-ol7.repo*
find /etc/yum.repos.d/

# yum repository metadata Clean up
yum clean all

# Checking repository information
yum repolist all

# Enable Yum Repository Data from Oracle Linux YUM repository (yum.oracle.com)
yum-config-manager --enable ol7_latest
yum-config-manager --enable ol7_UEKR5
yum-config-manager --enable ol7_optional_latest
yum-config-manager --enable ol7_addons
yum-config-manager --enable ol7_software_collections
yum-config-manager --enable ol7_oracle_instantclient

# Disable Yum Repository Data from Oracle Linux YUM repository (yum.oracle.com)
yum-config-manager --disable ol7_developer
yum-config-manager --disable ol7_developer_EPEL

# Checking repository information
yum repolist all

# yum repository metadata Clean up
yum clean all

# Default Package Update
yum update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Pre-installation package difference of Oracle Linux and RHEL (from Oracle Linux Community Repository)
yum install -y abrt abrt-cli blktrace cloud-utils-growpart parted time tmpwatch tzdata unzip usermode zip

# Package Install Oracle Linux System Administration Tools (from Oracle Linux Official Repository)
yum install -y acpid arptables bash-completion bc bcc bcc-tools bind-utils blktrace bpftool crash-trace-command crypto-utils curl dstat ebtables ethtool expect fio gdisk git hdparm intltool iotop iperf3 iptraf-ng kexec-tools libicu lsof lvm2 lzop man-pages mcelog mdadm mlocate mtr nc ncompress net-snmp-utils nftables nmap numactl nvme-cli nvmetcli pmempool psacct psmisc rsync smartmontools sos strace symlinks sysfsutils sysstat tcpdump traceroute tree unzip vdo vim-enhanced wget xfsdump xfsprogs zip zsh
yum install -y cifs-utils nfs-utils nfs4-acl-tools
yum install -y iscsi-initiator-utils lsscsi sdparm sg3_utils
yum install -y setroubleshoot-server selinux-policy* setools-console checkpolicy policycoreutils policycoreutils-restorecond
yum install -y pcp pcp-manager pcp-pmda* pcp-selinux pcp-system-tools pcp-zeroconf

# Package Install Oracle Linux support tools (from Oracle Linux Official Repository)
yum install -y redhat-lsb-core

# Package Install Oracle Linux Cleanup tools (from Oracle Linux Official Repository)
yum install -y ol-template-config ovm-template-config*

# Package Install Oracle Linux kernel live-patching tools (from Oracle Linux Official Repository)
# yum install -y kpatch

# Package Install Python 3 Runtime (from Oracle Linux Official Repository)
yum install -y python3 python3-pip python3-devel python3-rpm-generators python3-rpm-macros python3-setuptools python3-test python3-wheel

#-------------------------------------------------------------------------------
# Custom Package Installation [EPEL]
#-------------------------------------------------------------------------------

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
# yum localinstall -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
cat > /etc/yum.repos.d/epel-bootstrap.repo << __EOF__
[epel-bootstrap]
name=Bootstrap EPEL
mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-7&arch=\$basearch
failovermethod=priority
enabled=0
gpgcheck=0
__EOF__

yum clean all

yum --enablerepo=epel-bootstrap -y install epel-release

# Delete yum temporary data
rm -f /etc/yum.repos.d/epel-bootstrap.repo
rm -rf /var/cache/yum/x86_64/7Server/epel-bootstrap*

# Disable EPEL yum repository
egrep '^\[|enabled' /etc/yum.repos.d/epel*
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel-*.repo
egrep '^\[|enabled' /etc/yum.repos.d/epel*

# yum repository metadata Clean up
yum clean all

# EPEL repository package [yum command]
yum --disablerepo="*" --enablerepo="epel" list available > /tmp/command-log_yum_repository-package-list_epel.txt

# Package Install RHEL System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y atop bash-completion-extras collectl jq moreutils moreutils-parallel zstd

#-------------------------------------------------------------------------------
# Custom Package Installation [Oracle Linux Cloud Native Environment]
#-------------------------------------------------------------------------------

# Checking repository information
yum repolist all

# Package Install Oracle Linux yum repository Files (from Oracle Linux Official Repository)
find /etc/yum.repos.d/

yum install -y oracle-olcne-release-el7

find /etc/yum.repos.d/

# [Workaround] Fix BaseURL
find /etc/yum.repos.d -type f -print | xargs grep '.oracle.com'
grep -l 'yum$ociregion.oracle.com' /etc/yum.repos.d/*.repo* | xargs sed -i -e 's|yum$ociregion.oracle.com|yum.oracle.com|g'
grep -l 'yum.oracle.com' /etc/yum.repos.d/*.repo* | xargs sed -i -e 's|http://yum.oracle.com|https://yum.oracle.com|g'
find /etc/yum.repos.d -type f -print | xargs grep '.oracle.com'

# Developer Preview packages for Oracle Linux Cloud Native Environment Oracle Linux 7 (x86_64)
#  https://yum.oracle.com/repo/OracleLinux/OL7/developer/olcne/x86_64/index.html
yum-config-manager --enable ol7_developer_olcne

# Checking repository information
yum repolist all

# yum repository metadata Clean up
yum clean all

#-------------------------------------------------------------------------------
# Custom Package Installation [Oracle Software Product]
#-------------------------------------------------------------------------------

# Package Install Oracle Database Utility (from Oracle Linux Official Repository)
yum install -y kmod-oracleasm oracleasm-support ocfs2-tools

# Package Install Oracle Database Pre-Installation Tools (from Oracle Linux Official Repository)
# yum install -y oracle-rdbms-server-11gR2-preinstall
# yum install -y oracle-rdbms-server-12cR1-preinstall
# yum install -y oracle-database-server-12cR2-preinstall
# yum install -y oracle-database-preinstall-18c
yum install -y oracle-database-preinstall-19c

# Package Install Oracle Enterprise Manager Agent Pre-Installation Tools (from Oracle Linux Official Repository)
yum install -y oracle-em-agent-13cR2-preinstall

# Package Install Oracle Instant Client (from Oracle Linux Official Repository)
yum install -y oracle-instantclient19.3-basic oracle-instantclient19.3-devel oracle-instantclient19.3-jdbc oracle-instantclient19.3-sqlplus oracle-instantclient19.3-tools

# Package Install Oracle E-Business Suite Pre-Installation Tools (from Oracle Linux Official Repository)
# yum install -y oracle-ebs-server-R12-preinstall

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


# Package Install AWS-CLI Tools (from Python Package Index (PyPI) Repository)
# yum install -y python3 python3-pip python3-devel python3-rpm-generators python3-rpm-macros python3-setuptools python3-test python3-wheel
python3 --version

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
	if [[ "$InstanceType" =~ ^(a1.*|c5.*|c5d.*|c5n.*|e3.*|f1.*|g3.*|g3s.*|g4dn.*|h1.*|i3.*|i3en.*|i3p.*|m5.*|m5a.*|m5ad.*|m5d.*|m5dn.*|m5n.*|p2.*|p3.*|p3dn.*|r4.*|r5.*|r5a.*|r5ad.*|r5d.*|r5dn.*|r5n.*|t3.*|t3a.*|x1.*|x1e.*|z1d.*|m4.16xlarge|u-*tb1.metal)$ ]]; then
		# Get EC2 Instance Attribute(Elastic Network Adapter Status)
		echo "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
		aws ec2 describe-instances --instance-id ${InstanceId} --query Reservations[].Instances[].EnaSupport --output json --region ${Region}

		# Get Linux Kernel Module(modinfo ena)
		echo "# Get Linux Kernel Module(modinfo ena)"
		if [ $(lsmod | awk '{print $1}' | grep -w ena) ]; then
			modinfo ena
		fi
	elif [[ "$InstanceType" =~ ^(c3.*|c4.*|d2.*|i2.*|r3.*|m4.*)$ ]]; then
		# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
		echo "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}

		# Get Linux Kernel Module(modinfo ixgbevf)
		echo "# Get Linux Kernel Module(modinfo ixgbevf)"
		if [ $(lsmod | awk '{print $1}' | grep -w ixgbevf) ]; then
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
		if [ $(lsmod | awk '{print $1}' | grep -w nvme) ]; then
			modinfo nvme
		fi

		# Get NVMe Device(nvme list)
		# http://www.spdk.io/doc/nvme-cli.html
		# https://github.com/linux-nvme/nvme-cli
		if [ $(lsmod | awk '{print $1}' | grep -w nvme) ]; then
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
# yum --enablerepo=epel localinstall -y https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.amzn1.noarch.rpm

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
#-------------------------------------------------------------------------------

yum localinstall --nogpgcheck -y "https://s3.amazonaws.com/amazoncloudwatch-agent/redhat/amd64/latest/amazon-cloudwatch-agent.rpm"

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

# Package Install Oracle Linux System Administration Tools (from Oracle Linux EPEL Repository)
# yum --enablerepo=ol7_developer_EPEL install -y ansible ansible-doc

# Package Install Ansible (from EPEL Repository)
yum --enablerepo=epel install -y ansible ansible-doc

ansible --version

ansible localhost -m setup

#-------------------------------------------------------------------------------
# Custom Package Installation [PowerShell Core(pwsh)]
# https://docs.microsoft.com/ja-jp/powershell/scripting/setup/Installing-PowerShell-Core-on-macOS-and-Linux?view=powershell-6
# https://github.com/PowerShell/PowerShell
#
# https://packages.microsoft.com/rhel/7/prod/
#
# https://docs.aws.amazon.com/ja_jp/powershell/latest/userguide/pstools-getting-set-up-linux-mac.html
# https://www.powershellgallery.com/packages/AWSPowerShell.NetCore/
#-------------------------------------------------------------------------------

# Register the Microsoft RedHat repository
curl https://packages.microsoft.com/config/rhel/7/prod.repo | tee /etc/yum.repos.d/microsoft.repo

# yum repository metadata Clean up
yum clean all

# Install PowerShell
yum install -y powershell

rpm -qi powershell

# Check Version
pwsh -Version

# Operation check of PowerShell command
# pwsh -Command "Get-Module -ListAvailable"

# pwsh -Command "Install-Module -Name AWSPowerShell.NetCore -AllowClobber -Force"
# pwsh -Command "Import-Module AWSPowerShell.NetCore"

# pwsh -Command "Get-Module -ListAvailable"

# pwsh -Command "Get-AWSPowerShellVersion"
# pwsh -Command "Get-AWSPowerShellVersion -ListServiceVersionInfo"

#-------------------------------------------------------------------------------
# Custom Package Installation [Oracle Developer Package:td-agent]
#-------------------------------------------------------------------------------

# Package Install Oracle Linux System Administration Tools (from Oracle Linux Development Repository)
# yum --enablerepo=ol7_developer install -y td-agent


# /opt/td-agent/usr/sbin/td-agent --version
# /opt/td-agent/usr/bin/td --version

# cat /etc/td-agent/td-agent.conf

# systemctl daemon-reload

# systemctl status -l td-agent
# systemctl enable td-agent
# systemctl is-enabled td-agent

# systemctl restart td-agent
# systemctl status -l td-agent

# Package Install Fluentd (td-agent) Gem Packages (from Ruby Gem Package)

# /opt/td-agent/usr/sbin/td-agent-gem list

# /opt/td-agent/usr/sbin/td-agent-gem search -r fluent-plugin

# /opt/td-agent/usr/sbin/td-agent-gem install fluent-plugin-aws-elasticsearch-service
# /opt/td-agent/usr/sbin/td-agent-gem install fluent-plugin-cloudwatch-logs
# /opt/td-agent/usr/sbin/td-agent-gem install fluent-plugin-kinesis
# /opt/td-agent/usr/sbin/td-agent-gem install fluent-plugin-kinesis-firehose

# /opt/td-agent/usr/sbin/td-agent-gem update fluent-plugin-s3

# /opt/td-agent/usr/sbin/td-agent-gem list

#-------------------------------------------------------------------------------
# Custom Package Installation [Oracle Developer Package:Terraform]
#-------------------------------------------------------------------------------

# Package Install Oracle Linux System Administration Tools (from Oracle Linux Development Repository)
# yum --enablerepo=ol7_developer install -y terraform

# terraform --version

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

sed -i "1i# use the local instance NTP service, if available\nserver 169.254.169.123 prefer iburst\n" /etc/chrony.conf

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

# Package Install Tuned (from Oracle Linux Official Repository)
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
setenforce 0
getenforce

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

if [ ! $(grep -q disk_setup /etc/cloud/cloud.cfg) ]; then
	sed -i 's/ - migrator/ - disk_setup\n - migrator/' /etc/cloud/cloud.cfg

	cat /etc/cloud/cloud.cfg

	# Extending a Partition and File System
	if [ $(df -hl | awk '{print $1}' | grep -w /dev/xvda1) ]; then
		echo "Amazon EC2 Instance type (Non-Nitro Hypervisor) :" $InstanceType

		# Extending a Partition
		parted -l
		lsblk -al
		LANG=C growpart --dry-run /dev/xvda 1
		LANG=C growpart /dev/xvda 1
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

	elif [ $(df -hl | awk '{print $1}' | grep -w /dev/nvme0n1p1) ]; then
		echo "Amazon EC2 Instance type (Nitro Hypervisor) :" $InstanceType

		# Extending a Partition
		parted -l
		lsblk -al
		LANG=C growpart --dry-run /dev/nvme0n1 1
		LANG=C growpart /dev/nvme0n1 1
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
