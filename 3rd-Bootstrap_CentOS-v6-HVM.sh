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
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_CentOS-v6-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - CentOS v6
#    https://docs.centos.org/en-US/docs/
#    https://wiki.centos.org/Documentation
#    https://wiki.centos.org/Cloud/AWS
#
#    https://aws.amazon.com/marketplace/pp/B00NQAYLWO
#
#    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/
#-------------------------------------------------------------------------------

# [Workaround #1] Fix BaseURL
find /etc/yum.repos.d -type f -print | xargs grep -ie 'mirrorlist.centos.org' -ie 'vault.centos.org'
grep -l 'mirrorlist.centos.org' /etc/yum.repos.d/*.repo* | xargs sed -i -e 's/^mirrorlist=http:\/\/mirrorlist.centos.org/#mirrorlist=http:\/\/mirrorlist.centos.org/g'
grep -l 'mirrorlist.centos.org' /etc/yum.repos.d/*.repo* | xargs sed -i -e 's/^#baseurl=http:\/\/mirror.centos.org/baseurl=http:\/\/vault.centos.org/g'
find /etc/yum.repos.d -type f -print | xargs grep -ie 'mirrorlist.centos.org' -ie 'vault.centos.org'

# Cleanup repository information
yum clean all

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
    lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
cat /etc/centos-release

# Default installation package [rpm command]
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/command-log_rpm_installed-package.txt

# Default installation package [yum command]
yum list installed > /tmp/command-log_yum_installed-package.txt

# Default repository package [yum command]
yum list all > /tmp/command-log_yum_repository-package-list.txt

# Default repository package group [yum command]
yum grouplist -v > /tmp/command-log_yum_repository-package-group-list.txt

# upstartd service config [chkconfig command]
chkconfig --list > /tmp/command-log_chkconfig_list.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------
# Yum Repositories (CentOS v6)
#  http://mirror.centos.org/centos-6/6/
#-------------------------------------------------------------------------------

# yum repository metadata Clean up
yum clean all

# Default Package Update (Packages Related to yum)
yum install -y yum yum-plugin-fastestmirror yum-utils

# Checking repository information
yum repolist all

# Package Install CentOS yum repository Files (from CentOS Community Repository)
find /etc/yum.repos.d/

yum search centos-release
yum install -y centos-release centos-release-scl
yum --enablerepo="*" --verbose clean all

find /etc/yum.repos.d/

# [Workaround #2] Fix BaseURL
find /etc/yum.repos.d -type f -print | xargs grep -ie 'mirrorlist.centos.org' -ie 'vault.centos.org'
grep -l 'mirrorlist.centos.org' /etc/yum.repos.d/*.repo* | xargs sed -i -e 's|# baseurl=|#baseurl=|g'
grep -l 'mirrorlist.centos.org' /etc/yum.repos.d/*.repo* | xargs sed -i -e 's/^mirrorlist=http:\/\/mirrorlist.centos.org/#mirrorlist=http:\/\/mirrorlist.centos.org/g'
grep -l 'mirrorlist.centos.org' /etc/yum.repos.d/*.repo* | xargs sed -i -e 's/^#baseurl=http:\/\/mirror.centos.org/baseurl=http:\/\/vault.centos.org/g'
find /etc/yum.repos.d -type f -print | xargs grep -ie 'mirrorlist.centos.org' -ie 'vault.centos.org'

# Cleanup repository information
yum --enablerepo="*" --verbose clean all

# Checking repository information
yum repolist all

# Checking repository information (repository configuration file)
find /etc/yum.repos.d -type f -print | xargs egrep '^\[|enabled'

# Enable repository in repository configuration file:[CentOS-Base.repo]
yum-config-manager --enable base
yum-config-manager --enable updates
yum-config-manager --enable extras

yum-config-manager --disable centosplus

# Enable repository in repository configuration file:[CentOS-SCLo-scl.repo]
yum-config-manager --enable centos-sclo-sclo

# Enable repository in repository configuration file:[CentOS-SCLo-scl-rh.repo]
yum-config-manager --enable centos-sclo-rh

# Checking repository information
yum repolist all

# Checking repository information (repository configuration file)
find /etc/yum.repos.d -type f -print | xargs egrep '^\[|enabled'

# yum repository metadata Clean up
yum --enablerepo="*" --verbose clean all

# Default Package Update
yum update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install CentOS System Administration Tools (from CentOS Community Repository)
yum install -y abrt abrt-cli acpid bc bind-utils blktrace crash-trace-command crypto-utils curl dstat ebtables ethtool expect gdisk git hdparm intltool iotop kexec-tools latencytop-tui libicu lsof lvm2 lzop man-pages mc mcelog mdadm mlocate mtr nc ncompress net-snmp-utils nmap numactl numatop parted psacct psmisc rsync screen smartmontools sos strace symlinks sysfsutils sysstat system-config-network-tui tcpdump time tmpwatch traceroute tree tzdata unzip usermode util-linux-ng vim-enhanced wget wireshark zip zsh
yum install -y cifs-utils nfs-utils nfs4-acl-tools
yum install -y iscsi-initiator-utils lsscsi scsi-target-utils sdparm sg3_utils
yum install -y setroubleshoot-server "selinux-policy*" setools-console checkpolicy policycoreutils
yum install -y pcp pcp-conf pcp-manager "pcp-pmda*" pcp-system-tools

# Package Install CentOS support tools (from CentOS Community Repository)
yum install -y redhat-lsb-core

#-------------------------------------------------------------------------------
# Custom Package Installation [Python3]
#-------------------------------------------------------------------------------

# Package Install Python 3 Runtime (from Red Hat Official Repository)
yum install -y rh-python36 rh-python36-python-pip rh-python36-python-devel rh-python36-python-setuptools rh-python36-python-setuptools rh-python36-python-simplejson rh-python36-python-test rh-python36-python-tools rh-python36-python-virtualenv rh-python36-python-wheel
yum install -y rh-python36-PyYAML rh-python36-python-docutils rh-python36-python-six

# Version Information (Python3/RHSCL)
/opt/rh/rh-python36/root/usr/bin/python3 -V
/opt/rh/rh-python36/root/usr/bin/pip3 -V

# Configuration Python3 Runtime
alternatives --install "/usr/bin/python3" python3 "/opt/rh/rh-python36/root/usr/bin/python3" 1
alternatives --display python3

alternatives --install "/usr/bin/pip3" pip3 "/opt/rh/rh-python36/root/usr/bin/pip3" 1
alternatives --display pip3

#-------------------------------------------------------------------------------
# Custom Package Installation [EPEL]
# https://archives.fedoraproject.org/pub/archive/epel/6/x86_64/
#-------------------------------------------------------------------------------

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
yum install -y epel-release

# Disable EPEL yum repository
egrep '^\[|enabled' /etc/yum.repos.d/epel*
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel-*.repo
egrep '^\[|enabled' /etc/yum.repos.d/epel*

# yum repository metadata Clean up
yum --enablerepo="*" --verbose clean all

# EPEL repository package [yum command]
yum --disablerepo="*" --enablerepo="epel" list available > /tmp/command-log_yum_repository-package-list_epel.txt

# Package Install CentOS System Administration Tools (from EPEL Repository)
yum --enablerepo="epel" install -y atop bash-completion byobu collectd colordiff fio fping glances htop httping iftop inotify-tools iperf3 iptraf-ng ipv6calc jq moreutils ncdu netsniff-ng nload srm tcping wdiff zstd

yum --enablerepo="epel" install -y cloud-utils-growpart dracut-modules-growroot

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
	NewestAmiInfo=$(aws ec2 describe-images --owner "679593333241" --filter "Name=name,Values=CentOS Linux 6 x86_64 HVM EBS ENA*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)|[0]' --output json --region ${Region})
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
#-------------------------------------------------------------------------------
# yum --enablerepo="epel" localinstall -y "https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.amzn1.noarch.rpm"

# yum --enablerepo="epel" install -y python-pip
# # pip install --upgrade pip

# pip install pystache
# pip install argparse
# pip install python-daemon
# pip install requests

# curl -sS "https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz" -o "/tmp/aws-cfn-bootstrap-latest.tar.gz"
# tar -pxzf "/tmp/aws-cfn-bootstrap-latest.tar.gz" -C /tmp

# cd /tmp/aws-cfn-bootstrap-1.4/
# python setup.py build
# python setup.py install

# chmod 775 /usr/init/redhat/cfn-hup

# if [ -L /etc/init.d/cfn-hup ]; then
# 	echo "Symbolic link exists"
# else
# 	echo "No symbolic link exists"
# 	ln -s /usr/init/redhat/cfn-hup /etc/init.d/cfn-hup
# fi

# cd /tmp

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------

yum localinstall --nogpgcheck -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

rpm -qi amazon-ssm-agent

status amazon-ssm-agent
/sbin/restart amazon-ssm-agent
status amazon-ssm-agent

ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Install [Amazon CloudWatch Agent]
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/download-cloudwatch-agent-commandline.html
# https://github.com/aws/amazon-cloudwatch-agent
#-------------------------------------------------------------------------------

yum localinstall --nogpgcheck -y "https://s3.amazonaws.com/amazoncloudwatch-agent/centos/amd64/latest/amazon-cloudwatch-agent.rpm"

# Package Information
rpm -qi amazon-cloudwatch-agent

cat /opt/aws/amazon-cloudwatch-agent/bin/CWAGENT_VERSION

cat /opt/aws/amazon-cloudwatch-agent/etc/common-config.toml

# Configure Amazon CloudWatch Agent software (Monitor settings)
curl -sS ${CWAgentConfig} -o "/tmp/config.json"
cat "/tmp/config.json"

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/tmp/config.json -s

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a stop
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a start

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status

# View Amazon CloudWatch Agent config files
cat /opt/aws/amazon-cloudwatch-agent/etc/common-config.toml

cat /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
#-------------------------------------------------------------------------------

# Package Install Ansible (from EPEL Repository)
yum --enablerepo="epel" install -y ansible ansible-doc

ansible --version

ansible localhost -m setup

#-------------------------------------------------------------------------------
# Custom Package Installation [fluentd]
# https://docs.fluentd.org/installation/install-by-rpm
#-------------------------------------------------------------------------------

curl -fsSL "https://toolbelt.treasuredata.com/sh/install-redhat-td-agent3.sh" | sh

rpm -qi td-agent

# Configure fluentd software (Start Daemon td-agent)
service td-agent restart
service td-agent status

chkconfig --list td-agent
chkconfig td-agent on
chkconfig --list td-agent

# Package bundled ruby gem package information
/opt/td-agent/embedded/bin/fluent-gem list

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

# Network Information(Firewall Service) [chkconfig --list iptables]
chkconfig --list iptables

# Network Information(Firewall Service) [service ip6tables stop]
chkconfig --list ip6tables

# Linux Security Information(SELinux) [getenforce] [sestatus]
getenforce

sestatus

#-------------------------------------------------------------------------------
# Configure Amazon Time Sync Service
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
#-------------------------------------------------------------------------------

# Replace NTP Client software (Uninstall ntpd Package)
if [ $(chkconfig --list | awk '{print $1}' | grep -x ntpd) ]; then
	chkconfig --list ntpd
	service ntpd stop
fi

yum remove -y ntp*

# Install NTP Client software (Install chrony Package)
yum install -y chrony

# Configure NTP Client software (Start Daemon chronyd)
chkconfig --list chronyd
chkconfig chronyd on
chkconfig --list chronyd

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
service chronyd restart
service chronyd status

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

# Package Install Tuned (from Red Hat Official Repository)
yum install -y tuned tuned-utils tuned-profiles-oracle

# Configure Tuned software (Start Daemon tuned)
service tuned restart
service tuned status

chkconfig --list tuned
chkconfig tuned on
chkconfig --list tuned

# Configure Tuned software (select profile - throughput-performance)
tuned-adm list

tuned-adm active
tuned-adm profile throughput-performance
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

# Firewall Service Disabled (iptables/ip6tables)
service iptables stop
chkconfig --list iptables
chkconfig iptables off
chkconfig --list iptables

service ip6tables stop
chkconfig --list ip6tables
chkconfig ip6tables off
chkconfig --list ip6tables

# Setting SystemClock and Timezone
if [ "${Timezone}" = "Asia/Tokyo" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	# Setting SystemClock
	cat /dev/null > /etc/sysconfig/clock
	echo 'ZONE="Asia/Tokyo"' >> /etc/sysconfig/clock
	echo 'UTC=false' >> /etc/sysconfig/clock
	cat /etc/sysconfig/clock
	# Setting TimeZone
	date
	/bin/cp -fp /usr/share/zoneinfo/Asia/Tokyo /etc/localtime
	date
elif [ "${Timezone}" = "UTC" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	# Setting SystemClock
	cat /dev/null > /etc/sysconfig/clock
	echo 'ZONE="UTC"' >> /etc/sysconfig/clock
	echo 'UTC=true' >> /etc/sysconfig/clock
	cat /etc/sysconfig/clock
	# Setting TimeZone
	date
	/bin/cp -fp /usr/share/zoneinfo/UTC /etc/localtime
	date
else
	echo "# Default SystemClock and Timezone"
	cat /etc/sysconfig/clock
	cat /etc/localtime
fi

# Setting System Language
if [ "${Language}" = "ja_JP.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
	cat /dev/null > /etc/sysconfig/i18n
	echo 'LANG=ja_JP.utf8' >> /etc/sysconfig/i18n
	cat /etc/sysconfig/i18n
elif [ "${Language}" = "en_US.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
	cat /dev/null > /etc/sysconfig/i18n
	echo 'LANG=en_US.utf8' >> /etc/sysconfig/i18n
	cat /etc/sysconfig/i18n
else
	echo "# Default Language"
	cat /etc/sysconfig/i18n
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

# Configure cloud-init/growpart module
cat /etc/cloud/cloud.cfg

if [ $(grep -q growpart /etc/cloud/cloud.cfg) ]; then
	cat /etc/cloud/cloud.cfg
else
	sed -i 's/ - resizefs/ - growpart\n - resizefs/' /etc/cloud/cloud.cfg
	cat /etc/cloud/cloud.cfg

	# # Initial RAM disk reorganization of the currently running Linux-kernel
	# ls -l /boot/
	# lsinitrd /boot/initramfs-$(uname -r).img | grep -ie "growroot" -ie "growpart"
	# dracut --force --add growroot /boot/initramfs-$(uname -r).img
	# lsinitrd /boot/initramfs-$(uname -r).img | grep -ie "growroot" -ie "growpart"
	# ls -l /boot/

	# # Initial RAM disk reorganization of latest Linux-kernel
	# eval $(grep ^DEFAULTKERNEL= /etc/sysconfig/kernel)
	# LastestKernelVersion=$(rpm -qa ${DEFAULTKERNEL} | sed 's/^kernel-//' | sed 's/^uek-//' | sort --reverse | head -n 1)
	# ls -l /boot/
	# lsinitrd /boot/initramfs-${LastestKernelVersion}.img | grep -ie "growroot" -ie "growpart"
	# dracut --force --add growroot /boot/initramfs-${LastestKernelVersion}.img
	# lsinitrd /boot/initramfs-${LastestKernelVersion}.img | grep -ie "growroot" -ie "growpart"
	# ls -l /boot/

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
