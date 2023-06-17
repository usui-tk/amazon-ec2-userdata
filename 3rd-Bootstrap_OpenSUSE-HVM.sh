#!/bin/bash -v

set -e -x

# Logger
exec > >(tee /var/log/user-data_3rd-bootstrap.log || logger -t user-data -s 2> /dev/console) 2>&1

################################################################################
#                                                                              #
#  Script Evaluated Operating System Information - [Open SUSE 15.5]            #
#                                                                              #
################################################################################

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
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_OpenSUSE-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - openSUSE Leap
#
#    https://en.opensuse.org
#    https://mirrors.opensuse.org/
#    https://wiki.geeko.jp/
#
#    https://en.opensuse.org/YaST_Software_Management
#
#    https://build.opensuse.org/project
#    https://build.opensuse.org/project/show/Cloud:Images:Leap_15.5
#
#    https://aws.amazon.com/marketplace/seller-profile?id=730aa725-c0c9-4d1d-863f-8e7325fccad4
#    https://aws.amazon.com/marketplace/pp/prodview-wn2xje27ui45o
#
#    https://github.com/SUSE-Enceladus
#-------------------------------------------------------------------------------

# Cleanup repository information
zypper clean --all

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

# Default installation package [zypper command]
zypper search --installed-only > /tmp/command-log_zypper_installed-package.txt

# Default repository products list [zypper command]
zypper products > /tmp/command-log_zypper_repository-products-list.txt

# Default repository patterns list [zypper command]
zypper patterns > /tmp/command-log_zypper_repository-patterns-list.txt

# Default repository packages list [zypper command]
zypper packages > /tmp/command-log_zypper_repository-packages-list.txt

# systemd unit files
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

# systemd service config
systemctl list-units --type=service --all --no-pager > /tmp/command-log_systemctl_list-service-config.txt

# Determine the OS release
eval $(grep ^VERSION_ID= /etc/os-release)

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# openSUSE Leap Linux Software repository metadata Clean up
zypper clean --all
# zypper --quiet refresh -fdb

# openSUSE Leap Linux Software repository information
zypper repos --uri

# Update default package
zypper --quiet --non-interactive update --auto-agree-with-licenses

# Apply openSUSE Leap Linux Service Pack
# (Service pack information as of 2023.6.17 : openSUSE Leap 15.5)
ServicePackStatus="0"

if [ -n "$VERSION_ID" ]; then
	if [ "${VERSION_ID}" = "15.5" ]; then
		echo "openSUSE Leap ${VERSION_ID}"
		cat /etc/os-release

		# openSUSE Leap Linux Software repository information
		zypper repos --uri

	elif [ "${VERSION_ID}" = "15.4" ] || [ "${VERSION_ID}" = "15.3" ] || [ "${VERSION_ID}" = "15.2" ] || [ "${VERSION_ID}" = "15.1" ] || [ "${VERSION_ID}" = "15.0" ]; then
		echo "openSUSE Leap ${VERSION_ID}"
		cat /etc/os-release

		# openSUSE Leap Linux Software repository information
		zypper repos --uri

		# Backup openSUSE Leap Linux Software repository configuration files
		cp -Rv /etc/zypp/repos.d /etc/zypp/repos.d.Old

		# Change openSUSE Leap Linux Software repository configuration files
		if [ "${VERSION_ID}" = "15.5" ]; then
			echo "openSUSE Leap ${VERSION_ID}"
			cat /etc/os-release
		elif [ "${VERSION_ID}" = "15.4" ]; then
			# Change repository information (15.4 -> 15.5)
			sed -i 's/15.4/15.5/g' /etc/zypp/repos.d/*.repo
		elif [ "${VERSION_ID}" = "15.3" ]; then
			# Change repository information (15.3 -> 15.5)
			sed -i 's/15.3/15.5/g' /etc/zypp/repos.d/*.repo
		elif [ "${VERSION_ID}" = "15.2" ]; then
			# Change repository information (15.2 -> 15.5)
			sed -i 's/15.2/15.5/g' /etc/zypp/repos.d/*.repo
		elif [ "${VERSION_ID}" = "15.1" ]; then
			# Change repository information (15.1 -> 15.5)
			sed -i 's/15.1/15.5/g' /etc/zypp/repos.d/*.repo
		elif [ "${VERSION_ID}" = "15.0" ]; then
			# Change repository information (15.0 -> 15.5)
			sed -i 's/15.0/15.5/g' /etc/zypp/repos.d/*.repo
		else
			echo "openSUSE Leap ${VERSION_ID}"
			cat /etc/os-release
		fi

		# Renew repository information
		zypper --gpg-auto-import-keys --quiet refresh -fdb

		# Apply openSUSE Leap Linux Service Pack
		zypper --quiet --non-interactive dist-upgrade --auto-agree-with-licenses || ServicePackStatus=$?
		if [ $ServicePackStatus -eq 0 ]; then
			echo "Successful execution [Zypper dist-upgrade Command]"
			eval $(grep ^VERSION_ID= /etc/os-release)
			# Clean up
			rm -rf /etc/zypp/repos.d.Old
		else
			echo "Failed to execute [Zypper dist-upgrade Command]"
		fi

		echo "openSUSE Leap ${VERSION_ID}"
		cat /etc/os-release

	else
		echo "openSUSE Leap ${VERSION_ID}"
		cat /etc/os-release
	fi
fi

# openSUSE Leap Linux Software repository metadata Clean up
zypper clean --all
# zypper --quiet refresh -fdb

# Install recommended packages
# zypper --quiet --non-interactive install-new-recommends

#-------------------------------------------------------------------------------
# Custom Package Installation (from openSUSE Leap community Software repository)
#-------------------------------------------------------------------------------

# Package Install SLES System Administration Tools (from openSUSE Leap community Software repository - Select pattern)
zypper --quiet --non-interactive install --type pattern base
zypper --quiet --non-interactive install --type pattern console
zypper --quiet --non-interactive install --type pattern yast2_basis
zypper --quiet --non-interactive install --type pattern apparmor
zypper --quiet --non-interactive install --type pattern enhanced_base

# Package Install SLES System Administration Tools (from openSUSE Leap community Software repository - Select package)
zypper --quiet --non-interactive install aaa_base aaa_base-extras arptables atop bash-completion bash-loadables bc bcc-tools bind-utils blktrace cloud-netconfig-ec2 collectl conntrack-tools curl dstat ebtables ethtool expect fio gdisk git-core glib2-lang glibc-extra gperftools hdparm hostinfo intltool iotop iotop jq kexec-tools kmod-bash-completion libicu lsb-release lvm2 lzop man-pages man-pages-posix mcelog mdadm mlocate mtr net-snmp nftables nmap numactl nvme-cli nvmetcli parted patchutils pmdk pmdk-tools psmisc psutils rsync sdparm seccheck smartmontools strace supportutils sysfsutils syslinux sysstat system-group-wheel system-user-bin system-user-daemon tcpdump time traceroute tree tuned unrar unzip util-linux vim-enhanced wget xfsdump xfsprogs yq zip zypper-log

zypper --quiet --non-interactive install aws-efs-utils cifs-utils nfs-client nfs-utils nfs4-acl-tools yast2-nfs-client

zypper --quiet --non-interactive install libiscsi-utils libiscsi8 lsscsi open-iscsi sdparm sg3_utils yast2-iscsi-client

zypper --quiet --non-interactive install pcp pcp-conf 'pcp-pmda-*' pcp-system-tools pcp-zeroconf

# openSUSE Leap Linux Software repository metadata Clean up
zypper clean --all
# zypper --quiet refresh -fdb

# Package Install Python 3 Runtime (from openSUSE Leap community Software repository)
zypper --quiet --non-interactive install python3 python3-base python3-pip python3-setuptools python3-tools python3-virtualenv python3-wheel
zypper --quiet --non-interactive install python3-Babel python3-PyJWT python3-PyYAML python3-pycurl python3-cryptography python3-python-dateutil python3-requests-aws python3-simplejson python3-six python3-urllib3

# openSUSE Leap Linux Software repository metadata Clean up
zypper clean --all
# zypper --quiet refresh -fdb

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

	if [ $(rpm -qa | grep aws-cli) ]; then
		rpm -qi aws-cli

		zypper --quiet --non-interactive remove aws-cli
	fi

fi

# Prohibit installation of AWS-CLI v1 package from repository
zypper --quiet --non-interactive locks
zypper --quiet --non-interactive addlock aws-cli
zypper --quiet --non-interactive locks

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
	ProductCodes=$(curl -s "http://169.254.169.254/latest/meta-data/product-codes")
	if [ -n "$ProductCodes" ]; then
		echo "# Get Newest AMI Information from Public AMI (AWS Martketplace)"
		NewestAmiId=$(aws ec2 describe-images --owners aws-marketplace --filters "Name=product-code,Values=${ProductCodes}" --query "sort_by(Images, &CreationDate)[-1].[ImageId]" --output text --region ${Region})
		aws ec2 describe-images --image-ids ${NewestAmiId} --output json --region ${Region}
	else
		echo "# Get Newest AMI Information from Public AMI"
		NewestAmiId=$(aws ec2 describe-images --owner 679593333241 --filter "Name=name,Values=openSUSE-Leap-15-*-hvm-ssd-x86_64*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)' --output text --region ${Region} | sort -k 3 --reverse | head -n 1 | awk '{print $1}')
		aws ec2 describe-images --image-ids ${NewestAmiId} --output json --region ${Region}
	fi
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

zypper --quiet --non-interactive --no-gpg-checks install "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

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

# zypper --quiet --non-interactive --no-gpg-checks install "https://s3.amazonaws.com/amazoncloudwatch-agent/suse/amd64/latest/amazon-cloudwatch-agent.rpm"

# rpm -qi amazon-cloudwatch-agent

# cat /opt/aws/amazon-cloudwatch-agent/bin/CWAGENT_VERSION

# cat /opt/aws/amazon-cloudwatch-agent/etc/common-config.toml

# systemctl daemon-reload

# # Configure Amazon CloudWatch Agent software (Start Daemon awsagent)
# if [ $(systemctl is-enabled amazon-cloudwatch-agent) = "disabled" ]; then
# 	systemctl enable amazon-cloudwatch-agent
# 	systemctl is-enabled amazon-cloudwatch-agent
# fi

# # Configure Amazon CloudWatch Agent software (Monitor settings)
# curl -sS ${CWAgentConfig} -o "/tmp/config.json"
# cat "/tmp/config.json"

# /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/tmp/config.json -s

# /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a stop
# /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a start

# systemctl status -l amazon-cloudwatch-agent

# /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status

# # View Amazon CloudWatch Agent config files
# cat /opt/aws/amazon-cloudwatch-agent/etc/common-config.toml

# cat /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml

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
# https://packagehub.suse.com/packages/ansible/
#-------------------------------------------------------------------------------

# Package Install openSUSE Leap System Administration Tools (from openSUSE Leap community Software repository)
zypper --quiet --non-interactive install ansible

ansible --version

ansible localhost -m setup

#-------------------------------------------------------------------------------
# Custom Package Installation [Terraform]
#-------------------------------------------------------------------------------

# Package Install openSUSE Leap System Administration Tools (from openSUSE Leap community Software repository)
zypper --quiet --non-interactive install terraform "terraform-provider-*"

terraform --version

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
zypper clean --all
# zypper --quiet refresh -fdb

zypper --quiet --non-interactive update

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

# Network Information(Firewall Service) [SuSEfirewall2]
if [ $(command -v SuSEfirewall2) ]; then
	if [ $(systemctl is-enabled SuSEfirewall2) = "enabled" ]; then
		# Network Information(Firewall Service) [SuSEfirewall2 status]
		#   https://en.opensuse.org/SuSEfirewall2
		SuSEfirewall2 status
	fi
fi

# Linux Security Information(AppArmor)
if [ $(command -v rcapparmor) ]; then
	if [ $(systemctl is-enabled apparmor) = "enabled" ]; then
		if [ $(aa-enabled) = "Yes" ]; then
			AppArmorStatus="0"

			# Linux Security Information(AppArmor) [rcapparmor status]
			rcapparmor status || AppArmorStatus=$?

			# Linux Security Information(AppArmor) [aa-status]
			aa-status || AppArmorStatus=$?
		fi
	fi
fi

#-------------------------------------------------------------------------------
# Configure Amazon Time Sync Service
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
#-------------------------------------------------------------------------------

# Configure NTP Client software (Install chrony Package)
zypper --quiet --non-interactive install chrony

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

# Package Install Tuned (from openSUSE Leap community Software repository)
zypper --quiet --non-interactive install tuned tuned-utils tuned-profiles-oracle

rpm -qi tuned

systemctl daemon-reload

systemctl restart tuned

systemctl status -l tuned

# Configure Tuned software (Start Daemon tuned)
if [ $(systemctl is-enabled tuned) = "disabled" ]; then
	systemctl enable tuned
	systemctl is-enabled tuned
fi

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Update default configuration for Zypper
ZypperFlag=0
ZypperFlag=$(cat /etc/zypp/zypper.conf | grep -w runSearchPackages | grep -w ask | wc -l)

if [ $ZypperFlag -gt 0 ]; then
	cat /etc/zypp/zypper.conf | grep -w runSearchPackages
	sed -i 's/# runSearchPackages = ask/runSearchPackages = never/g' /etc/zypp/zypper.conf
	cat /etc/zypp/zypper.conf | grep -w runSearchPackages
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
