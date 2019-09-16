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
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_SLES-v15-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - SUSE Linux Enterprise Server 15
#    https://www.suse.com/documentation/sles-15/
#    https://www.suse.com/ja-jp/documentation/sles-15/
#    https://www.suse.com/documentation/suse-best-practices/
#    https://forums.suse.com/forumdisplay.php?94-Amazon-EC2
#    
#    https://scc.suse.com/packages/?name=SUSE%20Linux%20Enterprise%20Server&version=15.1&arch=x86_64&query=&module=
#
#    https://susepubliccloudinfo.suse.com/v1/amazon/images/active.json
#    https://susepubliccloudinfo.suse.com/v1/amazon/images/active.xml
#
#    https://aws.amazon.com/jp/partners/suse/faqs/
#    https://aws.amazon.com/marketplace/pp/B07SPX8ML1
#    http://d36cz9buwru1tt.cloudfront.net/SUSE_Linux_Enterprise_Server_on_Amazon_EC2_White_Paper.pdf
#
#    https://en.opensuse.org/YaST_Software_Management
#
#    https://github.com/SUSE-Enceladus
#-------------------------------------------------------------------------------

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

# Default repository package [zypper command]
zypper search > /tmp/command-log_zypper_repository-package-list.txt

# systemd service config
systemctl list-unit-files --no-pager -all > /tmp/command-log_systemctl_list-unit-files.txt

# Default repository list [zypper command]
zypper products > /tmp/command-log_zypper_repository-list.txt

# Default repository pattern [zypper command]
zypper search --type pattern > /tmp/command-log_zypper_repository-patterm-list.txt

# Determine the OS release
eval $(grep ^VERSION_ID= /etc/os-release)

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# SUSE Linux Enterprise Server Software repository metadata Clean up
zypper clean --all
zypper --quiet refresh -fdb

zypper repos

# Package Configure SLES Modules
#   https://www.suse.com/products/server/features/modules/
SUSEConnect --list-extensions

# Update default package
zypper --quiet --non-interactive update --auto-agree-with-licenses

# Apply SLES Service Pack
if [ -n "$VERSION_ID" ]; then
	if [ "${VERSION_ID}" = "15.2" ]; then
		echo "SUSE Linux Enterprise Server 15 SP2 -> SUSE Linux Enterprise Server 15 Lastest ServicePack"
		cat /etc/os-release
		zypper migration --quiet --non-interactive --migration "1" --auto-agree-with-licenses --recommends --details
		cat /etc/os-release

	elif [ "${VERSION_ID}" = "15.1" ]; then
		echo "SUSE Linux Enterprise Server 15 SP1 -> SUSE Linux Enterprise Server 15 Lastest ServicePack"
		cat /etc/os-release
		zypper migration --quiet --non-interactive --migration "1" --auto-agree-with-licenses --recommends --details
		cat /etc/os-release

	elif [ "${VERSION_ID}" = "15" ]; then
		echo "SUSE Linux Enterprise Server 15 GA -> SUSE Linux Enterprise Server 15 Lastest ServicePack"
		cat /etc/os-release
		zypper migration --quiet --non-interactive --migration "1" --auto-agree-with-licenses --recommends --details
		cat /etc/os-release

	else
		echo "SUSE Linux Enterprise Server 15 (Unknown)"
	fi
fi

# Install recommended packages
# zypper --quiet --non-interactive install-new-recommends

#-------------------------------------------------------------------------------
# Custom Package Installation (from SUSE Linux Enterprise Server Software repository)
#  - Packages sorted by name
#    https://www.suse.com/LinuxPackages/packageRouter.jsp?product=server&version=12&service_pack=&architecture=x86_64&package_name=index_all
#  - Packages sorted by group
#    https://www.suse.com/LinuxPackages/packageRouter.jsp?product=server&version=12&service_pack=&architecture=x86_64&package_name=index_group
#-------------------------------------------------------------------------------

# Package Install SLES System Administration Tools (from SUSE Linux Enterprise Server Software repository - Select pattern)
zypper --quiet --non-interactive install --type pattern base
zypper --quiet --non-interactive install --type pattern yast2_basis
zypper --quiet --non-interactive install --type pattern apparmor
zypper --quiet --non-interactive install --type pattern enhanced_base

# Package Install SLES System Administration Tools (from SUSE Linux Enterprise Server Software repository - Select package)
zypper --quiet --non-interactive install arptables bash-completion bcc-tools cloud-netconfig-ec2 dstat ebtables git-core hdparm hostinfo iotop kexec-tools kmod-bash-completion lsb-release lzop net-snmp nmap nvme-cli sdparm seccheck supportutils supportutils-plugin-suse-public-cloud sysstat systemd-bash-completion time traceroute tuned unrar unzip zypper-log
zypper --quiet --non-interactive install aws-efs-utils cifs-utils nfs-client nfs-utils nfs4-acl-tools yast2-nfs-client
zypper --quiet --non-interactive install libiscsi-utils libiscsi8 lsscsi open-iscsi sdparm sg3_utils yast2-iscsi-client

if [ -n "$VERSION_ID" ]; then
	if [ "${VERSION_ID}" = "15.2" ]; then
		echo "SUSE Linux Enterprise Server 15 SP2"
		zypper --quiet --non-interactive install jq
		zypper --quiet --non-interactive install pcp pcp-conf pcp-system-tools
	elif [ "${VERSION_ID}" = "15.1" ]; then
		echo "SUSE Linux Enterprise Server 15 SP1"
		zypper --quiet --non-interactive install jq
		zypper --quiet --non-interactive install pcp pcp-conf pcp-system-tools
	elif [ "${VERSION_ID}" = "15" ]; then
		echo "SUSE Linux Enterprise Server 15 GA"
		zypper --quiet --non-interactive install pcp pcp-conf
	else
		echo "SUSE Linux Enterprise Server 15 (Unknown)"
	fi
fi

# Package Install SLES System AWS Tools (from SUSE Linux Enterprise Server Software repository)
if [ -n "$VERSION_ID" ]; then
	if [ "${VERSION_ID}" = "15.2" ]; then
		echo "SUSE Linux Enterprise Server 15 SP2"
		#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
		zypper --quiet --non-interactive install python3-susepubliccloudinfo
	elif [ "${VERSION_ID}" = "15.1" ]; then
		echo "SUSE Linux Enterprise Server 15 SP1"
		#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
		zypper --quiet --non-interactive install python3-susepubliccloudinfo
	elif [ "${VERSION_ID}" = "15" ]; then
		echo "SUSE Linux Enterprise Server 15 GA"
		#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
		# zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
	else
		echo "SUSE Linux Enterprise Server 15 (Unknown)"
		#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
	fi
fi

# Package Install Python 3 Runtime (from SUSE Linux Enterprise Server Software repository)
zypper --quiet --non-interactive install python3 python3-base python3-pip python3-setuptools python3-tools python3-virtualenv python3-wheel
zypper --quiet --non-interactive install python3-Babel python3-PyJWT python3-PyYAML python3-pycrypto python3-pycurl python3-cryptography python3-python-dateutil python3-simplejson python3-six python3-urllib3

# Package Install SAP Utility and Tools (from SUSE Linux Enterprise Server Software repository
SapFlag=0
SapFlag=$(find /etc/zypp/repos.d/ -name "*SLE-Product-SLES_SAP15*" | wc -l)

if [ $SapFlag -gt 0 ]; then
	echo "SUSE Linux Enterprise Server for SAP Applications 15"

	# Package Install SAP Utility and Tools (from SUSE Linux Enterprise Server Software repository - Select pattern)
	zypper --quiet --non-interactive install --type pattern sap_server
	zypper --quiet --non-interactive install --type pattern sap-hana

	# Package Install SAP Utility and Tools (from SUSE Linux Enterprise Server Software repository - Select package)
	zypper --quiet --non-interactive install sapconf saptune insserv-compat
	zypper --quiet --non-interactive install libz1-32bit libcurl4-32bit libX11-6-32bit libidn11-32bit libgcc_s1-32bit libopenssl1_0_0 glibc-32bit glibc-i18ndata glibc-locale-32bit
else
	echo "SUSE Linux Enterprise Server 15 (non SUSE Linux Enterprise Server for SAP Applications 15)"
fi

#-------------------------------------------------------------------------------
# Custom Package Installation (from openSUSE Build Service Repository)
#   https://build.opensuse.org/
#   https://download.opensuse.org/repositories/utilities/SLE_15/
#-------------------------------------------------------------------------------

# Package Install SLES System Administration Tools (from openSUSE Build Service Repository)
if [ -n "$VERSION_ID" ]; then
	if [ "${VERSION_ID}" = "15.2" ]; then
		echo "SUSE Linux Enterprise Server 15 SP2"


	elif [ "${VERSION_ID}" = "15.1" ]; then
		echo "SUSE Linux Enterprise Server 15 SP1"

		# Add openSUSE Build Service Repository [utilities/SLE_15_SP1_Backports]
		zypper repos
		zypper addrepo --check --refresh --name "SLE_15_SP1_Backports" "https://download.opensuse.org/repositories/utilities/SLE_15_SP1_Backports/utilities.repo"
		zypper --gpg-auto-import-keys refresh utilities

		# Repository Configure openSUSE Build Service Repository
		zypper repos
		zypper clean --all
		zypper --quiet refresh -fdb
		zypper repos

		# Package Install SLES System Administration Tools (from openSUSE Build Service Repository)
		zypper --quiet --non-interactive install atop

	elif [ "${VERSION_ID}" = "15" ]; then
		echo "SUSE Linux Enterprise Server 15 GA"

		# Add openSUSE Build Service Repository [utilities/SLE_15]
		zypper repos
		zypper addrepo --check --refresh --name "SLE_15" "https://download.opensuse.org/repositories/utilities/SLE_15/utilities.repo"
		zypper --gpg-auto-import-keys refresh utilities

		# Repository Configure openSUSE Build Service Repository
		zypper repos
		zypper clean --all
		zypper --quiet refresh -fdb
		zypper repos

		# Package Install SLES System Administration Tools (from openSUSE Build Service Repository)
		zypper --quiet --non-interactive install atop

	else
		echo "SUSE Linux Enterprise Server 15 (Unknown)"
	fi
fi

#-------------------------------------------------------------------------------
# Custom Package Installation (from SUSE Package Hub Repository)
#   https://packagehub.suse.com/
#   https://packagehub.suse.com/how-to-use/
#-------------------------------------------------------------------------------

# Package Install SLES System Administration Tools (from SUSE Package Hub Repository)
if [ -n "$VERSION_ID" ]; then
	if [ "${VERSION_ID}" = "15.2" ]; then
		echo "SUSE Linux Enterprise Server 15 SP2"

		# Add SUSE Package Hub Repository : Version - SUSE Linux Enterprise 15 SP2
		# SUSEConnect --status-text
		# SUSEConnect --list-extensions
		# SUSEConnect --product "PackageHub/15.2/x86_64"
		# sleep 5

		# Repository Configure SUSE Package Hub Repository
		# SUSEConnect --status-text
		# SUSEConnect --list-extensions

		# zypper clean --all
		# zypper --quiet refresh -fdb

		# zypper repos

		# Package Install SLES System Administration Tools (from SUSE Package Hub Repository)
		# zypper --quiet --non-interactive install collectl mtr

	elif [ "${VERSION_ID}" = "15.1" ]; then
		echo "SUSE Linux Enterprise Server 15 SP1"

		# Add SUSE Package Hub Repository : Version - SUSE Linux Enterprise 15 SP1
		# SUSEConnect --status-text
		# SUSEConnect --list-extensions
		# SUSEConnect --product "PackageHub/15.1/x86_64"
		# sleep 5

		# Repository Configure SUSE Package Hub Repository
		# SUSEConnect --status-text
		# SUSEConnect --list-extensions

		# zypper clean --all
		# zypper --quiet refresh -fdb

		# zypper repos

		# Package Install SLES System Administration Tools (from SUSE Package Hub Repository)
		# zypper --quiet --non-interactive install collectl mtr

	elif [ "${VERSION_ID}" = "15" ]; then
		echo "SUSE Linux Enterprise Server 15 GA"

		# Add SUSE Package Hub Repository : Version - SUSE Linux Enterprise 15
		# SUSEConnect --status-text
		# SUSEConnect --list-extensions
		# SUSEConnect --product "PackageHub/15/x86_64"
		# sleep 5

		# Repository Configure SUSE Package Hub Repository
		# SUSEConnect --status-text
		# SUSEConnect --list-extensions

		# zypper clean --all
		# zypper --quiet refresh -fdb

		# zypper repos

		# Package Install SLES System Administration Tools (from SUSE Package Hub Repository)
		# zypper --quiet --non-interactive install collectl mtr

	else
		echo "SUSE Linux Enterprise Server 15 (Unknown)"
	fi
fi

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
SapFlag=0
SapFlag=$(find /etc/zypp/repos.d/ -name "*SLE-Product-SLES_SAP15*" | wc -l)

if [ $SapFlag -gt 0 ]; then
	if [ -n "$RoleName" ]; then
		echo "SUSE Linux Enterprise Server for SAP Applications 15"
		echo "# Get Newest AMI Information from Public AMI (AWS Martketplace/PAYG)"
		ProductCodes=$(curl -s "http://169.254.169.254/latest/meta-data/product-codes")
		if [ -n "$ProductCodes" ]; then
			NewestAmiId=$(aws ec2 describe-images --owners aws-marketplace --filters "Name=product-code,Values=${ProductCodes}" --query "sort_by(Images, &CreationDate)[-1].[ImageId]" --output text --region ${Region})
			aws ec2 describe-images --image-ids ${NewestAmiId} --output json --region ${Region}
		else
			NewestAmiId=$(aws ec2 describe-images --owners aws-marketplace --filters "Name=product-code,Values=6ajp9738nmxhrsj68dvuwztp9" --query "sort_by(Images, &CreationDate)[-1].[ImageId]" --output text --region ${Region})
			aws ec2 describe-images --image-ids ${NewestAmiId} --output json --region ${Region}
		fi
	fi
else
	if [ -n "$RoleName" ]; then
		echo "SUSE Linux Enterprise Server 15 (non SUSE Linux Enterprise Server for SAP Applications 15)"  
		echo "# Get Newest AMI Information from Public AMI"
		NewestAmiId=$(aws ec2 describe-images --owner 013907871322 --filter "Name=name,Values=suse-sles-15-*-hvm-ssd-x86_64" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)' --output text --region ${Region} | grep -v byos | grep -v ecs | grep -v sapcal | sort -k 3 --reverse | head -n 1 | awk '{print $1}')
		aws ec2 describe-images --image-ids ${NewestAmiId} --output json --region ${Region}
	fi
fi

# Get the latest AMI information of the OS type of this EC2 instance from SUSE Public Cloud Info Service
# https://www.suse.com/c/suse-public-cloud-image-life-cycle/
# https://github.com/SUSE-Enceladus/public-cloud-info-client
if [ $(command -v pint) ]; then
	pint amazon images --active --json --region=${Region}
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
#-------------------------------------------------------------------------------

zypper --quiet --non-interactive --no-gpg-checks install "https://s3.amazonaws.com/amazoncloudwatch-agent/suse/amd64/latest/amazon-cloudwatch-agent.rpm"

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

# Package Install SLES System Administration Tools (from SUSE Linux Enterprise Server Software repository)
zypper --quiet --non-interactive install python-curses

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

/opt/aws/ec2rl/ec2rl list

# Required Software Package
# /opt/aws/ec2rl/ec2rl software-check

# Diagnosis [dig modules]
# /opt/aws/ec2rl/ec2rl run --only-modules=dig --domain=amazon.com

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
# https://packagehub.suse.com/packages/ansible/
#-------------------------------------------------------------------------------

# Package Install SLES System Administration Tools (from SUSE Package Hub Repository)
# zypper --quiet --non-interactive install ansible

# ansible --version

# ansible localhost -m setup 

#-------------------------------------------------------------------------------
# Custom Package Installation [PowerShell Core(pwsh)]
# https://docs.microsoft.com/ja-jp/powershell/scripting/setup/Installing-PowerShell-Core-on-macOS-and-Linux?view=powershell-6
# https://github.com/PowerShell/PowerShell
# 
# https://packages.microsoft.com/sles/15/prod/
# 
# https://docs.aws.amazon.com/ja_jp/powershell/latest/userguide/pstools-getting-set-up-linux-mac.html
# https://www.powershellgallery.com/packages/AWSPowerShell.NetCore/
#-------------------------------------------------------------------------------

# Add the Microsoft Product repository
zypper addrepo --check --refresh --name "Microsoft-Paclages-SLE-15" "https://packages.microsoft.com/config/sles/15/prod.repo"

# Register the Microsoft signature key
rpm --import https://packages.microsoft.com/keys/microsoft.asc
zypper --gpg-auto-import-keys refresh packages-microsoft-com-prod

zypper repos

# Update the list of products
# zypper clean --all
# zypper --quiet refresh -fdb

# zypper --quiet --non-interactive update

# Install PowerShell
# zypper --quiet --non-interactive install powershell

# rpm -qi powershell

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
zypper clean --all
zypper --quiet refresh -fdb

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

# Disk Information(MountPoint) [lsblk]
lsblk

# Disk Information(File System) [df -h]
df -h

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
		# Linux Security Information(AppArmor) [rcapparmor status]
		rcapparmor status
	fi
fi

#-------------------------------------------------------------------------------
# Configure Amazon Time Sync Service
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
#-------------------------------------------------------------------------------

# Configure NTP Client software (Install chrony Package)
zypper --quiet --non-interactive install chrony

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

# Package Install Tuned (from SUSE Linux Enterprise Server Software repository)
zypper --quiet --non-interactive install tuned

rpm -qi tuned

systemctl daemon-reload

systemctl restart tuned

systemctl status -l tuned

# Configure Tuned software (Start Daemon tuned)
if [ $(systemctl is-enabled tuned) = "disabled" ]; then
	systemctl enable tuned
	systemctl is-enabled tuned
fi

# Configure Tuned software
SapFlag=0
SapFlag=$(find /etc/zypp/repos.d/ -name "*SLE-Product-SLES_SAP15*" | wc -l)

if [ $SapFlag -gt 0 ]; then
	echo "SUSE Linux Enterprise Server for SAP Applications 15"
	# Configure Tuned software (select profile - sapconf)
	tuned-adm list
	tuned-adm active
	tuned-adm profile sapconf
	# tuned-adm profile saptune
	tuned-adm active
else
	echo "SUSE Linux Enterprise Server 15 (non SUSE Linux Enterprise Server for SAP Applications 15)"  
	# Configure Tuned software (select profile - throughput-performance)
	tuned-adm list
	tuned-adm active
	tuned-adm profile throughput-performance 
	tuned-adm active
fi 

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting SystemClock and Timezone
if [ "${Timezone}" = "Asia/Tokyo" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	# timedatectl status
	timedatectl set-timezone Asia/Tokyo
	date
	# timedatectl status
elif [ "${Timezone}" = "UTC" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	# timedatectl status
	timedatectl set-timezone UTC
	date
	# timedatectl status
else
	echo "# Default SystemClock and Timezone"
	# timedatectl status
	date
fi

# Setting System Language
if [ "${Language}" = "ja_JP.UTF-8" ]; then
	# echo "# Setting System Language -> $Language"
	locale
	# localectl status
	localectl set-locale LANG=ja_JP.utf8
	locale
	# localectl status
	cat /etc/locale.conf
elif [ "${Language}" = "en_US.UTF-8" ]; then
	# echo "# Setting System Language -> $Language"
	locale
	# localectl status
	localectl set-locale LANG=en_US.utf8
	locale
	# localectl status
	cat /etc/locale.conf
else
	echo "# Default Language"
	locale
	cat /etc/locale.conf
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
