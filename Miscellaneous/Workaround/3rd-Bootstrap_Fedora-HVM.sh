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
# Acquire unique information of Linux distribution
#  - Fedora
#    https://docs.fedoraproject.org/
#
#    https://alt.fedoraproject.org/cloud/
#    https://fedoracloud.readthedocs.io/en/latest/whatis.html
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

cat /etc/system-release

# Default installation package [rpm command]
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/command-log_rpm_installed-package.txt

# Default installation package [dnf command]
dnf list installed > /tmp/command-log_dnf_installed-package.txt

# Default repository package [dnf command]
dnf list all > /tmp/command-log_dnf_repository-package-list.txt

# Default repository package group [dnf command]
dnf group list -v > /tmp/command-log_dnf_repository-package-group-list.txt

# Default repository list [dnf command]
dnf repolist all > /tmp/command-log_dnf_repository-list.txt

# Default repository module [dnf command]
dnf module list > /tmp/command-log_dnf_module-list.txt

# systemd unit files
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

# systemd service config
systemctl list-units --type=service --all --no-pager > /tmp/command-log_systemctl_list-service-config.txt

# Determine the OS release
eval $(grep ^VERSION_ID= /etc/os-release)

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# yum repository metadata Clean up
dnf clean all

# Package Update Bash/DNF Administration Tools (from Fedora Official Repository)
dnf install -y bash dnf dnf-conf dnf-utils
dnf install -y dnf-plugins-core dnf-plugin-system-upgrade

# Checking repository information
dnf repolist all

# Cleanup repository information
dnf clean all

# Default Package Update
dnf update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Fedora System Administration Tools (from Fedora Official Repository)
dnf install -y abrt abrt-cli acpid atop bash-completion bc bcc bcc-tools bind-utils blktrace bpftool collectl crypto-policies curl dstat ebtables ethtool expect fio gdisk git glances gnutls-utils hdparm htop iftop inotify-tools intltool iotop iperf3 iptraf-ng jnettop jq kexec-tools libicu lsof lvm2 lzop man-pages mc mcelog mdadm mlocate moreutils moreutils-parallel mtr nc ncdu ncompress net-snmp-utils nftables nmap numactl nvme-cli nvmetcli parted patchutils patchutils pciutils pmempool psacct psmisc python3-dnf-plugin-versionlock python3-dnf-plugins-extras-common rsync smartmontools sos srm strace symlinks sysfsutils sysstat tcpdump time tlog tmpwatch traceroute tree tzdata unzip usermode util-linux util-linux-user vim-enhanced wget xfsdump xfsprogs zip zsh
dnf install -y cifs-utils nfs-utils nfs4-acl-tools
dnf install -y iscsi-initiator-utils lsscsi sg3_utils
dnf install -y setroubleshoot-server "selinux-policy*" setools-console checkpolicy policycoreutils policycoreutils-python-utils policycoreutils-restorecond
dnf install -y pcp pcp-export-pcp2json pcp-manager "pcp-pmda*" pcp-selinux pcp-system-tools pcp-zeroconf

if [ -n "$VERSION_ID" ]; then
	if [ "${VERSION_ID}" = "31" ]; then
		echo "fedora ${VERSION_ID}"
		dnf install -y arptables-compat
	elif [ "${VERSION_ID}" = "30" ]; then
		echo "fedora ${VERSION_ID}"
		dnf install -y arptables
	elif [ "${VERSION_ID}" = "29" ]; then
		echo "fedora ${VERSION_ID}"
		dnf install -y arptables
	elif [ "${VERSION_ID}" = "28" ]; then
		echo "fedora ${VERSION_ID}"
		dnf install -y arptables
	else
		echo "fedora ${VERSION_ID}"
	fi
fi

# Package Install Fedora support tools (from Fedora Official Repository)
dnf install -y redhat-lsb-core

# Package Install Python 3 Runtime (from Red Hat Official Repository)
dnf install -y python3 python3-pip python3-rpm-generators python3-rpm-macros python3-setuptools python3-test python3-wheel

# Package Install Fedora Web-Based support tools (from Fedora Official Repository)
# dnf install -y cockpit cockpit-dashboard cockpit-packagekit cockpit-session-recording cockpit-storaged cockpit-system cockpit-ws

# Package Install Fedora RPM Development Tools (from Fedora Official Repository)
dnf install -y rpmdevtools rpmconf

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

		dnf remove -y awscli
	fi

fi

# Package download AWS-CLI v2 Tools (from Bundle Installer)
curl -sS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
unzip -q "/tmp/awscliv2.zip" -d /tmp/

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
	NewestAmiInfo=$(aws ec2 describe-images --owner "125523088429" --filter "Name=name,Values=Fedora-Cloud-Base-*-gp2*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)|[0]' --output json --region ${Region})
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

dnf localinstall --nogpgcheck -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

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

# Package Install Fedora System Administration Tools (from Fedora Official Repository)
dnf install -y ansible ansible-doc

ansible --version

ansible localhost -m setup

#-------------------------------------------------------------------------------
# Custom Package Installation [Terraform]
# https://www.terraform.io/docs/cli/install/yum.html
#-------------------------------------------------------------------------------

# Repository Configuration (HashiCorp Linux Repository)
dnf config-manager --add-repo "https://rpm.releases.hashicorp.com/fedora/hashicorp.repo"

cat /etc/yum.repos.d/hashicorp.repo

# Cleanup repository information
dnf clean all

# HashiCorp Linux repository package [dnf command]
dnf repository-packages hashicorp list > /tmp/command-log_dnf_repository-package-list_hashicorp.txt

# Package Install Infrastructure as Code (IaC) Tools (from HashiCorp Linux Repository)
dnf --enablerepo=hashicorp -y install terraform

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
# Custom Package Installation [Docker]
#-------------------------------------------------------------------------------

# Package Install Docker Enviroment Tools (from Fedora Official Repository)
if [ -n "$VERSION_ID" ]; then
	if [ "${VERSION_ID}" = "31" ]; then
		echo "fedora ${VERSION_ID}"
		dnf install -y moby-engine
		rpm -qi moby-engine
		systemctl daemon-reload
		# systemctl restart docker
		# systemctl status -l docker
		# Configure Docker software (Start Daemon docker/moby-engine)
		if [ $(systemctl is-enabled docker) = "disabled" ]; then
			systemctl enable docker
			systemctl is-enabled docker
		fi
		# Docker Deamon Information
		docker version --format '{{json .}}' | jq .
	elif [ "${VERSION_ID}" = "30" ]; then
		echo "fedora ${VERSION_ID}"
		dnf install -y docker
		rpm -qi docker
		systemctl daemon-reload
		systemctl restart docker
		systemctl status -l docker
		# Configure Docker software (Start Daemon docker)
		if [ $(systemctl is-enabled docker) = "disabled" ]; then
			systemctl enable docker
			systemctl is-enabled docker
		fi
		# Docker Deamon Information
		docker version --format '{{json .}}' | jq .
	elif [ "${VERSION_ID}" = "29" ]; then
		echo "fedora ${VERSION_ID}"
		dnf install -y docker
		rpm -qi docker
		systemctl daemon-reload
		systemctl restart docker
		systemctl status -l docker
		# Configure Docker software (Start Daemon docker)
		if [ $(systemctl is-enabled docker) = "disabled" ]; then
			systemctl enable docker
			systemctl is-enabled docker
		fi
		# Docker Deamon Information
		docker version --format '{{json .}}' | jq .
	elif [ "${VERSION_ID}" = "28" ]; then
		echo "fedora ${VERSION_ID}"
		dnf install -y docker
		rpm -qi docker
		systemctl daemon-reload
		systemctl restart docker
		systemctl status -l docker
		# Configure Docker software (Start Daemon docker)
		if [ $(systemctl is-enabled docker) = "disabled" ]; then
			systemctl enable docker
			systemctl is-enabled docker
		fi
		# Docker Deamon Information
		docker version --format '{{json .}}' | jq .
	else
		echo "fedora ${VERSION_ID}"
	fi
fi

# Docker Pull Image (from Docker Hub)
if [ $(docker info > /dev/null 2>&1) ]; then
	echo "# Docker daemon is running"
	docker pull fedora:latest                        # Fedora
	docker pull amazonlinux:latest                   # Amazon Linux 2 LTS
else
	echo "# Docker daemon is not running"
fi

# Docker Run (Amazon Linux 2 LTS)
# docker run -it amazonlinux:latest bash
# cat /etc/system-release
# cat /etc/image-id
# exit

#-------------------------------------------------------------------------------
# Custom Package Installation [Node.js & Serverless Framework]
#-------------------------------------------------------------------------------

# Package Install Node.js NPM Enviroment Tools (from Fedora Official Repository)
dnf install -y nodejs npm

# Package Information
rpm -qi nodejs
rpm -qi npm

node -v
npm -v

# Install Serverless Framework
# https://serverless.com/
# https://github.com/serverless/serverless
# npm install -g serverless

# sls -v

# Install AWS Serverless Application Model (SAM) - SAM Local
# https://docs.aws.amazon.com/lambda/latest/dg/sam-cli-requirements.html
# npm install -g aws-sam-local

# sam --version

#-------------------------------------------------------------------------------
# Custom Package Installation [Go]
#-------------------------------------------------------------------------------
dnf install -y golang

rpm -qi golang

go version

#-------------------------------------------------------------------------------
# Custom Package Installation for Desktop Environment
#-------------------------------------------------------------------------------
dnf group install -y "GNOME"

echo "exec /usr/bin/gnome-session" >> ~/.xinitrc

#-------------------------------------------------------------------------------
# Custom Package Installation for XRDP Server
#-------------------------------------------------------------------------------
dnf install -y xrdp

rpm -qi xrdp

systemctl daemon-reload

systemctl restart xrdp

systemctl status -l xrdp

# Configure XRDP Server software (Start Daemon xrdp)
if [ $(systemctl is-enabled xrdp) = "disabled" ]; then
	systemctl enable xrdp
	systemctl is-enabled xrdp
fi

#-------------------------------------------------------------------------------
# Custom Package Installation for VNC Server
#
#  - VNC Server User : fedora [cloud-init default user]
#
#-------------------------------------------------------------------------------
dnf install -y tigervnc-server

rpm -qi tigervnc-server

systemctl daemon-reload

# # Configure VNC Server for "fedora" user
# cat > /home/fedora/vnc-setup.sh << __EOF__
# #!/bin/bash

# VNC_PASSWORD=\$(cat /dev/urandom | base64 | fold -w 8 | head -n 1)

# vncpasswd << 'EOF';
# \$VNC_PASSWORD
# \$VNC_PASSWORD
# n
# EOF

# echo "# VNC Password is \$VNC_PASSWORD" > ~/.vnc/cloud-init_configure_passwd
# __EOF__

# chmod 777 /home/fedora/vnc-setup.sh

# su - "fedora" -c "/home/fedora/vnc-setup.sh"

# # Pre-operation test of VNC server
# su - "fedora" -c "vncserver :1 -geometry 1024x768 -depth 32"

# sleep 15

# su - "fedora" -c "vncserver -kill :1"

# cat /home/fedora/.vnc/xstartup
# cat /home/fedora/.vnc/config

# # Systemd's VNC Server configuration
# cp -pr /usr/lib/systemd/system/vncserver@.service /etc/systemd/system/vncserver@:1.service

# cat /etc/systemd/system/vncserver@:1.service

# sed -i 's@<USER>@fedora@g' /etc/systemd/system/vncserver@:1.service

# cat /etc/systemd/system/vncserver@:1.service

# systemctl daemon-reload

# # Systemd's VNC Server startup
# systemctl start vncserver@:1.service

# systemctl status -l vncserver@:1.service

# # Configure XRDP Server software (Start Daemon xrdp)
# if [ $(systemctl is-enabled vncserver@:1.service) = "disabled" ]; then
# 	systemctl enable vncserver@:1.service
# 	systemctl is-enabled vncserver@:1.service
# fi

#-------------------------------------------------------------------------------
# Custom Package Installation for Desktop Application [Google Chrome]
#  - https://www.google.com/linuxrepositories/
#-------------------------------------------------------------------------------

cat > /etc/yum.repos.d/google-chrome.repo << __EOF__
[google-chrome]
name=google-chrome - \$basearch
baseurl=https://dl.google.com/linux/chrome/rpm/stable/\$basearch
enabled=1
gpgcheck=1
gpgkey=https://dl-ssl.google.com/linux/linux_signing_key.pub
__EOF__

# Cleanup repository information
dnf clean all
dnf makecache

# Install Google Chrome Stable version
dnf install -y google-chrome-stable

rpm -qi google-chrome-stable

# Install Google Chrome Beta version
# dnf install -y google-chrome-beta
# rpm -qi google-chrome-beta

# Install Google Chrome Unstable version
# dnf install -y google-chrome-unstable
# rpm -qi google-chrome-unstable

#-------------------------------------------------------------------------------
# Custom Package Installation for Desktop Application [Visual Studio Code]
#-------------------------------------------------------------------------------

rpm --import "https://packages.microsoft.com/keys/microsoft.asc"

# Add the VS Code Repository
cat > /etc/yum.repos.d/vscode.repo << __EOF__
[code]
name=Visual Studio Code
baseurl=https://packages.microsoft.com/yumrepos/vscode
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
__EOF__

# Cleanup repository information
dnf clean all
dnf makecache

# Install Visual Studio Code Stable version
dnf install -y code

rpm -qi code

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

# Package Install Tuned (from Fedora Official Repository)
yum install -y tuned tuned-utils

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
yum install -y acpid

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
	dnf install -y ibus-kkc sazanami-gothic-fonts sazanami-mincho-fonts ipa-gothic-fonts ipa-mincho-fonts vlgothic-fonts vlgothic-p-fonts

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
