#!/bin/bash -v

set -e -x

# Logger
exec > >(tee /var/log/user-data-bootstrap.log || logger -t user-data -s 2> /dev/console) 2>&1

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
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_Kali-Linux-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - Kali Linux 2017.3
#    https://www.kali.org/kali-linux-documentation/
#    https://docs.kali.org/
#
#    https://aws.amazon.com/marketplace/pp/B01M26MMTT
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

# systemd service config
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

# Determine the OS release
eval $(grep ^VERSION_ID= /etc/os-release)
VersionYear=$(echo $VERSION_ID | sed -e "s/\.[^.]*$//g")

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# apt repository metadata Clean up
apt clean -y -q

# apt repository mirrors site information
curl -sI "http://http.kali.org/README"
# curl -s "http://http.kali.org/README.mirrorlist"

# Default Package Update
apt update -y -q && apt upgrade -y -q && apt dist-upgrade -y -q

# apt repository metadata Clean up
apt clean -y -q

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Debian apt Administration Tools (from Kali Linux Official Repository)
apt install -y -q apt-transport-https ca-certificates curl gnupg software-properties-common

# Package Install Kali Linux System Administration Tools (from Kali Linux Official Repository)
apt install -y -q acpid acpitool arptables atop bash-completion binutils bpfcc-tools byobu collectl debian-goodies dstat ebtables fio gdisk git hardinfo hdparm ipv6toolkit jq kexec-tools locales-all lsof lzop iotop mtr needrestart netcat nmap nvme-cli parted python3-bpfcc snmp sosreport sysstat tcpdump traceroute unzip wget zip
apt install -y -q cifs-utils nfs-common nfs4-acl-tools nfswatch
apt install -y -q open-iscsi open-isns-utils lsscsi scsitools sdparm sg3-utils
apt install -y -q apparmor apparmor-easyprof apparmor-profiles apparmor-profiles-extra apparmor-utils dh-apparmor
apt install -y -q pcp pcp-conf pcp-manager 

# Package Install Python 3 Runtime (from Debian Official Repository)
apt install -y -q python3 python3-pip python3-setuptools python3-testtools python3-toolz python3-wheel

#-------------------------------------------------------------------------------
# Custom Package Installation [Special package for Kali]
#  https://tools.kali.org/kali-metapackages
#  https://tools.kali.org/tools-listing
#-------------------------------------------------------------------------------

# Package Install Kali Linux Meta-Package
apt install -y -q kali-linux-full kali-defaults kali-linux-gpu kali-linux-top10 kali-linux-web kali-linux-forensics kali-linux-pwtools

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
apt install -y -q awscli

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
	NewestAmiInfo=$(aws ec2 describe-images --owner "679593333241" --filter "Name=name,Values=Kali Linux*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)|[0]' --output json --region ${Region})
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
	if [[ "$InstanceType" =~ ^(a1.*|c5.*|c5d.*|c5n.*|e3.*|f1.*|g3.*|g3s.*|g4dn.*|h1.*|i3.*|i3en.*|i3p.*|m5.*|m5a.*|m5ad.*|m5d.*|p2.*|p3.*|p3dn.*|r4.*|r5.*|r5a.*|r5ad.*|r5d.*|t3.*|t3a.*|x1.*|x1e.*|z1d.*|m4.16xlarge|u-6tb1.metal|u-9tb1.metal|u-12tb1.metal)$ ]]; then
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
	if [[ "$InstanceType" =~ ^(a1.*|c1.*|c3.*|c4.*|c5.*|c5d.*|c5n.*|d2.*|e3.*|f1.*|g2.*|g3.*|g3s.*|g4dn.*|h1.*|i2.*|i3.*|i3en.*|i3p.*|m1.*|m2.*|m3.*|m4.*|m5.*|m5a.*|m5ad.*|m5d.*|p2.*|p3.*|p3dn.*|r3.*|r4.*|r5.*|r5a.*|r5ad.*|r5d.*|t3.*|t3a.*|x1.*|x1e.*|z1d.*|u-6tb1.metal|u-9tb1.metal|u-12tb1.metal)$ ]]; then
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
	if [[ "$InstanceType" =~ ^(a1.*|c5.*|c5d.*|c5n.*|f1.*|g4dn.*|i3.*|i3en.*|i3p.*|m5.*|m5a.*|m5ad.*|m5d.*|p3dn.*|r5.*|r5a.*|r5ad.*|r5d.*|t3.*|t3a.*|z1d.*|u-6tb1.metal|u-9tb1.metal|u-12tb1.metal)$ ]]; then
		
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
apt install -y -q ansible

apt show ansible

ansible --version

ansible localhost -m setup 

#-------------------------------------------------------------------------------
# Custom Package Installation [Docker]
#-------------------------------------------------------------------------------

# install dependencies
apt install -y -q apt-transport-https ca-certificates curl gnupg2 software-properties-common

# install docker
apt install -y -q docker-compose

apt show docker-compose

systemctl daemon-reload

systemctl restart docker

systemctl status -l docker

# Configure Docker software (Start Daemon docker)
if [ $(systemctl is-enabled docker) = "disabled" ]; then
	systemctl enable docker
	systemctl is-enabled docker
fi

# Docker Deamon Information
docker --version

docker info

# manage Docker as a non-root user
cat /etc/group | grep docker

usermod -aG docker ec2-user

cat /etc/group | grep docker

# Docker Pull Image (from Docker Hub)
docker pull kalilinux/kali-linux-docker          # Kali Linux
docker pull amazonlinux:latest                   # Amazon Linux 2 LTS

# Docker Run (Kali Linux)
# docker run -it kalilinux/kali-linux-docker /bin/bash
# cat /etc/os-release
# exit

# Docker Run (Amazon Linux 2 LTS)
# docker run -it amazonlinux:latest bash
# cat /etc/system-release
# cat /etc/image-id 
# exit

#-------------------------------------------------------------------------------
# Custom Package Installation for Desktop Environment
#-------------------------------------------------------------------------------

# Package Install Kali Linux Desktop Environment [Desktop for Gnome 3]
apt install -y -q kali-desktop-gnome

# Package Install Kali Linux Desktop Environment for Japanese (from Kali Linux Official Repository)
apt install -y -q task-japanese task-japanese-desktop locales-all fonts-ipafont ibus-mozc

#-------------------------------------------------------------------------------
# Custom Package Installation for XRDP Server
#-------------------------------------------------------------------------------
apt install -y -q xrdp

apt show xrdp

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
#  - VNC Server User : ec2-user [cloud-init default user]
#
#-------------------------------------------------------------------------------
apt install -y -q vnc4server tigervnc-common tigervnc-standalone-server tigervnc-xorg-extension

systemctl daemon-reload

# # Configure VNC Server for "ec2-user" user
# cat > /home/ec2-user/vnc-setup.sh << __EOF__
# #!/bin/bash

# VNC_PASSWORD=\$(cat /dev/urandom | base64 | fold -w 8 | head -n 1)

# vncpasswd << 'EOF';
# \$VNC_PASSWORD
# \$VNC_PASSWORD
# n
# EOF

# # echo "# VNC Password is \$VNC_PASSWORD" > ~/.vnc/cloud-init_configure_passwd
# __EOF__

# chmod 777 /home/ec2-user/vnc-setup.sh

# su - "ec2-user" -c "/home/ec2-user/vnc-setup.sh"


# # Pre-operation test of VNC server
# su - "ec2-user" -c "vncserver :1 -geometry 1024x768 -depth 32"

# sleep 10

# su - "ec2-user" -c "vncserver -kill :1"

# # cat /home/ec2-user/.vnc/xstartup
# # cat /home/ec2-user/.vnc/config

# # Systemd's VNC Server configuration 
# cat > /etc/systemd/system/vncserver@:1.service << __EOF__
# [Unit]
# Description=Remote desktop service (VNC)
# After=syslog.target network.target

# [Service]
# Type=forking

# ExecStartPre=/bin/sh -c '/usr/bin/vncserver -kill %i > /dev/null 2>&1 || :'
# ExecStart=/usr/sbin/runuser -l ec2-user -c "/usr/bin/vncserver %i"
# PIDFile=/home/ec2-user/.vnc/%H%i.pid
# ExecStop=/bin/sh -c '/usr/bin/vncserver -kill %i > /dev/null 2>&1 || :'

# [Install]
# WantedBy=multi-user.target

# __EOF__

# cat /etc/systemd/system/vncserver@:1.service

# systemctl daemon-reload

#-------------------------------------------------------------------------------
# Custom Package Installation for Desktop Application [Google Chrome]
#  - https://www.google.com/linuxrepositories/
#-------------------------------------------------------------------------------

cd /tmp

# Import GPG Key File
curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | apt-key add -

# Add the Google Chrome Repository (Temporary)
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google.list

# apt repository metadata Clean up
apt clean -y

# Update and install Google Chrome Stable version
apt update -y -q && apt install -y -q google-chrome-stable

# Package Information
apt show google-chrome-stable

# Clean up Temporary repository file
ls -l /etc/apt/sources.list.d/
rm -rf /etc/apt/sources.list.d/google.list
ls -l /etc/apt/sources.list.d/

# apt repository metadata Clean up
apt clean -y
rm -rf /var/lib/apt/lists/*
apt update -y

#-------------------------------------------------------------------------------
# Custom Package Installation for Desktop Application [Visual Studio Code]
#-------------------------------------------------------------------------------
cd /tmp

# Download the Microsoft GPG key, and convert it from OpenPGP ASCII 
# armor format to GnuPG format
curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg

# Move the file into your apt trusted keys directory (requires root)
mv microsoft.gpg /etc/apt/trusted.gpg.d/microsoft.gpg
 
# Add the VS Code Repository
echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list

# apt repository metadata Clean up
apt clean -y

# Update and install Visual Studio Code 
apt update -y && apt install -y -q code

# Package Information
apt show code

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------

# apt repository metadata Clean up
apt clean -y -q 

# Default Package Update
apt update -y -q && apt upgrade -y -q && apt dist-upgrade -y -q

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

# Disk Information(MountPoint) [lsblk]
lsblk

# Disk Information(File System) [df -h]
df -h

# Network Information(Network Interface) [ip addr show]
ip addr show

# Network Information(Routing Table) [ip route show]
ip route show

#-------------------------------------------------------------------------------
# Configure Amazon Time Sync Service
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
#-------------------------------------------------------------------------------

# Replace NTP Client software (Uninstall ntp Package)
apt remove -y -q ntp sntp

# Configure NTP Client software (Install chrony Package)
apt install -y -q chrony

rpm -qi chrony

systemctl daemon-reload

systemctl restart chrony

systemctl status -l chrony

# Configure NTP Client software (Start Daemon chrony)
if [ $(systemctl is-enabled chrony) = "disabled" ]; then
	systemctl enable chrony
	systemctl is-enabled chrony
fi

# Configure NTP Client software (Configure chronyd)
cat /etc/chrony/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

sed -i 's/#log tracking measurements statistics/log tracking measurements statistics/g' /etc/chrony/chrony.conf

sed -i "1i# use the local instance NTP service, if available\nserver 169.254.169.123 prefer iburst\n" /etc/chrony/chrony.conf

cat /etc/chrony/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

# Configure NTP Client software (Time adjustment)
systemctl restart chrony

sleep 3
chronyc tracking
sleep 3
chronyc sources -v
sleep 3
chronyc sourcestats -v

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
	apt install -y -q task-japanese task-japanese-desktop fonts-ipafont
	
	echo "# Setting System Language -> $Language"
	locale
	localectl status --no-pager
	localectl list-locales --no-pager | grep ja_
	localectl set-locale LANG=ja_JP.utf8
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
	localectl set-locale LANG=en_US.utf8
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
# System Reboot
#-------------------------------------------------------------------------------

# Instance Reboot
reboot
