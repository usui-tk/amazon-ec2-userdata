#!/bin/bash -v

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
	Language="ja_JP.UTF-8"
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
#  - Fedora 27
#    https://docs.fedoraproject.org/
#    https://docs.fedoraproject.org/f27/system-administrators-guide/index.html
#
#    https://alt.fedoraproject.org/cloud/
#    https://fedoracloud.readthedocs.io/en/latest/whatis.html
#
#-------------------------------------------------------------------------------

# Show Linux Distribution/Distro information
lsb_release -a

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

# systemd service config
systemctl list-units --no-pager -all

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# yum repository metadata Clean up
dnf clean all

# Package Update Bash/DNF Administration Tools (from Fedora Official Repository)
dnf install -y bash dnf dnf-conf dnf-utils
dnf clean all
dnf makecache

# Package Install DNF Administration Tools (from Fedora Official Repository)
dnf install -y dnf-plugins-core dnf-plugin-system-upgrade
dnf clean all
dnf makecache

# --- Workaround ---
# dnf install -y glibc-langpack* langpacks-*

# Default Package Update
dnf update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Fedora System Administration Tools (from Fedora Official Repository)
dnf install -y arptables atop bash-completion bc bind-utils collectl curl dstat ebtables ethtool fio gdisk git hdparm jq lsof lzop iotop mlocate mtr nc nmap nvme-cli numactl rpmconf sos strace sysstat tcpdump tree traceroute unzip vim-enhanced wget zip
dnf install -y setroubleshoot-server

# Package Install Fedora RPM Development Tools (from Fedora Official Repository)
dnf install -y rpmdevtools
# dnf group install -y "RPM Development Tools"

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
RoleArn=$(curl -s "http://169.254.169.254/latest/meta-data/iam/info" | jq -r '.InstanceProfileArn')
RoleName=$(echo $RoleArn | cut -d '/' -f 2)

if [ -n "$RoleName" ]; then
	StsCredential=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
	StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
	StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
	StsToken=$(echo $StsCredential | jq -r '.Token')
fi

# AWS Account ID
AwsAccountId=$(curl -s "http://169.254.169.254/latest/dynamic/instance-identity/document" | jq -r '.accountId')

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI]
#-------------------------------------------------------------------------------
dnf install -y awscli

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

# Get AMI Information
if [ -n "$RoleName" ]; then
	echo "# Get AMI Information"
	aws ec2 describe-images --image-ids ${AmiId} --output json --region ${Region}
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

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
#
# - ENA (Elastic Network Adapter)
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
# - SR-IOV
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/sriov-networking.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(c5.*|e3.*|f1.*|g3.*|h1.*|i3.*|m5.*|p2.*|p3.*|r4.*|x1.*|x1e.*|m4.16xlarge)$ ]]; then
		# Get EC2 Instance Attribute(Elastic Network Adapter Status)
		echo "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
		aws ec2 describe-instances --instance-id ${InstanceId} --query Reservations[].Instances[].EnaSupport --output json --region ${Region}
		echo "# Get Linux Kernel Module(modinfo ena)"
		modinfo ena
	elif [[ "$InstanceType" =~ ^(c3.*|c4.*|d2.*|i2.*|r3.*|m4.*)$ ]]; then
		# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
		echo "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}
		echo "# Get Linux Kernel Module(modinfo ixgbevf)"
		modinfo ixgbevf
	else
		echo "# Not Target Instance Type :" $InstanceType
	fi
fi

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
#
# - EBS Optimized Instance
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/EBSOptimized.html
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/EBSPerformance.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(c1.*|c3.*|c4.*|c5.*|d2.*|e3.*|f1.*|g2.*|g3.*|h1.*|i2.*|i3.*|m1.*|m2.*|m3.*|m4.*|m5.*|p2.*|p3.*|r3.*|r4.*|x1.*|x1e.*)$ ]]; then
		# Get EC2 Instance Attribute(EBS-optimized instance Status)
		echo "# Get EC2 Instance Attribute(EBS-optimized instance Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute ebsOptimized --output json --region ${Region}
		echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
		blockdev --report
	else
		echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
		blockdev --report
	fi
fi

# Get EC2 Instance attached NVMe Device Information
#
# - Amazon EBS and NVMe Volumes [c5, m5]
#   http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nvme-ebs-volumes.html
# - SSD Instance Store Volumes [f1, i3]
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/ssd-instance-store.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(c5.*|m5.*|f1.*|i3.*)$ ]]; then
		# Get NVMe Device(nvme list)
		# http://www.spdk.io/doc/nvme-cli.html
		# https://github.com/linux-nvme/nvme-cli
		echo "# Get NVMe Device(nvme list)"
		nvme list

		# Get PCI-Express Device(lspci -v)
		echo "# Get PCI-Express Device(lspci -v)"
		lspci -v

		# Get Disk Information[MountPoint] (lsblk)
		echo "# Get Disk Information[MountPoint] (lsblk)"
		lsblk
	else
		echo "# Not Target Instance Type :" $InstanceType
	fi
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-SHELL]
#-------------------------------------------------------------------------------
# dnf install -y aws-shell

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------
# dnf localinstall -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

dnf localinstall -y "https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm"

rpm -qi amazon-ssm-agent

systemctl daemon-reload

systemctl status -l amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl is-enabled amazon-ssm-agent

systemctl restart amazon-ssm-agent
systemctl status -l amazon-ssm-agent

ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Rescue for Linux (ec2rl)]
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Linux-Server-EC2Rescue.html
# https://github.com/awslabs/aws-ec2rescue-linux
#-------------------------------------------------------------------------------

# Package Download Amazon Linux System Administration Tools (from S3 Bucket)
curl -sS "https://s3.amazonaws.com/ec2rescuelinux/ec2rl.tgz" -o "/tmp/ec2rl.tgz"

mkdir -p "/opt/aws"

tar -xzvf "/tmp/ec2rl.tgz" -C "/opt/aws"

mv --force /opt/aws/ec2rl-* "/opt/aws/ec2rl"

cat > /etc/profile.d/ec2rl.sh << __EOF__
export PATH=\$PATH:/opt/aws/ec2rl
__EOF__

source /etc/profile.d/ec2rl.sh

# Check Version
/opt/aws/ec2rl/ec2rl version

/opt/aws/ec2rl/ec2rl version-check

# Required Software Package
/opt/aws/ec2rl/ec2rl software-check

# Diagnosis [dig modules]
# /opt/aws/ec2rl/ec2rl run --only-modules=dig --domain=amazon.com

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
#-------------------------------------------------------------------------------

# Package Install Fedora System Administration Tools (from Fedora Official Repository)
dnf install -y ansible ansible-doc ansible-lint

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

# Register the Microsoft signature key
rpm --import https://packages.microsoft.com/keys/microsoft.asc

# Register the Microsoft RedHat repository
curl https://packages.microsoft.com/config/rhel/7/prod.repo | tee /etc/yum.repos.d/microsoft.repo

# Update the list of products
dnf clean all
dnf makecache

dnf update -y

# Install a system component
dnf install -y compat-openssl10

# Install PowerShell
dnf install -y powershell

rpm -qi powershell

# Check Version
pwsh -Version

# Import-Module [AWSPowerShell.NetCore]
pwsh -Command "Get-Module -ListAvailable"

pwsh -Command "Install-Module -Name AWSPowerShell.NetCore -AllowClobber -Force"

pwsh -Command "Get-Module -ListAvailable"

pwsh -Command "Get-AWSPowerShellVersion"
# pwsh -Command "Get-AWSPowerShellVersion -ListServiceVersionInfo"

#-------------------------------------------------------------------------------
# Custom Package Installation [Docker - Fedora Repository]
#-------------------------------------------------------------------------------

# Package Install Docker Enviroment Tools (from Fedora Official Repository)
dnf install -y docker fedora-dockerfiles

systemctl daemon-reload

systemctl status -l docker
systemctl enable docker
systemctl is-enabled docker

systemctl restart docker
systemctl status -l docker

# Docker Deamon Information
docker --version
docker info

# Docker Pull Image (from Docker Hub)
docker pull fedora:latest
docker pull amazonlinux:latest                   # Amazon Linux
docker pull amazonlinux:2017.12.0.20171212.2     # Amazon Linux 2 LTS [2017.12.0]
docker pull centos:latest                        # CentOS v7

# Docker Run (Amazon Linux)
# docker run -it amazonlinux:latest /bin/bash
# cat /etc/system-release
# cat /etc/image-id 
# exit

# Docker Run (Amazon Linux 2 LTS)
# docker run -it amazonlinux:2017.12.0.20171212.2 bash
# cat /etc/system-release
# cat /etc/image-id 
# exit


#-------------------------------------------------------------------------------
# Custom Package Installation [Docker Community Edition - Docker.inc Repository]
#-------------------------------------------------------------------------------

# Package Uninstall Docker Enviroment Tools (from Fedora Official Repository)
# dnf remove -y docker docker-common docker-selinux docker-engine-selinux docker-engine

# Package Install Docker Enviroment Tools (from Docker Community Edition Official Repository)
# dnf repolist

# dnf config-manager --add-repo "https://download.docker.com/linux/fedora/docker-ce.repo"
# dnf config-manager --set-enabled docker-ce-edge

# dnf makecache

# sleep 5

# dnf repolist
# dnf makecache

# dnf install -y docker-ce

# systemctl daemon-reload

# systemctl status -l docker
# systemctl enable docker
# systemctl is-enabled docker

# systemctl restart docker
# systemctl status -l docker

# Docker Deamon Information
# docker --version

# docker info

# Docker Configuration
# usermod -a -G docker fedora

# Docker Pull Image (from Docker Hub)
# docker pull fedora:latest
# docker pull amazonlinux:latest                   # Amazon Linux
# docker pull amazonlinux:2017.12.0.20171212.2     # Amazon Linux 2 LTS [2017.12.0]
# docker pull centos:latest                        # CentOS v7

# Docker Run (Amazon Linux)
# docker run -it amazonlinux:latest /bin/bash
# cat /etc/system-release
# exit

#-------------------------------------------------------------------------------
# Custom Package Installation [Fluentd (td-agent)]
#-------------------------------------------------------------------------------

# curl -L https://toolbelt.treasuredata.com/sh/install-redhat-td-agent3.sh| bash
rpm --import https://packages.treasuredata.com/GPG-KEY-td-agent

cat > /etc/yum.repos.d/td.repo << __EOF__
[treasuredata]
name=TreasureData
baseurl=http://packages.treasuredata.com/3/redhat/7/x86_64/
gpgcheck=1
gpgkey=https://packages.treasuredata.com/GPG-KEY-td-agent
__EOF__

dnf clean all
dnf makecache

# Install Treasure Agent
dnf install -y td-agent

# Package Information
rpm -qi td-agent

systemctl daemon-reload

systemctl status -l td-agent
systemctl enable td-agent
systemctl is-enabled td-agent

systemctl restart td-agent
systemctl status -l td-agent

# Package Install Fluentd (td-agent) Gem Packages (from Ruby Gem Package)
/opt/td-agent/embedded/bin/fluent-gem list --local

/opt/td-agent/embedded/bin/fluent-gem search -r fluent-plugin

/opt/td-agent/embedded/bin/fluent-gem install fluent-plugin-aws-elasticsearch-service
/opt/td-agent/embedded/bin/fluent-gem install fluent-plugin-cloudwatch-logs
/opt/td-agent/embedded/bin/fluent-gem install fluent-plugin-kinesis
/opt/td-agent/embedded/bin/fluent-gem install fluent-plugin-kinesis-firehose
/opt/td-agent/embedded/bin/fluent-gem install fluent-plugin-s3

/opt/td-agent/embedded/bin/fluent-gem list --local

#-------------------------------------------------------------------------------
# Custom Package Installation [Node.js & Serverless Framework]
#-------------------------------------------------------------------------------
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
# Custom Package Installation [Python 3.6]
#-------------------------------------------------------------------------------
dnf install -y python3

/usr/bin/python3 -V

#-------------------------------------------------------------------------------
# Custom Package Installation [Go 1.9]
#-------------------------------------------------------------------------------
dnf install -y golang golang-github-aws-aws-sdk-go-devel

/usr/bin/go version

#-------------------------------------------------------------------------------
# Custom Package Installation for Desktop Environment
#-------------------------------------------------------------------------------
dnf group install -y "Fedora Workstation"

#-------------------------------------------------------------------------------
# Custom Package Installation for VNC Server
#
#  - VNC Server User : fedora [cloud-init default user]
#
#-------------------------------------------------------------------------------
dnf install -y tigervnc-server

# Configure VNC Server for "fedora" user
cat > /home/fedora/vnc-setup.sh << __EOF__
#!/bin/bash

VNC_PASSWORD=\$(cat /dev/urandom | base64 | fold -w 8 | head -n 1)

vncpasswd << 'EOF';
\$VNC_PASSWORD
\$VNC_PASSWORD
n
EOF

echo "# VNC Password is \$VNC_PASSWORD" > ~/.vnc/cloud-init_configure_passwd
__EOF__

chmod 777 /home/fedora/vnc-setup.sh

su - "fedora" -c "/home/fedora/vnc-setup.sh"

# Pre-operation test of VNC server
su - "fedora" -c "vncserver :1 -geometry 1024x768 -depth 32"

sleep 10

su - "fedora" -c "vncserver -kill :1"

cat /home/fedora/.vnc/xstartup
cat /home/fedora/.vnc/config

# Systemd's VNC Server configuration 
cp -pr /usr/lib/systemd/system/vncserver@.service /etc/systemd/system/vncserver@:1.service

cat /etc/systemd/system/vncserver@:1.service

sed -i 's@<USER>@fedora@g' /etc/systemd/system/vncserver@:1.service

cat /etc/systemd/system/vncserver@:1.service

systemctl daemon-reload

# Systemd's VNC Server startup
systemctl status vncserver@:1.service
systemctl start vncserver@:1.service
systemctl status vncserver@:1.service

systemctl enable vncserver@:1.service
systemctl is-enabled vncserver@:1.service

#-------------------------------------------------------------------------------
# Custom Package Installation for Desktop Application [Google Chrome]
#  - https://www.google.com/linuxrepositories/
#-------------------------------------------------------------------------------

cat > /etc/yum.repos.d/google-chrome.repo << __EOF__
[google-chrome]
name=google-chrome - \$basearch
baseurl=http://dl.google.com/linux/chrome/rpm/stable/\$basearch
enabled=1
gpgcheck=1
gpgkey=https://dl-ssl.google.com/linux/linux_signing_key.pub
__EOF__

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
# RPM Package Configuration Check
#-------------------------------------------------------------------------------
rpmconf --all

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

# Network Information(Firewall Service) [firewalld]
if [ $(command -v firewall-cmd) ]; then
    # Network Information(Firewall Service) [systemctl status -l firewalld]
    systemctl status -l firewalld

	systemctl disable firewalld
	systemctl is-enabled firewalld

	systemctl status -l firewalld
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
systemctl daemon-reload

# Configure NTP Client software (Configure chronyd)
cat /etc/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

sed -i 's/#log measurements statistics tracking/log measurements statistics tracking/g' /etc/chrony.conf

sed -i "1i# use the local instance NTP service, if available\nserver 169.254.169.123 prefer iburst\n" /etc/chrony.conf

cat /etc/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

# Configure NTP Client software (Start Daemon chronyd)
systemctl status chronyd
systemctl restart chronyd
systemctl status chronyd

systemctl enable chronyd
systemctl is-enabled chronyd

# Configure NTP Client software (Time adjustment)
sleep 3

chronyc tracking
chronyc sources -v
chronyc sourcestats -v

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
	dnf install -y langpacks-ja
	dnf install -y ibus-kkc sazanami-gothic-fonts sazanami-mincho-fonts ipa-gothic-fonts ipa-mincho-fonts vlgothic-fonts vlgothic-p-fonts
	echo "# Setting System Language -> $Language"
	locale
	# localectl status
	localectl set-locale LANG=ja_JP.utf8
	locale
	# localectl status
	cat /etc/locale.conf
elif [ "${Language}" = "en_US.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
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
	# Setting NTP Deamon
	sed -i 's/bindcmdaddress ::1/#bindcmdaddress ::1/g' /etc/chrony.conf
	systemctl restart chronyd
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
	lsmod | grep ipv6
	echo "# Show Network Listen Address and report"
	netstat -an -A inet6
	echo "# Show Network Routing Table"
	netstat -r -A inet6
else
	echo "# Default IP Protocol Stack"
	echo "# Show IPv6 Network Interface Address"
	ifconfig
	echo "# Show IPv6 Kernel Module"
	lsmod | grep ipv6
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
