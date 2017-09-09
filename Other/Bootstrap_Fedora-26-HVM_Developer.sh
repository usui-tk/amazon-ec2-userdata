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
# Default Package Update
#-------------------------------------------------------------------------------

# yum repository metadata Clean up
dnf clean all

# Default Package Update
dnf update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Fedora System Administration Tools (from Fedora Official Repository)
dnf install -y dnf-plugins-core dnf-plugin-system-upgrade dnf-utils
dnf clean all
dnf makecache

dnf install -y bash-completion bind-utils curl dstat ethtool fio gdisk git hdparm jq lsof lzop iotop mtr nc nmap rpmconf sos tcpdump traceroute vim-enhanced wget
dnf install -y setroubleshoot-server

# Package Install Fedora RPM Development Tools (from Fedora Official Repository)
dnf install -y rpmdevtools
# dnf group install -y "RPM Development Tools"

#-------------------------------------------------------------------------------
# Set AWS Instance MetaData
#-------------------------------------------------------------------------------

# Instance MetaData
AZ=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
Region=$(echo $AZ | sed -e 's/.$//g')
InstanceId=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
InstanceType=$(curl -s http://169.254.169.254/latest/meta-data/instance-type)
PrivateIp=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
AmiId=$(curl -s http://169.254.169.254/latest/meta-data/ami-id)

# IAM Role & STS Information
RoleArn=$(curl -s http://169.254.169.254/latest/meta-data/iam/info | jq -r '.InstanceProfileArn')
RoleName=$(echo $RoleArn | cut -d '/' -f 2)

StsCredential=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
StsToken=$(echo $StsCredential | jq -r '.Token')

# AWS Account ID
AwsAccountId=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r '.accountId')

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

sleep 3

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
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(g3.*|i3.*|m4.16xlarge|p2.*|r4.*|x1.*)$ ]]; then
		# Get EC2 Instance Attribute(Elastic Network Adapter Status)
		echo "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
		aws ec2 describe-instances --instance-id ${InstanceId} --query Reservations[].Instances[].EnaSupport --output json --region ${Region}
		echo "# Get Linux Kernel Module(modinfo ena)"
		modinfo ena
	elif [[ "$InstanceType" =~ ^(c3.*|c4.*|d2.*|i2.*|m4.*|r3.*)$ ]]; then
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
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(c1.*|c3.*|c4.*|d2.*|g2.*|g3.*|i2.*|i3.*|m1.*|m2.*|m3.*|m4.*|p2.*|r3.*|r4.*|x1.*)$ ]]; then
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

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-SHELL]
#-------------------------------------------------------------------------------
# dnf install -y aws-shell

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Service Manager (aka SSM) agent]
#-------------------------------------------------------------------------------
# dnf localinstall -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm

dnf localinstall -y https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

systemctl daemon-reload

systemctl status -l amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl is-enabled amazon-ssm-agent

systemctl restart amazon-ssm-agent
systemctl status -l amazon-ssm-agent

ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
#-------------------------------------------------------------------------------

# Package Install Fedora System Administration Tools (from Fedora Official Repository)
dnf install -y ansible ansible-doc

ansible --version

ansible localhost -m setup 

#-------------------------------------------------------------------------------
# Custom Package Installation [Docker - Fedora Repository]
#-------------------------------------------------------------------------------

# Package Install Docker Enviroment Tools (from Fedora Official Repository)
# dnf install -y docker fedora-dockerfiles

# systemctl daemon-reload

# systemctl status -l docker
# systemctl enable docker
# systemctl is-enabled docker

# systemctl restart docker
# systemctl status -l docker

# Docker Deamon Information
# docker --version
# docker info

#-------------------------------------------------------------------------------
# Custom Package Installation [Docker Community Edition - Docker.inc Repository]
#-------------------------------------------------------------------------------

# Package Uninstall Docker Enviroment Tools (from Fedora Official Repository)
dnf remove -y docker docker-common docker-selinux docker-engine-selinux docker-engine

# Package Install Docker Enviroment Tools (from Docker Community Edition Official Repository)
dnf repolist
dnf config-manager --add-repo "https://download.docker.com/linux/fedora/docker-ce.repo"
dnf repolist
dnf config-manager --set-enabled docker-ce-edge
dnf repolist
dnf makecache

dnf install -y docker-ce

systemctl daemon-reload

systemctl status -l docker
systemctl enable docker
systemctl is-enabled docker

systemctl restart docker
systemctl status -l docker

# Docker Deamon Information
docker --version

docker info

# Docker Configuration
usermod -a -G docker fedora

# Docker Pull Image (from Docker Hub)
docker pull fedora:latest
docker pull amazonlinux:latest
docker pull centos:latest # CentOS v7

# Docker Run (Amazon Linux)
# docker run -it amazonlinux:latest /bin/bash
# cat /etc/system-release
# exit

#-------------------------------------------------------------------------------
# Custom Package Installation [Fluentd (td-agent)]
#-------------------------------------------------------------------------------

# Package Install Fedora C-Language Development Tools (from Fedora Official Repository)
# dnf install -y gcc
dnf group install -y "C Development Tools and Libraries"

# Package Install Fedora Ruby Development Tools (from Fedora Official Repository)
dnf install -y ruby ruby-devel libxml2-devel libxslt-devel sqlite-devel

ruby --version

# Package Install Fluentd (td-agent) Tools (from Ruby Gem Package)
gem install fluentd -v "~> 0.12.0"

mkdir -p /etc/fluentd

/usr/local/bin/fluentd --setup /etc/fluentd

cat /etc/fluentd/fluent.conf

/usr/local/bin/fluentd --config /etc/fluentd/fluent.conf -vv & # -vv enables trace level logs. You can omit -vv option.

echo '{"json":"message"}' | /usr/local/bin/fluent-cat debug.test

# Package Install Fluentd (td-agent) Gem Packages (from Ruby Gem Package)
/usr/local/bin/fluent-gem list

/usr/local/bin/fluent-gem search -r fluent-plugin

/usr/local/bin/fluent-gem install fluent-plugin-aws-elasticsearch-service
/usr/local/bin/fluent-gem install fluent-plugin-cloudwatch-logs
/usr/local/bin/fluent-gem install fluent-plugin-kinesis
/usr/local/bin/fluent-gem install fluent-plugin-kinesis-firehose
/usr/local/bin/fluent-gem install fluent-plugin-s3

/usr/local/bin/fluent-gem list


#-------------------------------------------------------------------------------
# Custom Package Installation [Node.js & Serverless Application Framework]
#-------------------------------------------------------------------------------
dnf install -y nodejs npm
node -v
npm -v

npm install -g serverless

sls -v

#-------------------------------------------------------------------------------
# Custom Package Installation [Python 3.6]
#-------------------------------------------------------------------------------
dnf install -y python36

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
dnf clean all

#-------------------------------------------------------------------------------
# RPM Package Configuration Check
#-------------------------------------------------------------------------------
rpmconf --all

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# CPU Information [cat /proc/cpuinfo]
cat /proc/cpuinfo

# CPU Information [lscpu]
lscpu

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
    # Network Information(Firewall Service) [firewall-cmd --list-all]
    firewall-cmd --list-all
fi

# Linux Security Information(SELinux) [getenforce] [sestatus]
getenforce

sestatus

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# NTP Service Enabled(chronyd)
systemctl status -l chronyd
systemctl restart chronyd
systemctl status -l chronyd

systemctl enable chronyd
systemctl is-enabled chronyd
sleep 3
chronyc tracking
chronyc sources -v
chronyc sourcestats -v

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

# Time synchronization with NTP server
date
chronyc tracking
chronyc sources -v
chronyc sourcestats -v
date

# Setting System Language
if [ "${Language}" = "ja_JP.UTF-8" ]; then
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

# Instance Reboot
reboot
