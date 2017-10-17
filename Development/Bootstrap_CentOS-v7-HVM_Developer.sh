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
yum clean all

# Default Package Update
yum update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install CentOS System Administration Tools (from CentOS Community Repository)
yum install -y arptables bash-completion bind-utils dstat ebtables gdisk git hdparm lsof lzop iotop mtr nc nmap sos sysstat tcpdump traceroute vim-enhanced yum-priorities yum-plugin-versionlock wget
yum install -y setroubleshoot-server

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
yum install -y epel-release

sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
# yum-config-manager --disable epel epel-debuginfo epel-source

yum clean all

# Package Install RHEL System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y atop collectl fio jq

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

StsCredential=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
StsToken=$(echo $StsCredential | jq -r '.Token')

# AWS Account ID
AwsAccountId=$(curl -s "http://169.254.169.254/latest/dynamic/instance-identity/document" | jq -r '.accountId')

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI]
#-------------------------------------------------------------------------------
yum --enablerepo=epel install -y python2-pip
pip install --upgrade pip
pip install awscli

cat > /etc/profile.d/aws-cli.sh << __EOF__
if [ -n "\$BASH_VERSION" ]; then
   complete -C /usr/bin/aws_completer aws
fi
__EOF__

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
#
# - ENA (Elastic Network Adapter)
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
# - SR-IOV
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/sriov-networking.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(e3.*|f1.*|g3.*|i3.*|p2.*|r4.*|x1.*|x1e.*|m4.16xlarge)$ ]]; then
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
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(c1.*|c3.*|c4.*|d2.*|e3.*|f1.*|g2.*|g3.*|i2.*|i3.*|m1.*|m2.*|m3.*|m4.*|p2.*|r3.*|r4.*|x1.*|x1e.*)$ ]]; then
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
# Custom Package Installation [AWS CloudFormation Helper Scripts]
#-------------------------------------------------------------------------------
# yum --enablerepo=epel localinstall -y https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.amzn1.noarch.rpm
# yum --enablerepo=epel install -y python2-pip
# pip install --upgrade pip

pip install pystache
pip install argparse
pip install python-daemon
pip install requests

curl https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz -o /tmp/aws-cfn-bootstrap-latest.tar.gz
tar -pxvzf /tmp/aws-cfn-bootstrap-latest.tar.gz -C /tmp

cd /tmp/aws-cfn-bootstrap-1.4/
python setup.py build
python setup.py install

chmod 775 /usr/init/redhat/cfn-hup
ln -s /usr/init/redhat/cfn-hup /etc/init.d/cfn-hup

cd /tmp

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Service Manager (aka SSM) agent]
#-------------------------------------------------------------------------------
# yum localinstall -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

yum localinstall -y "https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm"

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
#-------------------------------------------------------------------------------

# Package Download Amazon Linux System Administration Tools (from S3 Bucket)
curl -sS "https://s3.amazonaws.com/ec2rescuelinux/ec2rl.tgz" -o "/tmp/ec2rl.tgz"

mkdir -p "/opt/aws"

tar -xzvf "/tmp/ec2rl.tgz" -C "/opt/aws"

cat > /etc/profile.d/ec2rl.sh << __EOF__
export PATH=\$PATH:/opt/aws/ec2rl
__EOF__

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

# Package Install Ansible (from EPEL Repository)
yum --enablerepo=epel install -y ansible ansible-doc

ansible --version

ansible localhost -m setup 

#-------------------------------------------------------------------------------
# Custom Package Installation [Docker Community Edition - Docker.inc Repository]
#-------------------------------------------------------------------------------

# Package Uninstall Docker Enviroment Tools (from CentOS Official Repository)
yum remove -y docker docker-common docker-selinux docker-engine

# Package Install Docker Enviroment Tools (from CentOS Official Repository)
yum install -y yum-utils device-mapper-persistent-data lvm2

# Package Install Docker Enviroment Tools (from Docker Community Edition Official Repository)
yum repolist
yum-config-manager --add-repo "https://download.docker.com/linux/centos/docker-ce.repo"
yum repolist
yum-config-manager --enable docker-ce-edge
yum repolist
yum makecache fast

yum install -y docker-ce

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
usermod -a -G docker centos

# Docker Pull Image (from Docker Hub)
docker pull amazonlinux:latest
docker pull centos:latest # CentOS v7

# Docker Run (Amazon Linux)
# docker run -it amazonlinux:latest /bin/bash
# cat /etc/system-release
# exit

#-------------------------------------------------------------------------------
# Custom Package Installation [Fluentd (td-agent)]
#-------------------------------------------------------------------------------

# Package Install Fluentd (td-agent) Tools (from Treasure Data Inc Official Repository)
curl -L https://toolbelt.treasuredata.com/sh/install-redhat-td-agent2.sh | sh

rpm -qi td-agent

/opt/td-agent/usr/sbin/td-agent --version
/opt/td-agent/usr/bin/td --version

# cat /etc/td-agent/td-agent.conf

systemctl daemon-reload

systemctl status -l td-agent
systemctl enable td-agent
systemctl is-enabled td-agent

systemctl restart td-agent
systemctl status -l td-agent

# Package Install Fluentd (td-agent) Gem Packages (from Ruby Gem Package)
/opt/td-agent/usr/sbin/td-agent-gem list

/opt/td-agent/usr/sbin/td-agent-gem search -r fluent-plugin

/opt/td-agent/usr/sbin/td-agent-gem install fluent-plugin-aws-elasticsearch-service
/opt/td-agent/usr/sbin/td-agent-gem install fluent-plugin-cloudwatch-logs
/opt/td-agent/usr/sbin/td-agent-gem install fluent-plugin-kinesis
/opt/td-agent/usr/sbin/td-agent-gem install fluent-plugin-kinesis-firehose

/opt/td-agent/usr/sbin/td-agent-gem update fluent-plugin-s3

/opt/td-agent/usr/sbin/td-agent-gem list

#-------------------------------------------------------------------------------
# Custom Package Installation [Node.js & Serverless Application Framework]
#-------------------------------------------------------------------------------

# Package Install Node.js Development Tools (from Node.js Foundation Official Repository)
curl --silent --location https://rpm.nodesource.com/setup_6.x | bash -

yum install -y nodejs

node -v
npm -v

npm install -g serverless

sls -v

#-------------------------------------------------------------------------------
# Custom Package Installation [Python 3.6 - Software Collections(SCL) Repository]
#-------------------------------------------------------------------------------
# yum repolist
# yum install -y centos-release-scl
# yum repolist

# yum install -y rh-python36 rh-python36-runtime rh-python36-scldevel rh-python36-build
# scl enable rh-python36 bash
# python --version

#-------------------------------------------------------------------------------
# Custom Package Installation [Python 3.6 - IUS Community Repository]
#-------------------------------------------------------------------------------
yum repolist
yum localinstall -y https://centos7.iuscommunity.org/ius-release.rpm
yum repolist

yum install -y python36u python36u-libs python36u-devel python36u-pip
python3.6 --version

#-------------------------------------------------------------------------------
# Custom Package Installation [Python 3.6 - Python Software Foundation]
#-------------------------------------------------------------------------------
# yum -y install openssl-devel sqlite-devel zkib-devel
# yum groupinstall -y "Development tools"

# Source Code Build Python 3.6.2 (from Python Software Foundation Official WebSite)
# mkdir ~/src
# cd ~/src
# wget https://www.python.org/ftp/python/3.6.2/Python-3.6.2.tgz
# tar zxvf Python-3.6.2.tgz
# cd Python-3.6.2
# ./configure --enable-optimizations
# make -j4
# make altinstall

# /usr/local/bin/python3.6 --version

# Create virtualenv running Python 3.6
# pip install virtualenv virtualenvwrapper
# virtualenv --version

# Add bash_profile
# cat >> ~/.bash_profile << __EOF__

# export VIRTUALENVWRAPPER_PYTHON=/usr/local/bin/python3.6
# ### Virtualenvwrapper
# if [ -f /usr/bin/virtualenvwrapper.sh ]; then
#     export WORKON_HOME=\$HOME/.virtualenvs
#     source /usr/bin/virtualenvwrapper.sh
# fi
# __EOF__

# cat ~/.bash_profile
# source ~/.bash_profile

# Setting for Python 3.6 Environment
# virtualenv  --python=/usr/local/bin/python3.6 py3.6
# source py3.6/bin/activate
# python --version

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
yum clean all

#-------------------------------------------------------------------------------
# System Setting
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
systemctl restart chronyd
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
