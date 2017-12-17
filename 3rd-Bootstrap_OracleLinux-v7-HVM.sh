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

# Linux distribution Information
uname -a

cat /etc/os-release

cat /etc/oracle-release
cat /etc/redhat-release

# Default installation package
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/rpm-list.txt

# systemd service config
systemctl list-units --no-pager -all

#-------------------------------------------------------------------------------
# Yum Configuration
#-------------------------------------------------------------------------------
yum clean all
yum install -y rhn-client-tools yum-utils
yum clean all

# Delete AMI Defalut YUM Repositories File
rm -rf /etc/yum.repos.d/public-yum-ol7.repo*

# Add Oralce Linux v7 Public YUM Repositories File
yum-config-manager --add-repo http://public-yum.oracle.com/public-yum-ol7.repo

#-------------------------------------------------------------------------------
# Enable Repositories (Oracle Linux v7)
#  http://yum.oracle.com/oracle-linux-7.html
#-------------------------------------------------------------------------------

# Latest packages released for Oracle Linux 7.
#  http://yum.oracle.com/repo/OracleLinux/OL7/latest/x86_64/index.html
yum-config-manager --enable ol7_latest

# Latest Unbreakable Enterprise Kernel Release 4 packages for Oracle Linux 7.
#  http://yum.oracle.com/repo/OracleLinux/OL7/UEKR4/x86_64/index.html
yum-config-manager --enable ol7_UEKR4

# Latest packages released for Oracle Linux 7.
#  http://yum.oracle.com/repo/OracleLinux/OL7/optional/latest/x86_64/index.html
yum-config-manager --enable ol7_optional_latest

# Latest add-on packages for Oracle Linux 7.
#  http://yum.oracle.com/repo/OracleLinux/OL7/addons/x86_64/index.html
yum-config-manager --enable ol7_addons

# Latest packages for test and development for Oracle Linux 7.
#  http://yum.oracle.com/repo/OracleLinux/OL7/developer/x86_64/index.html
yum-config-manager --enable ol7_developer

# Latest EPEL packages for test and development for Oracle Linux 7.
#  http://yum.oracle.com/repo/OracleLinux/OL7/developer_EPEL/x86_64/index.html
yum-config-manager --enable ol7_developer_EPEL

# Latest Software Collection Library packages for Oracle Linux 7.
#  http://yum.oracle.com/repo/OracleLinux/OL7/SoftwareCollections/x86_64/index.html
# yum-config-manager --enable ol7_software_collections

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

# Package Install Oracle Linux System Administration Tools (from Oracle Linux Official Repository)
yum install -y arptables bash-completion bc bind-utils dstat ebtables gdisk git hdparm lsof lzop iotop mlocate mtr nc nmap nvme-cli numactl sos strace sysstat tcpdump tree traceroute unzip vim-enhanced yum-priorities yum-plugin-versionlock yum-utils wget
yum install -y setroubleshoot-server

# Package Install Oracle Linux System Administration Tools (from Oracle Linux EPEL Repository)
yum --enablerepo=ol7_developer_EPEL install -y jq cloud-utils-growpart

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
# yum localinstall -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

cat > /etc/yum.repos.d/epel-bootstrap.repo << __EOF__
[epel]
name=Bootstrap EPEL
mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-7&arch=\$basearch
failovermethod=priority
enabled=0
gpgcheck=0
__EOF__

yum --enablerepo=epel -y install epel-release
rm -f /etc/yum.repos.d/epel-bootstrap.repo

sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
# yum-config-manager --disable epel epel-debuginfo epel-source

yum clean all

# Package Install Oracle Linux System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y atop collectl fio

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
yum --enablerepo=epel install -y python2-pip
pip install --upgrade pip

pip install awscli

cat > /etc/profile.d/aws-cli.sh << __EOF__
if [ -n "\$BASH_VERSION" ]; then
   complete -C /usr/bin/aws_completer aws
fi
__EOF__

source /etc/profile.d/aws-cli.sh

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
# Custom Package Installation [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------
# yum localinstall -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

yum localinstall -y "https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm"

rpm -qi amazon-ssm-agent

systemctl daemon-reload

systemctl status -l amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl is-enabled amazon-ssm-agent

systemctl restart amazon-ssm-agent
systemctl status -l amazon-ssm-agent

ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Install [Amazon CloudWatch Agent]
# http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/install-CloudWatch-Agent-on-EC2-Instance.html
#-------------------------------------------------------------------------------

# Package Download Amazon Linux System Administration Tools (from S3 Bucket)
curl -sS "https://s3.amazonaws.com/amazoncloudwatch-agent/linux/amd64/latest/AmazonCloudWatchAgent.zip" -o "/tmp/AmazonCloudWatchAgent.zip"

unzip "/tmp/AmazonCloudWatchAgent.zip" -d "/tmp/AmazonCloudWatchAgent"

cd "/tmp/AmazonCloudWatchAgent"

bash -x /tmp/AmazonCloudWatchAgent/install.sh

cd /tmp

# Package Information 
rpm -qi amazon-cloudwatch-agent

cat /opt/aws/amazon-cloudwatch-agent/bin/CWAGENT_VERSION

cat /opt/aws/amazon-cloudwatch-agent/etc/common-config.toml

# Parameter Settings for Amazon CloudWatch Agent
curl -sS ${CWAgentConfig} -o "/tmp/config.json"

cat /tmp/config.json

# Configuration for Amazon CloudWatch Agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/tmp/config.json -s

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status

# View Amazon CloudWatch Agent config files
cat /opt/aws/amazon-cloudwatch-agent/etc/common-config.toml

cat /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

cat /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Rescue for Linux (ec2rl)]
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Linux-Server-EC2Rescue.html
# https://github.com/awslabs/aws-ec2rescue-linux
#-------------------------------------------------------------------------------

# Package Download Amazon Linux System Administration Tools (from S3 Bucket)
curl -sS "https://s3.amazonaws.com/ec2rescuelinux/ec2rl.tgz" -o "/tmp/ec2rl.tgz"

mkdir -p "/opt/aws"

tar -xzvf "/tmp/ec2rl.tgz" -C "/opt/aws"

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

# Package Install Oracle Linux System Administration Tools (from Oracle Linux EPEL Repository)
yum --enablerepo=ol7_developer_EPEL install -y ansible ansible-doc

ansible --version

ansible localhost -m setup 

#-------------------------------------------------------------------------------
# Custom Package Installation [Oracle Developer Package:PowerShell]
#-------------------------------------------------------------------------------

# Package Install Oracle Linux System Administration Tools (from Oracle Linux Development Repository)
# yum --enablerepo=ol7_developer install -y powershell

# powershell --version

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

#-------------------------------------------------------------------------------
# System Setting (Root Disk Extension)
#-------------------------------------------------------------------------------
# Disk Information(Partition) [parted -l]
parted -l

# Disk Information(Partition) [file -s]
file -s /dev/xvd*

# Disk Information(MountPoint) [lsblk]
lsblk

# Disk Information(File System) [df -h]
df -h

# Expansion of disk partition
parted -l

LANG=C growpart --dry-run /dev/xvda 1
LANG=C growpart /dev/xvda 1

parted -l

# Expansion of disk partition
df -h

resize2fs /dev/xvda1

df -h

#-------------------------------------------------------------------------------
# Reboot
#-------------------------------------------------------------------------------

# Instance Reboot
reboot
