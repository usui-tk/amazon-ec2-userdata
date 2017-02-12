#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data_3rd-bootstrap.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Set UserData Parameter
#-------------------------------------------------------------------------------

if [ -f /tmp/userdata-parameter ]; then
    source /tmp/userdata-parameter
	# echo
	echo $Language
	echo $Timezone
	echo $VpcNetwork
fi

if [[ -z "${Language}" || -z "${Timezone}" || -z "${VpcNetwork}" ]]; then
    # Default Language
	Language="ja_JP.UTF-8"
    # Default Timezone
	Timezone="Asia/Tokyo"
	# Default VPC Network
	VpcNetwork="IPv4"
	# echo
	echo $Language
	echo $Timezone
	echo $VpcNetwork
fi

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

# Package Install Amazon Linux System Administration Tools (from Amazon Official Repository)
yum install -y dstat git jq lzop iotop mtr nmap sos sysstat yum-plugin-versionlock wget

# Package Install Amazon Linux System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y bash-completion

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
	if [[ "$InstanceType" =~ ^(x1.*|p2.*|r4.*|m4.16xlarge)$ ]]; then
		# Get EC2 Instance Attribute(Elastic Network Adapter Status)
		echo "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
		aws ec2 describe-instances --instance-id ${InstanceId} --query Reservations[].Instances[].EnaSupport --output json --region ${Region}
		echo "# Get Linux Kernel Module(modinfo ena)"
		modinfo ena
		echo "# Get Linux Network Interface Driver(ethtool -i eth0)"
		ethtool -i eth0
	elif [[ "$InstanceType" =~ ^(c3.*|c4.*|d2.*|i2.*|m4.*|r3.*)$ ]]; then
		# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
		echo "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}
		echo "# Get Linux Kernel Module(modinfo ixgbevf)"
		modinfo ixgbevf
		echo "# Get Linux Network Interface Driver(ethtool -i eth0)"
		ethtool -i eth0
	else
		echo "# Get Linux Network Interface Driver(ethtool -i eth0)"
		ethtool -i eth0
	fi
else
	echo "# Get Linux Network Interface Driver(ethtool -i eth0)"
	ethtool -i eth0
fi

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(c1.*|c3.*|c4.*|d2.*|g2.*|i2.*|m1.*|m2.*|m3.*|m4.*|p2.*|r3.*|r4.*|x1.*)$ ]]; then
		# Get EC2 Instance Attribute(EBS-optimized instance Status)
		echo "# Get EC2 Instance Attribute(EBS-optimized instance Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute ebsOptimized --output json --region ${Region}
		echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
		blockdev --report
	else
		echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
		blockdev --report
	fi
else
	echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
	blockdev --report
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Systems Manager (SM) agent]
#-------------------------------------------------------------------------------
# yum localinstall -y https://amazon-ssm-ap-northeast-1.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

yum localinstall -y https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

status amazon-ssm-agent
/sbin/restart amazon-ssm-agent
status amazon-ssm-agent

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
yum clean all

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Ephemeral-Disk Auto Mount Disabled (cloud-init)
sed -i '/ephemeral0/d' /etc/cloud/cloud.cfg

# NTP Service Enabled(ntpd)
chkconfig --list ntpd
chkconfig ntpd on
chkconfig --list ntpd

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

# Time synchronization with NTP server
date
ntpdate 0.amazon.pool.ntp.org
date

# Setting System Language
if [ "${Language}" = "ja_JP.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
	cat /dev/null > /etc/sysconfig/i18n
	echo 'LANG=ja_JP.UTF-8' >> /etc/sysconfig/i18n
	cat /etc/sysconfig/i18n
elif [ "${Language}" = "en_US.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
	cat /dev/null > /etc/sysconfig/i18n
	echo 'LANG=en_US.UTF-8' >> /etc/sysconfig/i18n
	cat /etc/sysconfig/i18n
else
	echo "# Default Language"
	cat /etc/sysconfig/i18n
fi

# Setting IP Protocol Stack (IPv4 Only) or (IPv4/IPv6 Dual stack)
if [ "${VpcNetwork}" = "IPv4" ]; then
	echo "# Setting IP Protocol Stack -> $VpcNetwork"
	# Setting NTP Deamon
	sed -i 's/restrict -6/#restrict -6/g' /etc/ntp.conf
	service ntpd restart
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
elif [ "${Timezone}" = "IPv6" ]; then
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
