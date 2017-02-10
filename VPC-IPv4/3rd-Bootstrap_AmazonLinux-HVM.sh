#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data_3rd-bootstrap.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Set UserData Parameter
#-------------------------------------------------------------------------------

if [ -f /tmp/userdata-parameter ]; then
    source /tmp/userdata-parameter
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

# Get EC2 Region Information
aws ec2 describe-regions --region ${Region}

# Get AMI Information
echo "# Get AMI Information"
aws ec2 describe-images --image-ids ${AmiId} --output json --region ${Region}

# Get EC2 Instance Information
echo "# Get EC2 Instance Information"
aws ec2 describe-instances --instance-ids ${InstanceId} --output json --region ${Region}

# Get EC2 Instance attached EBS Volume Information
echo "# Get EC2 Instance attached EBS Volume Information"
aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=${InstanceId} --output json --region ${Region}

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
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

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
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

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Systems Manager (SM) agent]
#-------------------------------------------------------------------------------
# yum localinstall -y https://amazon-ssm-ap-northeast-1.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

yum localinstall -y https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

status amazon-ssm-agent
service amazon-ssm-agent start
status amazon-ssm-agent
/sbin/restart amazon-ssm-agent

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
yum clean all

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting SystemClock
cat > /etc/sysconfig/clock << __EOF__
ZONE="Asia/Tokyo"
UTC=false
__EOF__

# Setting TimeZone
date
/bin/cp -fp /usr/share/zoneinfo/Asia/Tokyo /etc/localtime
date
ntpdate 0.amazon.pool.ntp.org
date

# Setting NTP Deamon
sed -i 's/restrict -6/#restrict -6/g' /etc/ntp.conf
service ntpd restart
chkconfig ntpd on

# Setting Language
cat > /etc/sysconfig/i18n << __EOF__
LANG=ja_JP.UTF-8
__EOF__

# Ephemeral-Disk Auto Mount Disabled (cloud-init)
sed -i '/ephemeral0/d' /etc/cloud/cloud.cfg

# Firewall Service Disabled (iptables/ip6tables)
service iptables stop
chkconfig --list iptables
chkconfig iptables off
chkconfig --list iptables

service ip6tables stop
chkconfig --list ip6tables
chkconfig ip6tables off
chkconfig --list ip6tables

# Disable IPv6 Kernel Module
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf

# Disable IPv6 Kernel Parameter
sysctl -a

cat > /etc/sysctl.d/99-ipv6-disable.conf << __EOF__
# Custom sysctl Parameter for ipv6 disable
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
__EOF__

sysctl -p
sysctl -a | grep -ie "local_port" -ie "ipv6" | sort

# Instance Reboot
reboot
