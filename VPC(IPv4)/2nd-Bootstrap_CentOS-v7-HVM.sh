#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data.log || logger -t user-data -s 2> /dev/console) 2>&1

# Instance MetaData
AZ=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
Region=$(echo $AZ | sed -e 's/.$//g')
InstanceId=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
InstanceType=$(curl -s http://169.254.169.254/latest/meta-data/instance-type)
PrivateIp=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
AmiId=$(curl -s http://169.254.169.254/latest/meta-data/ami-id)

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
yum install -y bash-completion bind-utils dstat gdisk git lsof lzop iotop mtr nmap sos traceroute vim-enhanced yum-priorities yum-plugin-versionlock wget
yum install -y setroubleshoot-server

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
yum install -y epel-release
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
yum clean all

# Package Install RHEL System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y jq

#-------------------------------------------------------------------------------
# Getting IAM Role & STS Information
#-------------------------------------------------------------------------------
RoleArn=$(curl -s http://169.254.169.254/latest/meta-data/iam/info | jq -r '.InstanceProfileArn')
RoleName=$(echo $RoleArn | cut -d '/' -f 2)

StsCredential=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
StsToken=$(echo $StsCredential | jq -r '.Token')

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
# Custom Package Installation [Amazon EC2 Simple Systems Manager (SSM) agent]
#-------------------------------------------------------------------------------
# yum localinstall -y https://amazon-ssm-ap-northeast-1.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

yum localinstall -y https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

systemctl status amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl is-enabled amazon-ssm-agent

systemctl restart amazon-ssm-agent
systemctl status amazon-ssm-agent

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
yum clean all

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting TimeZone
timedatectl set-timezone Asia/Tokyo
# timedatectl status

# Setting Language
localectl set-locale LANG=ja_JP.utf8
# localectl status

# Setting NTP Deamon
sed -i 's/bindcmdaddress ::1/#bindcmdaddress ::1/g' /etc/chrony.conf
systemctl restart chronyd
systemctl enable chronyd
systemctl is-enabled chronyd
sleep 3
chronyc tracking
chronyc sources -v
chronyc sourcestats -v

# Disable IPv6 Kernel Module
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf

# Disable IPv6 Kernel Parameter
sysctl -a

cat > /etc/sysctl.d/99-ipv6-disable.conf << __EOF__
# Custom sysctl Parameter for ipv6 disable
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
__EOF__

sysctl --system
sysctl -p
sysctl -a | grep -ie "local_port" -ie "ipv6" | sort

# Instance Reboot
reboot
