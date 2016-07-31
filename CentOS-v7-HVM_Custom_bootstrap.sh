#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data.log || logger -t user-data -s 2> /dev/console) 2>&1

# Instance MetaData
AZ=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
Region=$(echo $AZ | sed -e 's/.$//g')
InstanceId=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
InstanceType=$(curl -s http://169.254.169.254/latest/meta-data/instance-type)
PrivateIp=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

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
yum --enablerepo=epel install -y python-pip
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

# Get EC2 Instance Information
echo "# Get EC2 Instance Information"
aws ec2 describe-instances --instance-ids ${InstanceId} --output json --region ${Region}

# Get EC2 Instance attached EBS Volume Information
echo "# Get EC2 Instance attached EBS Volume Information"
aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=${InstanceId} --output json --region ${Region}

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
if [[ "$InstanceType" =~ ^(x1.*)$ ]]; then
	# Get EC2 Instance Attribute(Elastic Network Adapter Status)
	echo "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
	aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute enaSupport --output json --region ${Region}
elif [[ "$InstanceType" =~ ^(c3.*|c4.*|d2.*|i2.*|m4.*|r3.*)$ ]]; then
	# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
	echo "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
	aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}
	modinfo ixgbevf
	ethtool -i eth0
else
	echo "Instance type of None [Network Interface Performance Attribute]"
fi

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
if [[ "$InstanceType" =~ ^(c1.*|c3.*|c4.*|d2.*|g2.*|i2.*|m1.*|m2.*|m3.*|m4.*|r3.*)$ ]]; then
	# Get EC2 Instance Attribute(EBS-optimized instance Status)
	echo "# Get EC2 Instance Attribute(EBS-optimized instance Status)"
	aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute ebsOptimized --output json --region ${Region}
else
	echo "Instance type of None [Storage Interface Performance Attribute]"
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS CloudFormation Helper Scripts]
#-------------------------------------------------------------------------------
# yum --enablerepo=epel localinstall -y https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.amzn1.noarch.rpm
# yum --enablerepo=epel install -y python-pip
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
# yum localinstall -y https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

yum localinstall -y https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

systemctl status amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl is-enabled amazon-ssm-agent

systemctl restart amazon-ssm-agent
systemctl status amazon-ssm-agent

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS CodeDeploy Agent]
#-------------------------------------------------------------------------------
yum install -y ruby

# curl https://aws-codedeploy-ap-southeast-1.s3.amazonaws.com/latest/install -o /tmp/Install-AWS-CodeDeploy-Agent
# curl https://aws-codedeploy-${Region}.s3.amazonaws.com/latest/install -o /tmp/Install-AWS-CodeDeploy-Agent

curl https://aws-codedeploy-${Region}.s3.amazonaws.com/latest/install -o /tmp/Install-AWS-CodeDeploy-Agent

chmod 744 /tmp/Install-AWS-CodeDeploy-Agent

ruby /tmp/Install-AWS-CodeDeploy-Agent auto

cat /opt/codedeploy-agent/.version

chmod 644 /usr/lib/systemd/system/codedeploy-agent.service

systemctl status codedeploy-agent
systemctl enable codedeploy-agent
systemctl is-enabled codedeploy-agent

systemctl restart codedeploy-agent
systemctl status codedeploy-agent

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Inspector Agent]
#-------------------------------------------------------------------------------
curl https://d1wk0tztpsntt1.cloudfront.net/linux/latest/install -o /tmp/Install-Amazon-Inspector-Agent

chmod 744 /tmp/Install-Amazon-Inspector-Agent
bash /tmp/Install-Amazon-Inspector-Agent

systemctl status awsagent
systemctl enable awsagent
systemctl is-enabled awsagent

systemctl restart awsagent
systemctl status awsagent

/opt/aws/awsagent/bin/awsagent status

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS CloudWatchLogs Agent]
#-------------------------------------------------------------------------------
# yum --enablerepo=epel install -y python-pip
# pip install --upgrade pip

cd /tmp
curl -O https://s3.amazonaws.com/aws-cloudwatch/downloads/latest/awslogs-agent-setup.py

cat > /tmp/awslogs.conf << __EOF__
[general]
state_file = /var/awslogs/state/agent-state
use_gzip_http_content_encoding = true

[SYSTEM-sample-Linux-OS-var-log-messages]
log_group_name = SYSTEM-sample-Linux-OS-var-log-messages
log_stream_name = {instance_id}
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/messages
initial_position = start_of_file
encoding = utf-8
buffer_duration = 5000

[SYSTEM-sample-Linux-OS-var-log-secure]
log_group_name = SYSTEM-sample-Linux-OS-var-log-secure
log_stream_name = {instance_id}
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/secure
initial_position = start_of_file
encoding = utf-8
buffer_duration = 5000

[SYSTEM-sample-Linux-SSM-Agent-Logs]
log_group_name = SYSTEM-sample-Linux-SSM-Agent-Logs
log_stream_name = {instance_id}
datetime_format = %Y-%m-%d %H:%M:%S
time_zone = LOCAL
file = /var/log/amazon/ssm/amazon-ssm-agent.log
initial_position = start_of_file
encoding = ascii
buffer_duration = 5000

[SYSTEM-sample-Linux-CodeDeploy-Agent-Logs]
log_group_name = SYSTEM-sample-Linux-CodeDeploy-Agent-Logs
log_stream_name = {instance_id}
datetime_format = %Y-%m-%d %H:%M:%S
time_zone = LOCAL
file = /var/log/aws/codedeploy-agent/codedeploy-agent.log
initial_position = start_of_file
encoding = ascii
buffer_duration = 5000

__EOF__

python /tmp/awslogs-agent-setup.py --region ${Region} --configfile /tmp/awslogs.conf --non-interactive

systemctl status awslogs
systemctl enable awslogs
systemctl is-enabled awslogs

systemctl restart awslogs
systemctl status awslogs

#-------------------------------------------------------------------------------
# Custom Package Installation [Docker(Docker Engine)] 
#-------------------------------------------------------------------------------
# Install Current Package (v1.9.x)
# yum install -y docker docker-logrotate docker-registry docker-distribution docker-rhel-push-plugin docker-python skopeo

# Install Future Package (v1.10.x)
# yum install -y docker-latest docker-latest-logrotate docker-registry docker-distribution docker-rhel-push-plugin docker-python skopeo

# Configure Current Package (v1.9.x)
# systemctl start docker
# systemctl status docker
# systemctl enable docker
# systemctl is-enabled docker

# Configure Future Package (v1.10.x)
# systemctl start docker-latest
# systemctl status docker-latest
# systemctl enable docker-latest
# systemctl is-enabled docker-latest

# systemctl start docker-registry
# systemctl status docker-registry
# systemctl enable docker-registry
# systemctl is-enabled docker-registry

# docker version
# docker info

# docker pull centos:7
# docker images
# docker inspect centos:7

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
#-------------------------------------------------------------------------------
yum --enablerepo=epel install -y ansible

ansible --version

#-------------------------------------------------------------------------------
# Custom Package Installation [Fluetnd(td-agent)]
#-------------------------------------------------------------------------------
# curl -L http://toolbelt.treasuredata.com/sh/install-redhat-td-agent2.sh | bash
rpm --import http://packages.treasuredata.com/GPG-KEY-td-agent

cat > /etc/yum.repos.d/td.repo << __EOF__
[treasuredata]
name=TreasureData
baseurl=http://packages.treasuredata.com/2/redhat/\$releasever/\$basearch
gpgcheck=1
gpgkey=https://packages.treasuredata.com/GPG-KEY-td-agent
__EOF__

yum install -y td-agent

td-agent-gem list --local
td-agent-gem install fluent-plugin-aws-elasticsearch-service
td-agent-gem install fluent-plugin-cloudwatch-logs
td-agent-gem install fluent-plugin-kinesis
td-agent-gem install fluent-plugin-kinesis-firehose
td-agent-gem update fluent-plugin-s3
td-agent-gem list --local

systemctl start td-agent
systemctl status td-agent
systemctl enable td-agent
systemctl is-enabled td-agent

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
yum clean all

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting ulimit (System Boot Process Only)
mkdir /etc/systemd/system.conf.d

cat > /etc/systemd/system.conf.d/limits.conf << __EOF__
[Manager]
DefaultLimitNOFILE=1006500
DefaultLimitNPROC=1006500
__EOF__

# Setting ulimit (Service:rsyslog)
mkdir /etc/systemd/system/rsyslog.service.d

cat > /etc/systemd/system/rsyslog.service.d/limits.conf << __EOF__
[Service]
LimitNOFILE=1006500
LimitNPROC=1006500
__EOF__

grep "open files" /proc/`pidof rsyslogd`/limits

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
