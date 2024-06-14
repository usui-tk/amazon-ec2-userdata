#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data.log || logger -t user-data -s 2> /dev/console) 2>&1

# Instance MetaData
region=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed -e 's/.$//g')
instanceId=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
instanceType=$(curl -s http://169.254.169.254/latest/meta-data/instance-type)
iamRole=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
privateIp=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# yum repository metadata Clean up
yum clean all

# Check AmazonLinux-Preview Repository rpm-files
yum --enablerepo=amzn-preview list | grep amzn-preview

# Default Package Update
yum update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Amazon Linux System Administration Tools (from Amazon Official Repository)
yum install -y dstat git jq lzop iotop mtr sos yum-plugin-versionlock
yum install -y aws-cli-plugin-cloudwatch-logs aws-cloudhsm-cli aws-kinesis-agent

# Package Install Amazon Linux System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y bash-completion

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI]
#-------------------------------------------------------------------------------
aws --version
aws ec2 describe-regions --region ${region}

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Simple Systems Manager (SSM) agent]
#-------------------------------------------------------------------------------
# yum localinstall -y https://amazon-ssm-ap-northeast-1.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm
# yum localinstall -y https://amazon-ssm-${region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

yum localinstall -y https://amazon-ssm-${region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

status amazon-ssm-agent
service amazon-ssm-agent start
status amazon-ssm-agent
/sbin/restart amazon-ssm-agent

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS CodeDeploy Agent]
#-------------------------------------------------------------------------------
yum install -y wget ruby
alternatives --display ruby

# curl https://aws-codedeploy-ap-southeast-1.s3.amazonaws.com/latest/install -o /tmp/Install-AWS-CodeDeploy-Agent
# curl https://aws-codedeploy-${region}.s3.amazonaws.com/latest/install -o /tmp/Install-AWS-CodeDeploy-Agent

curl https://aws-codedeploy-${region}.s3.amazonaws.com/latest/install -o /tmp/Install-AWS-CodeDeploy-Agent

chmod 744 /tmp/Install-AWS-CodeDeploy-Agent

ruby /tmp/Install-AWS-CodeDeploy-Agent auto

cat /opt/codedeploy-agent/.version

service codedeploy-agent status
chkconfig --list codedeploy-agent
chkconfig codedeploy-agent on
chkconfig --list codedeploy-agent
service codedeploy-agent start
service codedeploy-agent status

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Inspector Agent]
#-------------------------------------------------------------------------------
curl https://d1wk0tztpsntt1.cloudfront.net/linux/latest/install -o /tmp/Install-Amazon-Inspector-Agent

chmod 744 /tmp/Install-Amazon-Inspector-Agent
bash -v /tmp/Install-Amazon-Inspector-Agent

cat /opt/aws/awsagent/.version

chkconfig --list awsagent
chkconfig awsagent on
chkconfig --list awsagent

/opt/aws/awsagent/bin/awsagent status

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS CloudWatchLogs Agent] from PIP
# ### [Workaround Installation Pattern] ###
#-------------------------------------------------------------------------------
curl https://s3.amazonaws.com/aws-cloudwatch/downloads/latest/awslogs-agent-setup.py -o /tmp/awslogs-agent-setup.py

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

python /tmp/awslogs-agent-setup.py --region ${region} --configfile /tmp/awslogs.conf --non-interactive

service awslogs status
chkconfig --list awslogs
chkconfig awslogs on
chkconfig --list awslogs
service awslogs restart
service awslogs status


#-------------------------------------------------------------------------------
# Custom Package Installation [AWS CloudWatchLogs Agent] from RPM
# ### [General Installation Pattern] ###
#-------------------------------------------------------------------------------

# yum install -y awslogs aws-cli-plugin-cloudwatch-logs

# sed -i "s/region = us-east-1/region = ${region}/g" /etc/awslogs/awscli.conf

# cat > /etc/awslogs/awslogs.conf << __EOF__
# [general]
# state_file = /var/awslogs/state/agent-state
# use_gzip_http_content_encoding = true
# 
# [SYSTEM-sample-Linux-OS-var-log-messages]
# log_group_name = SYSTEM-sample-Linux-OS-var-log-messages
# log_stream_name = {instance_id}
# datetime_format = %b %d %H:%M:%S
# time_zone = LOCAL
# file = /var/log/messages
# initial_position = start_of_file
# encoding = utf-8
# buffer_duration = 5000
# 
# [SYSTEM-sample-Linux-OS-var-log-secure]
# log_group_name = SYSTEM-sample-Linux-OS-var-log-secure
# log_stream_name = {instance_id}
# datetime_format = %b %d %H:%M:%S
# time_zone = LOCAL
# file = /var/log/secure
# initial_position = start_of_file
# encoding = utf-8
# buffer_duration = 5000
# 
# [SYSTEM-sample-Linux-SSM-Agent-Logs]
# log_group_name = SYSTEM-sample-Linux-SSM-Agent-Logs
# log_stream_name = {instance_id}
# datetime_format = %Y-%m-%d %H:%M:%S
# time_zone = LOCAL
# file = /var/log/amazon/ssm/amazon-ssm-agent.log
# initial_position = start_of_file
# encoding = ascii
# buffer_duration = 5000
# 
# [SYSTEM-sample-Linux-CodeDeploy-Agent-Logs]
# log_group_name = SYSTEM-sample-Linux-CodeDeploy-Agent-Logs
# log_stream_name = {instance_id}
# datetime_format = %Y-%m-%d %H:%M:%S
# time_zone = LOCAL
# file = /var/log/aws/codedeploy-agent/codedeploy-agent.log
# initial_position = start_of_file
# encoding = ascii
# buffer_duration = 5000
# 
# __EOF__

# service awslogs start
# service awslogs status
# chkconfig --list awslogs
# chkconfig awslogs on
# chkconfig --list awslogs


#-------------------------------------------------------------------------------
# Custom Package Installation [Embulk]
#-------------------------------------------------------------------------------
yum install -y java-1.8.0-openjdk-devel

alternatives --display java
java -version
javac -version

curl --create-dirs -o ~/.embulk/bin/embulk -L "http://dl.embulk.org/embulk-latest.jar"
chmod +x ~/.embulk/bin/embulk
echo 'export PATH="$HOME/.embulk/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

embulk --version

embulk gem list
embulk gem install embulk-input-command
embulk gem install embulk-input-s3
embulk gem install embulk-parser-jsonl
embulk gem install embulk-parser-json
embulk gem install embulk-output-elasticsearch
embulk gem install embulk-output-redshift
embulk gem list

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
td-agent-gem install fluent-plugin-cloudwatch-logs
td-agent-gem install fluent-plugin-kinesis
td-agent-gem install fluent-plugin-elasticsearch
td-agent-gem update fluent-plugin-s3
td-agent-gem list --local

service td-agent start
service td-agent status
chkconfig --list td-agent
chkconfig td-agent on
chkconfig --list td-agent

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

