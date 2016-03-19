#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data.log || logger -t user-data -s 2> /dev/console) 2>&1

# Instance MetaData
region=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed -e 's/.$//g')
instanceId=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
instanceType=$(curl -s http://169.254.169.254/latest/meta-data/instance-type)
privateIp=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

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
yum install -y dstat git jq lzop iotop mtr sos yum-plugin-versionlock
yum install -y aws-cli-plugin-cloudwatch-logs aws-kinesis-agent

# Package Install RHEL System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y bash-completion

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI]
#-------------------------------------------------------------------------------
aws --version
aws ec2 describe-regions --region ${region}

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-SHELL]
#-------------------------------------------------------------------------------
# pip install --upgrade pip
# pip install --upgrade awscli
pip install aws-shell

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Simple Systems Manager (SSM) agent]
#-------------------------------------------------------------------------------
# yum localinstall -y https://amazon-ssm-ap-northeast-1.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm
# yum localinstall -y https://amazon-ssm-${region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

yum localinstall -y https://amazon-ssm-${region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

status amazon-ssm-agent

service amazon-ssm-agent start
status amazon-ssm-agent

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Inspector Agent]
#-------------------------------------------------------------------------------
cd /tmp
curl -O https://s3-us-west-2.amazonaws.com/inspector.agent.us-west-2/latest/install

chmod 744 /tmp/install
# bash -v install

# cat /opt/aws/inspector/etcagent.cfg

# /opt/aws/inspector/bin/inspector status

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS CloudWatchLogs Agent] from PIP
# ### [Workaround Installation Pattern] ###
#-------------------------------------------------------------------------------

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

__EOF__

python ./awslogs-agent-setup.py --region ${region} --configfile /tmp/awslogs.conf --non-interactive

service awslogs status
chkconfig --list awslogs
chkconfig awslogs on
chkconfig --list awslogs
service awslogs start
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
# __EOF__

# service awslogs start
# service awslogs status
# chkconfig --list awslogs
# chkconfig awslogs on
# chkconfig --list awslogs


#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
#-------------------------------------------------------------------------------
# yum --enablerepo=epel install -y ansible

#-------------------------------------------------------------------------------
# Custom Package Installation [Chef-Client(Chef-Solo)]
#-------------------------------------------------------------------------------
curl -L https://www.chef.io/chef/install.sh | bash -v
mkdir -p /etc/chef/ohai/hints
echo {} > /etc/chef/ohai/hints/ec2.json
OHAI_PLUGINS="$(ohai | jq -r '.chef_packages.ohai.ohai_root + "/plugins"')"
OHAI_PLUGINS_RACKERLABS="${OHAI_PLUGINS}/rackerlabs"
mkdir -p ${OHAI_PLUGINS_RACKERLABS}
curl -o ${OHAI_PLUGINS_RACKERLABS}/packages.rb https://raw.githubusercontent.com/rackerlabs/ohai-plugins/master/plugins/packages.rb
curl -o ${OHAI_PLUGINS_RACKERLABS}/sshd.rb https://raw.githubusercontent.com/rackerlabs/ohai-plugins/master/plugins/sshd.rb
curl -o ${OHAI_PLUGINS_RACKERLABS}/sysctl.rb https://raw.githubusercontent.com/rackerlabs/ohai-plugins/master/plugins/sysctl.rb
ohai

#-------------------------------------------------------------------------------
# Custom Package Installation [Fluetnd(td-agent)]
#-------------------------------------------------------------------------------
# curl -L http://toolbelt.treasuredata.com/sh/install-redhat-td-agent2.sh | bash -v
rpm --import http://packages.treasuredata.com/GPG-KEY-td-agent

cat > /etc/yum.repos.d/td.repo << __EOF__
[treasuredata]
name=TreasureData
baseurl=http://packages.treasuredata.com/2/redhat/\$releasever/\$basearch
gpgcheck=1
gpgkey=https://packages.treasuredata.com/GPG-KEY-td-agent
__EOF__

yum install -y td-agent

/opt/td-agent/embedded/bin/fluent-gem list --local
/opt/td-agent/embedded/bin/fluent-gem install fluent-plugin-cloudwatch-logs
/opt/td-agent/embedded/bin/fluent-gem install fluent-plugin-elasticsearch
/opt/td-agent/embedded/bin/fluent-gem update fluent-plugin-s3
/opt/td-agent/embedded/bin/fluent-gem list --local

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

cat > /etc/sysctl.d/ipv6-disable.conf << __EOF__
# Custom sysctl Parameter for ipv6 disable
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
__EOF__

sysctl -p
sysctl -a | grep -ie "local_port" -ie "ipv6" | sort

# Instance Reboot
reboot
