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

# Red Hat Update Infrastructure Client Package Update
yum clean all
yum update -y rh-amazon-rhui-client

# Enable Channnel (RHEL Server RPM) - [Default Enable]
yum-config-manager --enable rhui-REGION-rhel-server-releases
yum-config-manager --enable rhui-REGION-rhel-server-rh-common
yum-config-manager --enable rhui-REGION-client-config-server-7

# Enable Channnel (RHEL Server RPM) - [Default Disable]
yum-config-manager --enable rhui-REGION-rhel-server-optional
yum-config-manager --enable rhui-REGION-rhel-server-extras
# yum-config-manager --enable rhui-REGION-rhel-server-rhscl

# Enable Channnel (RHEL Server Debug RPM)
# yum-config-manager --enable rhui-REGION-rhel-server-releases-debug
# yum-config-manager --enable rhui-REGION-rhel-server-debug-rh-common
# yum-config-manager --enable rhui-REGION-rhel-server-debug-optional
# yum-config-manager --enable rhui-REGION-rhel-server-debug-extras
# yum-config-manager --enable rhui-REGION-rhel-server-debug-rhscl

# Enable Channnel (RHEL Server Source RPM)
# yum-config-manager --enable rhui-REGION-rhel-server-releases-source
# yum-config-manager --enable rhui-REGION-rhel-server-source-rh-common
# yum-config-manager --enable rhui-REGION-rhel-server-source-optional
# yum-config-manager --enable rhui-REGION-rhel-server-source-extras
# yum-config-manager --enable rhui-REGION-rhel-server-source-rhscl

# yum repository metadata Clean up
yum clean all

# Default Package Update
yum update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install RHEL System Administration Tools (from Red Hat Official Repository)
yum install -y bash-completion dstat gdisk git lzop iotop mtr sos traceroute yum-priorities yum-plugin-versionlock
yum install -y redhat-access-insights redhat-support-tool
yum install -y setroubleshoot-server

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
yum localinstall -y http://download.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-5.noarch.rpm
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
yum clean all

# Package Install RHEL System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y jq

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI]
#-------------------------------------------------------------------------------
yum --enablerepo=epel install -y python-pip
pip install --upgrade pip
pip install awscli
aws --version
aws ec2 describe-regions --region ${region}

cat > /etc/profile.d/aws-cli.sh << __EOF__
if [ -n "\$BASH_VERSION" ]; then
   complete -C /usr/bin/aws_completer aws
fi
__EOF__

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-SHELL]
#-------------------------------------------------------------------------------
# yum --enablerepo=epel install -y python-pip
# pip install --upgrade pip
# pip install --upgrade awscli
# pip install aws-shell

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

cd /tmp
curl -O https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz
tar -xvpf aws-cfn-bootstrap-latest.tar.gz

cd aws-cfn-bootstrap-1.4/
python setup.py build
python setup.py install

chmod 775 /usr/init/redhat/cfn-hup
ln -s /usr/init/redhat/cfn-hup /etc/init.d/cfn-hup

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Simple Systems Manager (SSM) agent]
#-------------------------------------------------------------------------------
# yum localinstall -y https://amazon-ssm-ap-northeast-1.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm
# yum localinstall -y https://amazon-ssm-${region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

yum localinstall -y https://amazon-ssm-${region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

systemctl status amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl is-enabled amazon-ssm-agent

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

__EOF__

python ./awslogs-agent-setup.py --region ${region} --configfile /tmp/awslogs.conf --non-interactive
systemctl status awslogs
systemctl enable awslogs
systemctl is-enabled awslogs

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
#-------------------------------------------------------------------------------
yum --enablerepo=epel install -y ansible

#-------------------------------------------------------------------------------
# Custom Package Installation [Chef-Client(Chef-Solo)]
#-------------------------------------------------------------------------------
curl -L https://www.chef.io/chef/install.sh | bash -v
mkdir -p /etc/chef/ohai/hints
echo {} > /etc/chef/ohai/hints/ec2.json
OHAI_PLUGINS="$(ohai | jq -r '.chef_packages.ohai.ohai_root + "/plugins"')"
OHAI_PLUGINS_RACKERLABS="${OHAI_PLUGINS}/rackerlabs"
mkdir -p ${OHAI_PLUGINS_RACKERLABS}
# curl -o ${OHAI_PLUGINS_RACKERLABS}/packages.rb https://raw.githubusercontent.com/rackerlabs/ohai-plugins/master/plugins/packages.rb
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

# Setting TimeZone
# timedatectl status
timedatectl set-timezone Asia/Tokyo
# timedatectl status

# Setting Language
# localectl status
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

cat > /etc/sysctl.d/ipv6-disable.conf << __EOF__
# Custom sysctl Parameter for ipv6 disable
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
__EOF__

sysctl -p
sysctl -a | grep -ie "local_port" -ie "ipv6" | sort

# Instance Reboot
reboot
