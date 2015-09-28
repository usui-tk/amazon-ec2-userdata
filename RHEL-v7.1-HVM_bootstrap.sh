#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data.log || logger -t user-data -s 2> /dev/console) 2>&1

# Red Hat Update Infrastructure Client Package Update
yum clean all
yum update -y rh-amazon-rhui-client

# Enable Channnel (RHEL Server RPM) - [Default Enable]
# yum-config-manager --enable rhui-REGION-rhel-server-releases
# yum-config-manager --enable rhui-REGION-rhel-server-rh-common
# yum-config-manager --enable rhui-REGION-client-config-server-7

# Enable Channnel (RHEL Server RPM) - [Default Disable]
yum-config-manager --enable rhui-REGION-rhel-server-optional
yum-config-manager --enable rhui-REGION-rhel-server-extras
#yum-config-manager --enable rhui-REGION-rhel-server-rhscl

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

# Custom Package Install
yum install -y bash-completion gdisk git yum-priorities yum-plugin-versionlock

# yum repository metadata Clean up
yum clean all

# Custom Package Install EPEL(Extra Packages for Enterprise Linux) repository Package
yum localinstall -y http://download.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-5.noarch.rpm
yum clean all

# Custom Package Install (from EPEL)
yum install -y jq

# Custom Package Install Chef-Client(Chef-Solo)
curl -L https://www.chef.io/chef/install.sh | bash -v

# Ohai EC2 Provider
mkdir -p /etc/chef/ohai/hints
echo {} > /etc/chef/ohai/hints/ec2.json

# Custom Package Install Fluetnd(td-agent)
# curl -L http://toolbelt.treasuredata.com/sh/install-redhat-td-agent2.sh | bash -v
rpm --import http://packages.treasuredata.com/GPG-KEY-td-agent

cat > /etc/yum.repos.d/td.repo << __EOF__
[treasuredata]
name=TreasureData
baseurl=http://packages.treasuredata.com/2/redhat/7/\$basearch
gpgcheck=1
gpgkey=http://packages.treasuredata.com/GPG-KEY-td-agent
__EOF__

yum install -y td-agent
systemctl start td-agent
systemctl status td-agent
systemctl enable td-agent
systemctl is-enabled td-agent

# Update rubygem for Fluentd
/opt/td-agent/embedded/bin/fluent-gem list --local
#/opt/td-agent/embedded/bin/fluent-gem update ${gem-name}

# Setting TimeZone
# timedatectl status
# timedatectl set-timezone Asia/Tokyo
# timedatectl status

# Setting Language
# localectl status
# localectl set-locale LANG=ja_JP.utf8
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


# Root Disk Partition Resize (GPT)
# -- Use RHEL v7 HVM AMI (7.1_HVM_GA) --
#    HexCode:EF02 [BIOS boot partition]  -> /dev/xvda1 <- None
#    HexCode:0700 [Microsoft basic data] -> /dev/xvda2 <- /
df -h
gdisk -l /dev/xvda

# Disable IPv6 Kernel Module
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf

# Disable IPv6 Kernel Parameter
sysctl -a
echo "# Custom sysctl Parameter for ipv6 disable" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
sysctl -a | grep -ie "local_port" -ie "ipv6" | sort

# Instance Reboot
reboot

