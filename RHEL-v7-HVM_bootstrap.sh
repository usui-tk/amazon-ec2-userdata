#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data.log || logger -t user-data -s 2> /dev/console) 2>&1

# Red Hat Update Infrastructure Client Package Update
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
yum localinstall -y http://packages.treasuredata.com/2/redhat/7/x86_64/td-agent-2.1.3-0.x86_64.rpm
systemctl start td-agent
systemctl status td-agent
systemctl enable td-agent
systemctl is-enabled td-agent

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
# -- Use RHEL v7 HVM AMI (7.0_HVM_GA) --
#    HexCode:EF02 [BIOS boot partition]  -> /dev/xvda1 <- None
#    HexCode:0700 [Microsoft basic data] -> /dev/xvda2 <- /
df -h
gdisk -l /dev/xvda

gdisk /dev/xvda << __EOF__
p
d
2
p
w
Y
Y
__EOF__

gdisk -l /dev/xvda

gdisk /dev/xvda << __EOF__
n
2
4096

0700
p
w
Y
Y
__EOF__

gdisk -l /dev/xvda
df -h

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

