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

# Red Hat Update Infrastructure Client Package Update
yum clean all
yum update -y rh-amazon-rhui-client

# Enable Channnel (RHEL Server RPM) - [Default Enable]
yum-config-manager --enable rhui-REGION-rhel-server-releases
yum-config-manager --enable rhui-REGION-rhel-server-rh-common
yum-config-manager --enable rhui-REGION-client-config-server-6

# Enable Channnel (RHEL Server RPM) - [Default Disable]
yum-config-manager --enable rhui-REGION-rhel-server-releases-optional
yum-config-manager --enable rhui-REGION-rhel-server-supplementary
# yum-config-manager --enable rhui-REGION-rhel-server-rhscl

# Enable Channnel (RHEL Server Debug RPM)
# yum-config-manager --enable rhui-REGION-rhel-server-debug-rh-common
# yum-config-manager --enable rhui-REGION-rhel-server-debug-supplementary
# yum-config-manager --enable rhui-REGION-rhel-server-debug-rhscl

# Enable Channnel (RHEL Server Source RPM)
# yum-config-manager --enable rhui-REGION-rhel-server-releases-source
# yum-config-manager --enable rhui-REGION-rhel-server-source-rh-common
# yum-config-manager --enable rhui-REGION-rhel-server-releases-optional-source
# yum-config-manager --enable rhui-REGION-rhel-server-source-supplementary
# yum-config-manager --enable rhui-REGION-rhel-server-source-rhscl

# yum repository metadata Clean up
yum clean all

# Default Package Update
yum update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install RHEL System Administration Tools (from Red Hat Official Repository)
yum install -y git lzop yum-priorities yum-plugin-versionlock
yum install -y redhat-access-insights redhat-support-tool
yum install -y setroubleshoot-server

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
yum localinstall -y http://download.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
yum clean all

# Package Install RHEL System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y bash-completion jq

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
ntpdate 0.rhel.pool.ntp.org
date

# Setting NTP Deamon
sed -i 's/restrict -6/#restrict -6/g' /etc/ntp.conf
service ntpd start
chkconfig ntpd on

# Setting Language
cat > /etc/sysconfig/i18n << __EOF__
LANG=ja_JP.UTF-8
__EOF__

# Firewall Service Disabled (iptables/ip6tables)
service iptables stop
chkconfig --list iptables
chkconfig iptables off
chkconfig --list iptables

service ip6tables stop
chkconfig --list ip6tables
chkconfig ip6tables off
chkconfig --list ip6tables

# Root Disk Partition Resize (GPT)
# -- Use RHEL v6 HVM AMI (6.6_HVM_GA) --
#    HexCode:EF00 [EFI System]
df -h
gdisk -l /dev/xvda

gdisk /dev/xvda << __EOF__
p
d
p
w
Y
Y
__EOF__

gdisk -l /dev/xvda

gdisk /dev/xvda << __EOF__
n
1
2048

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

cat > /etc/sysctl.d/ipv6-disable.conf << __EOF__
# Custom sysctl Parameter for ipv6 disable
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
__EOF__

sysctl -p
sysctl -a | grep -ie "local_port" -ie "ipv6" | sort

# Instance Reboot
reboot
