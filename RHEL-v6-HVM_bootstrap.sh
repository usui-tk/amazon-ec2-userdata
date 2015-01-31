#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data.log || logger -t user-data -s 2> /dev/console) 2>&1

# Red Hat Update Infrastructure Client Package Update
yum update -y rh-amazon-rhui-client

# Enable Channnel (RHEL Server RPM) - [Default Enable]
# yum-config-manager --enable rhui-REGION-rhel-server-releases
# yum-config-manager --enable rhui-REGION-rhel-server-rh-common
# yum-config-manager --enable rhui-REGION-client-config-server-6

# Enable Channnel (RHEL Server RPM) - [Default Disable]
yum-config-manager --enable rhui-REGION-rhel-server-releases-optional
yum-config-manager --enable rhui-REGION-rhel-server-supplementary
#yum-config-manager --enable rhui-REGION-rhel-server-rhscl

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

# Custom Package Install
yum install -y git yum-priorities yum-plugin-versionlock

# yum repository metadata Clean up
yum clean all

# Custom Package Install EPEL(Extra Packages for Enterprise Linux) repository Package
yum localinstall -y http://download.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
yum clean all

# Custom Package Install (from EPEL)
yum install -y bash-completion gdisk jq

# Custom Package Install AWS CloudFormation Helper Scripts
# Depends on EPEL repository
yum localinstall -y https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.amzn1.noarch.rpm

# Custom Package Install Chef-Client(Chef-Solo)
curl -L https://www.chef.io/chef/install.sh | bash -v

# Ohai EC2 Provider
mkdir -p /etc/chef/ohai/hints
echo {} > /etc/chef/ohai/hints/ec2.json

# Custom Package Install Fluetnd(td-agent)
# curl -L http://toolbelt.treasuredata.com/sh/install-redhat-td-agent2.sh | bash -v
yum localinstall -y http://packages.treasuredata.com/2/redhat/6/x86_64/td-agent-2.1.3-0.x86_64.rpm
service td-agent start
service td-agent status
chkconfig td-agent on

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

ef00
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
sysctl -a | grep -ie "local_port" -ie "ipv6" | sort
echo "# Custom sysctl Parameter for ipv6 disable" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
sysctl -a | grep -ie "local_port" -ie "ipv6" | sort

# Instance Reboot
reboot

