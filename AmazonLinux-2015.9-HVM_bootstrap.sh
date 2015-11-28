#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data.log || logger -t user-data -s 2> /dev/console) 2>&1

# Instance MetaData
region=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed -e 's/.$//g')
instanceId=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
privateIp=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

# Default Package Update
yum update -y

# Custom Package Install
yum install -y dstat git iotop jq lzop mtr sos systat yum-plugin-versionlock
yum install -y awslogs aws-cli-plugin-cloudwatch-logs

# yum repository metadata Clean up
yum clean all

# Custom Package Install Chef-Client(Chef-Solo)
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

# Custom Package Install Fluetnd(td-agent)
curl -L http://toolbelt.treasuredata.com/sh/install-redhat-td-agent2.sh | bash -v
/opt/td-agent/embedded/bin/fluent-gem list --local
#/opt/td-agent/embedded/bin/fluent-gem update ${gem-name}
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
sysctl -a | grep -ie "local_port" -ie "ipv6" | sort
echo "# Custom sysctl Parameter for ipv6 disable" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
sysctl -a | grep -ie "local_port" -ie "ipv6" | sort

# Instance Reboot
reboot
