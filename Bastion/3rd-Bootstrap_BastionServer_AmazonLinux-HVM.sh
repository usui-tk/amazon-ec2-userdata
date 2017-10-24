#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data_3rd-bootstrap.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Set UserData Parameter
#-------------------------------------------------------------------------------

if [ -f /tmp/userdata-parameter ]; then
    source /tmp/userdata-parameter
fi

if [[ -z "${Language}" || -z "${Timezone}" || -z "${VpcNetwork}" ]]; then
    # Default Language
	Language="ja_JP.UTF-8"
    # Default Timezone
	Timezone="Asia/Tokyo"
	# Default VPC Network
	VpcNetwork="IPv4"
fi

# echo
echo $Language
echo $Timezone
echo $VpcNetwork

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
yum install -y arptables_jf collectl dstat ebtables fio gdisk git hdparm jq lsof lzop iotop mtr nc nmap sos sysstat tcpdump traceroute vim-enhanced yum-plugin-versionlock yum-utils wget

# Package Install Amazon Linux System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y bash-completion

#-------------------------------------------------------------------------------
# Set AWS Instance MetaData
#-------------------------------------------------------------------------------

# Instance MetaData
AZ=$(curl -s "http://169.254.169.254/latest/meta-data/placement/availability-zone")
Region=$(echo $AZ | sed -e 's/.$//g')
InstanceId=$(curl -s "http://169.254.169.254/latest/meta-data/instance-id")
InstanceType=$(curl -s "http://169.254.169.254/latest/meta-data/instance-type")
PrivateIp=$(curl -s "http://169.254.169.254/latest/meta-data/local-ipv4")
AmiId=$(curl -s "http://169.254.169.254/latest/meta-data/ami-id")

# IAM Role & STS Information
RoleArn=$(curl -s "http://169.254.169.254/latest/meta-data/iam/info" | jq -r '.InstanceProfileArn')
RoleName=$(echo $RoleArn | cut -d '/' -f 2)

StsCredential=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
StsToken=$(echo $StsCredential | jq -r '.Token')

# AWS Account ID
AwsAccountId=$(curl -s "http://169.254.169.254/latest/dynamic/instance-identity/document" | jq -r '.accountId')

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI]
#-------------------------------------------------------------------------------
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


# Get AWS Region Information
if [ -n "$RoleName" ]; then
	echo "# Get AWS Region Infomation"
	aws ec2 describe-regions --region ${Region}
fi

# Get AMI Information
if [ -n "$RoleName" ]; then
	echo "# Get AMI Information"
	aws ec2 describe-images --image-ids ${AmiId} --output json --region ${Region}
fi

# Get EC2 Instance Information
if [ -n "$RoleName" ]; then
	echo "# Get EC2 Instance Information"
	aws ec2 describe-instances --instance-ids ${InstanceId} --output json --region ${Region}
fi

# Get EC2 Instance attached EBS Volume Information
if [ -n "$RoleName" ]; then
	echo "# Get EC2 Instance attached EBS Volume Information"
	aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=${InstanceId} --output json --region ${Region}
fi

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
#
# - ENA (Elastic Network Adapter)
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
# - SR-IOV
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/sriov-networking.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(e3.*|f1.*|g3.*|i3.*|p2.*|r4.*|x1.*|x1e.*|m4.16xlarge)$ ]]; then
		# Get EC2 Instance Attribute(Elastic Network Adapter Status)
		echo "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
		aws ec2 describe-instances --instance-id ${InstanceId} --query Reservations[].Instances[].EnaSupport --output json --region ${Region}
		echo "# Get Linux Kernel Module(modinfo ena)"
		modinfo ena
	elif [[ "$InstanceType" =~ ^(c3.*|c4.*|d2.*|i2.*|r3.*|m4.*)$ ]]; then
		# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
		echo "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}
		echo "# Get Linux Kernel Module(modinfo ixgbevf)"
		modinfo ixgbevf
	else
		echo "# Not Target Instance Type :" $InstanceType
	fi
fi

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
#
# - EBS Optimized Instance
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/EBSOptimized.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(c1.*|c3.*|c4.*|d2.*|e3.*|f1.*|g2.*|g3.*|i2.*|i3.*|m1.*|m2.*|m3.*|m4.*|p2.*|r3.*|r4.*|x1.*|x1e.*)$ ]]; then
		# Get EC2 Instance Attribute(EBS-optimized instance Status)
		echo "# Get EC2 Instance Attribute(EBS-optimized instance Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute ebsOptimized --output json --region ${Region}
		echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
		blockdev --report
	else
		echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
		blockdev --report
	fi
fi

#-------------------------------------------------------------------------------
# Custom Package Update [AWS Systems Service Manager (aka SSM) agent]
#-------------------------------------------------------------------------------
# yum localinstall -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

yum localinstall -y "https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm"

/sbin/status amazon-ssm-agent
/sbin/restart amazon-ssm-agent
/sbin/status amazon-ssm-agent

ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Rescue for Linux (ec2rl)]
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Linux-Server-EC2Rescue.html
#-------------------------------------------------------------------------------

# Package Download Amazon Linux System Administration Tools (from S3 Bucket)
curl -sS "https://s3.amazonaws.com/ec2rescuelinux/ec2rl.tgz" -o "/tmp/ec2rl.tgz"

mkdir -p "/opt/aws"

tar -xzvf "/tmp/ec2rl.tgz" -C "/opt/aws"

cat > /etc/profile.d/ec2rl.sh << __EOF__
export PATH=\$PATH:/opt/aws/ec2rl
__EOF__

# Check Version
/opt/aws/ec2rl/ec2rl version

/opt/aws/ec2rl/ec2rl version-check

# Required Software Package
/opt/aws/ec2rl/ec2rl software-check

# Diagnosis [dig modules]
# /opt/aws/ec2rl/ec2rl run --only-modules=dig --domain=amazon.com

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
#-------------------------------------------------------------------------------

# Package Install Amazon Linux System Administration Tools (from EPEL Repository)
# yum --enablerepo=epel install -y ansible ansible-doc
# ansible --version
# ansible localhost -m setup

# Package Install Amazon Linux System Administration Tools (from PIP)
pip install ansible

/usr/local/bin/ansible --version
/usr/local/bin/ansible localhost -m setup


################################################################################
#    Bastion Server Configuration - START
################################################################################

#-------------------------------------------------------------------------------
# BANNER CONFIGURATION - Amazon Linux (motd)
#-------------------------------------------------------------------------------
ls -al /etc/update-motd.d/

cat > /etc/update-motd.d/99-bastion-server-message << __EOF__
#!/bin/bash

cat << EOF

###############################################################################
#                                                                             #
#         ----------              CAUTION                  ----------         #
#                                                                             #
###############################################################################
#                           Authorized access only!                           #
#         Disconnect IMMEDIATELY if you are not an authorized user!!!         #
#                All actions will be monitored and recorded.                  #
###############################################################################

EOF
__EOF__

chmod 755 /etc/update-motd.d/99-bastion-server-message

bash -ex /usr/sbin/update-motd

#-------------------------------------------------------------------------------
# LOGGING CONFIGURATION - Amazon Linux (sshd logging)
#-------------------------------------------------------------------------------
declare -rx BASTION_MNT="/var/log/bastion"
declare -rx BASTION_LOG="bastion.log"
echo "Setting up bastion session log in ${BASTION_MNT}/${BASTION_LOG}"
mkdir -p ${BASTION_MNT}
declare -rx BASTION_LOGFILE="${BASTION_MNT}/${BASTION_LOG}"
declare -rx BASTION_LOGFILE_SHADOW="${BASTION_MNT}/.${BASTION_LOG}"
touch ${BASTION_LOGFILE}
ln ${BASTION_LOGFILE} ${BASTION_LOGFILE_SHADOW}

chown root:ec2-user  ${BASTION_MNT}
chown root:ec2-user  ${BASTION_LOGFILE}
chown root:ec2-user  ${BASTION_LOGFILE_SHADOW}
chmod 662 ${BASTION_LOGFILE}
chmod 662 ${BASTION_LOGFILE_SHADOW}
chattr +a ${BASTION_LOGFILE}
chattr +a ${BASTION_LOGFILE_SHADOW}
touch /tmp/messages
chown root:ec2-user /tmp/messages

chown root:ec2-user /usr/bin/script

service sshd restart

echo -e "\nDefaults env_keep += \"SSH_CLIENT\"" >> /etc/sudoers

cat >> /etc/bashrc << __EOF__

# Added by linux bastion bootstrap
declare -rx IP=\$(echo \$SSH_CLIENT | awk '{print \$1}')

declare -rx BASTION_LOG=${BASTION_LOGFILE}

declare -rx PROMPT_COMMAND='history -a >(logger -t "\$(date +"%Y/%m/%d %H:%M:%S.%3N %:z") [BASTION] [FROM]:\${IP} [USER]:\${USER} [DIRECTORY]:\${PWD} [COMMAND]" -s 2>>\${BASTION_LOG})'

__EOF__

service sshd restart

#-------------------------------------------------------------------------------
# LOGGING CONFIGURATION - Amazon Linux (ntpd logging)
#-------------------------------------------------------------------------------
sed -i 's/logconfig =clockall =peerall =sysall =syncall/logconfig =all/g' /etc/ntp.conf
sed -i "/logconfig/a logfile /var/log/ntpstats/ntpd.log" /etc/ntp.conf

ls -al /etc/logrotate.d/

cat >> /etc/logrotate.d/ntpd << __EOF__
/var/log/ntpstats/ntpd.log {
    missingok
    notifempty
    copytruncate
}
__EOF__

ls -al /etc/logrotate.d/

service ntpd restart

#-------------------------------------------------------------------------------
# AUTOMATICALLY UPDATE CONFIGURATION - Amazon Linux (yum update - security)
#-------------------------------------------------------------------------------
yum install -y yum-cron-security

cat /etc/yum/yum-cron-security.conf

service yum-cron status
chkconfig --list yum-cron
chkconfig yum-cron on
chkconfig --list yum-cron
service yum-cron restart
service yum-cron status

#-------------------------------------------------------------------------------
# LOGGING CONFIGURATION - Amazon Linux (AWS CloudWatchLogs Agent)
#-------------------------------------------------------------------------------
yum install -y awslogs aws-cli-plugin-cloudwatch-logs

sed -i "s/region = us-east-1/region = ${Region}/g" /etc/awslogs/awscli.conf

cat >> /etc/awslogs/awslogs.conf << __EOF__

# ----------------------------------------------------------------------------------------------------------------------
#  Added by linux bastion bootstrap
# ----------------------------------------------------------------------------------------------------------------------

[BastionServer-Linux-OS-var-log-messages]
log_group_name = BastionServer-Linux-LogGroupName
log_stream_name = {instance_id}_{hostname}_{ip_address}_LogFile-message
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/messages
initial_position = start_of_file
encoding = utf-8
buffer_duration = 5000

[BastionServer-Linux-OS-var-log-secure]
log_group_name = BastionServer-Linux-LogGroupName
log_stream_name = {instance_id}_{hostname}_{ip_address}_LogFile-secure
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/secure
initial_position = start_of_file
encoding = utf-8
buffer_duration = 5000

[BastionServer-Linux-OS-var-log-yum]
log_group_name = BastionServer-Linux-LogGroupName
log_stream_name = {instance_id}_{hostname}_{ip_address}_LogFile-yum.log
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/yum.log
initial_position = start_of_file
encoding = ascii
buffer_duration = 5000

[BastionServer-Linux-OS-var-log-bastion]
log_group_name = BastionServer-Linux-LogGroupName
log_stream_name = {instance_id}_{hostname}_{ip_address}_LogFile-bastion.log
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/bastion/.bastion.log
initial_position = start_of_file
encoding = ascii
buffer_duration = 5000

[BastionServer-Linux-OS-var-log-ntpd]
log_group_name = BastionServer-Linux-LogGroupName
log_stream_name = {instance_id}_{hostname}_{ip_address}_LogFile-ntpd.log
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/ntpstats/ntpd.log
initial_position = start_of_file
encoding = ascii
buffer_duration = 5000

[BastionServer-Linux-Amazon-SSM-Agent-Logs]
log_group_name = BastionServer-Linux-LogGroupName
log_stream_name = {instance_id}_{hostname}_{ip_address}_LogFile-amazon-ssm-agent.log
datetime_format = %Y-%m-%d %H:%M:%S
time_zone = LOCAL
file = /var/log/amazon/ssm/amazon-ssm-agent.log
initial_position = start_of_file
encoding = ascii
buffer_duration = 5000

__EOF__

service awslogs status
chkconfig --list awslogs
chkconfig awslogs on
chkconfig --list awslogs
service awslogs restart
service awslogs status

################################################################################
#    Bastion Server Configuration - FINISH
################################################################################


#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
yum clean all

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# CPU Information [cat /proc/cpuinfo]
cat /proc/cpuinfo

# CPU Information [lscpu]
lscpu

lscpu --extended

# Memory Information [cat /proc/meminfo]
cat /proc/meminfo

# Memory Information [free]
free

# Disk Information(Partition) [parted -l]
parted -l

# Disk Information(MountPoint) [lsblk]
lsblk

# Disk Information(File System) [df -h]
df -h

# Network Information(Network Interface) [ip addr show]
ip addr show

# Network Information(Routing Table) [ip route show]
ip route show

# Network Information(Firewall Service) [chkconfig --list iptables]
chkconfig --list iptables

# Network Information(Firewall Service) [service ip6tables stop]
chkconfig --list ip6tables

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Ephemeral-Disk Auto Mount Disabled (cloud-init)
sed -i '/ephemeral0/d' /etc/cloud/cloud.cfg

# NTP Service Enabled(ntpd)
chkconfig --list ntpd
chkconfig ntpd on
chkconfig --list ntpd

# Firewall Service Disabled (iptables/ip6tables)
service iptables stop
chkconfig --list iptables
chkconfig iptables off
chkconfig --list iptables

service ip6tables stop
chkconfig --list ip6tables
chkconfig ip6tables off
chkconfig --list ip6tables

# Setting SystemClock and Timezone
if [ "${Timezone}" = "Asia/Tokyo" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	# Setting SystemClock
	cat /dev/null > /etc/sysconfig/clock
	echo 'ZONE="Asia/Tokyo"' >> /etc/sysconfig/clock
	echo 'UTC=false' >> /etc/sysconfig/clock
	cat /etc/sysconfig/clock
	# Setting TimeZone
	date
	/bin/cp -fp /usr/share/zoneinfo/Asia/Tokyo /etc/localtime
	date
elif [ "${Timezone}" = "UTC" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	# Setting SystemClock
	cat /dev/null > /etc/sysconfig/clock
	echo 'ZONE="UTC"' >> /etc/sysconfig/clock
	echo 'UTC=true' >> /etc/sysconfig/clock
	cat /etc/sysconfig/clock
	# Setting TimeZone
	date
	/bin/cp -fp /usr/share/zoneinfo/UTC /etc/localtime
	date
else
	echo "# Default SystemClock and Timezone"
	cat /etc/sysconfig/clock
	cat /etc/localtime
fi

# Time synchronization with NTP server
date
ntpdate 0.amazon.pool.ntp.org
date

# Setting System Language
if [ "${Language}" = "ja_JP.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
	cat /dev/null > /etc/sysconfig/i18n
	echo 'LANG=ja_JP.UTF-8' >> /etc/sysconfig/i18n
	cat /etc/sysconfig/i18n
elif [ "${Language}" = "en_US.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
	cat /dev/null > /etc/sysconfig/i18n
	echo 'LANG=en_US.UTF-8' >> /etc/sysconfig/i18n
	cat /etc/sysconfig/i18n
else
	echo "# Default Language"
	cat /etc/sysconfig/i18n
fi

# Setting IP Protocol Stack (IPv4 Only) or (IPv4/IPv6 Dual stack)
if [ "${VpcNetwork}" = "IPv4" ]; then
	echo "# Setting IP Protocol Stack -> $VpcNetwork"
	# Setting NTP Deamon
	sed -i 's/restrict -6/#restrict -6/g' /etc/ntp.conf
	service ntpd restart
	# Disable IPv6 Kernel Module
	echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf
	# Disable IPv6 Kernel Parameter
	sysctl -a

	DisableIPv6Conf="/etc/sysctl.d/99-ipv6-disable.conf"

	cat /dev/null > $DisableIPv6Conf
	echo '# Custom sysctl Parameter for ipv6 disable' >> $DisableIPv6Conf
	echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> $DisableIPv6Conf
	echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> $DisableIPv6Conf

	sysctl -p

	sysctl -a | grep -ie "local_port" -ie "ipv6" | sort
elif [ "${VpcNetwork}" = "IPv6" ]; then
	echo "# Show IP Protocol Stack -> $VpcNetwork"
	echo "# Show IPv6 Network Interface Address"
	ifconfig
	echo "# Show IPv6 Kernel Module"
	lsmod | grep ipv6
	echo "# Show Network Listen Address and report"
	netstat -an -A inet6
	echo "# Show Network Routing Table"
	netstat -r -A inet6
else
	echo "# Default IP Protocol Stack"
	echo "# Show IPv6 Network Interface Address"
	ifconfig
	echo "# Show IPv6 Kernel Module"
	lsmod | grep ipv6
	echo "# Show Network Listen Address and report"
	netstat -an -A inet6
	echo "# Show Network Routing Table"
	netstat -r -A inet6
fi

# Check Restart Processes and Services
needs-restarting -s | sort

needs-restarting -r

# Instance Reboot
reboot
