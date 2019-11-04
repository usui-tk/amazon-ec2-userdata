#!/bin/bash -v

set -e -x

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

# Command Non-Interactive Mode
export DEBIAN_FRONTEND=noninteractive

# yum repository metadata Clean up
apt-get clean -y

# Default Package Update
apt-get update -y && apt-get upgrade -y && apt-get dist-upgrade -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Ubuntu System Administration Tools (from Ubuntu Official Repository)
apt-get install -y arptables atop bash-completion binutils chrony collectl curl debian-goodies dstat ebtables fio gdisk git hdparm ipv6toolkit jq lsof lzop iotop mtr needrestart nmap nvme-cli sysstat tcpdump traceroute unzip update-motd wget zip

#-------------------------------------------------------------------------------
# Custom Package Installation [Special package for AWS]
#-------------------------------------------------------------------------------

# Package Install Special package for AWS (from Ubuntu Official Repository)
apt-get install -y linux-aws linux-image-aws linux-tools-aws

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

if [ -n "$RoleName" ]; then
	StsCredential=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
	StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
	StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
	StsToken=$(echo $StsCredential | jq -r '.Token')
fi

# AWS Account ID
AwsAccountId=$(curl -s "http://169.254.169.254/latest/dynamic/instance-identity/document" | jq -r '.accountId')

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI]
#-------------------------------------------------------------------------------
# apt-get install -y python3-pip
apt-get install -y awscli

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
	if [[ "$InstanceType" =~ ^(c5.*|e3.*|f1.*|g3.*|h1.*|i3.*|m5.*|p2.*|p3.*|r4.*|x1.*|x1e.*|m4.16xlarge)$ ]]; then
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
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/EBSPerformance.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(c1.*|c3.*|c4.*|c5.*|d2.*|e3.*|f1.*|g2.*|g3.*|h1.*|i2.*|i3.*|m1.*|m2.*|m3.*|m4.*|m5.*|p2.*|p3.*|r3.*|r4.*|x1.*|x1e.*)$ ]]; then
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
# Custom Package Installation [AWS CloudFormation Helper Scripts]
#-------------------------------------------------------------------------------
apt-get install -y python-setuptools
easy_install https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz

ln -s /usr/local/lib/python2.7/dist-packages/aws_cfn_bootstrap-1.4-py2.7.egg/init/ubuntu/cfn-hup /etc/init.d/cfn-hup
chmod +x /etc/init.d/cfn-hup
update-rc.d cfn-hup defaults
service cfn-hup start

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------
curl -sS "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb" -o "/tmp/amazon-ssm-agent.deb"
dpkg -i "/tmp/amazon-ssm-agent.deb"

systemctl daemon-reload

systemctl status -l amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl is-enabled amazon-ssm-agent

systemctl restart amazon-ssm-agent
systemctl status -l amazon-ssm-agent

ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Rescue for Linux (ec2rl)]
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Linux-Server-EC2Rescue.html
# https://github.com/awslabs/aws-ec2rescue-linux
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

apt-get install -y software-properties-common
apt-add-repository -y ppa:ansible/ansible
apt-get update -y
apt-get install -y ansible

ansible --version

ansible localhost -m setup 


################################################################################
#    Bastion Server Configuration - START
################################################################################

#-------------------------------------------------------------------------------
# BANNER CONFIGURATION - Ubuntu (motd)
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
# LOGGING CONFIGURATION - Ubuntu (sshd logging)
#-------------------------------------------------------------------------------
declare -rx BASTION_MNT="/var/log/bastion"
declare -rx BASTION_LOG="bastion.log"
echo "Setting up bastion session log in ${BASTION_MNT}/${BASTION_LOG}"
mkdir -p ${BASTION_MNT}
declare -rx BASTION_LOGFILE="${BASTION_MNT}/${BASTION_LOG}"
declare -rx BASTION_LOGFILE_SHADOW="${BASTION_MNT}/.${BASTION_LOG}"
touch ${BASTION_LOGFILE}
ln ${BASTION_LOGFILE} ${BASTION_LOGFILE_SHADOW}

chown root:ubuntu  ${BASTION_MNT}
chown root:ubuntu  ${BASTION_LOGFILE}
chown root:ubuntu  ${BASTION_LOGFILE_SHADOW}
chmod 662 ${BASTION_LOGFILE}
chmod 662 ${BASTION_LOGFILE_SHADOW}
chattr +a ${BASTION_LOGFILE}
chattr +a ${BASTION_LOGFILE_SHADOW}
touch /tmp/messages
chown root:ubuntu /tmp/messages

chown syslog:adm /var/log/bastion
chown root:ubuntu /usr/bin/script

systemctl restart sshd

echo -e "\nDefaults env_keep += \"SSH_CLIENT\"" >> /etc/sudoers

cat >> /etc/bash.bashrc << __EOF__

# Added by linux bastion bootstrap
declare -rx IP=\$(who am i --ips|awk '{print \$5}')

declare -rx BASTION_LOG=${BASTION_LOGFILE}

declare -rx PROMPT_COMMAND='history -a >(logger -t "\$(date +"%Y/%m/%d %H:%M:%S.%3N %:z") [BASTION] [FROM]:\${IP} [USER]:\${USER} [DIRECTORY]:\${PWD} [COMMAND]" -s 2>>\${BASTION_LOG})'

__EOF__

systemctl restart sshd

#-------------------------------------------------------------------------------
# LOGGING CONFIGURATION - CentOS (chronyd logging)
#-------------------------------------------------------------------------------

# Package Install Ubuntu System Administration Tools (from Ubuntu Official Repository)
apt-get install -y chrony

systemctl daemon-reload

systemctl status -l chrony
systemctl enable chrony
systemctl is-enabled chrony

systemctl restart chrony
systemctl status -l chrony

sleep 3
chronyc tracking
chronyc sources -v
chronyc sourcestats -v

cat /etc/chrony/chrony.conf

cat /etc/logrotate.d/chrony

#-------------------------------------------------------------------------------
# AUTOMATICALLY UPDATE CONFIGURATION - Ubuntu (apt-get)
#-------------------------------------------------------------------------------
apt-get install -y unattended-upgrades

cat /etc/apt/apt.conf.d/20auto-upgrades

cat /etc/apt/apt.conf.d/50unattended-upgrades

systemctl daemon-reload

systemctl status -l unattended-upgrades
systemctl enable unattended-upgrades
systemctl is-enabled unattended-upgrades

systemctl restart unattended-upgrades
systemctl status -l unattended-upgrades

unattended-upgrades --dry-run
# unattended-upgrades --apt-debug

#-------------------------------------------------------------------------------
# LOGGING CONFIGURATION - CentOS (AWS CloudWatchLogs Agent)
#-------------------------------------------------------------------------------

# pip install --upgrade pip

curl -sS "https://s3.amazonaws.com/aws-cloudwatch/downloads/latest/awslogs-agent-setup.py" -o "/tmp/awslogs-agent-setup.py"

cat > /tmp/awslogs.conf << __EOF__
[general]
state_file = /var/awslogs/state/agent-state
use_gzip_http_content_encoding = true
logging_config_file = /var/awslogs/etc/awslogs.conf

[BastionServer-Linux-OS-var-log-syslog]
log_group_name = BastionServer-Linux-LogGroupName
log_stream_name = {instance_id}_{hostname}_{ip_address}_LogFile-syslog
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/syslog
initial_position = start_of_file
encoding = ascii
buffer_duration = 5000

[BastionServer-Linux-OS-var-log-auth]
log_group_name = BastionServer-Linux-LogGroupName
log_stream_name = {instance_id}_{hostname}_{ip_address}_LogFile-auth.log
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/auth.log
initial_position = start_of_file
encoding = ascii
buffer_duration = 5000

[BastionServer-Linux-OS-var-log-dpkg]
log_group_name = BastionServer-Linux-LogGroupName
log_stream_name = {instance_id}_{hostname}_{ip_address}_LogFile-dpkg.log
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/dpkg.log
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

[BastionServer-Linux-OS-var-log-chronyd]
log_group_name = BastionServer-Linux-LogGroupName
log_stream_name = {instance_id}_{hostname}_{ip_address}_LogFile-chrony-statistics.log
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/chrony/statistics.log
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

python /tmp/awslogs-agent-setup.py --region ${Region} --configfile /tmp/awslogs.conf --non-interactive

systemctl status awslogs
systemctl enable awslogs
systemctl is-enabled awslogs

systemctl restart awslogs
systemctl status awslogs

bash /var/awslogs/bin/awslogs-version.sh

################################################################################
#    Bastion Server Configuration - FINISH
################################################################################


#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
apt-get clean -y

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

# Network Information(Firewall Service) [Uncomplicated firewall]
if [ $(command -v ufw) ]; then
    # Network Information(Firewall Service) [systemctl status -l ufw]
    systemctl status -l ufw
    # Network Information(Firewall Service Status) [ufw status]
    ufw status verbose
    # Network Information(Firewall Service Disabled) [ufw disable]
    ufw disable
    # Network Information(Firewall Service Status) [systemctl status -l ufw]
	systemctl status -l ufw
	systemctl disable ufw
	systemctl status -l ufw
fi

# Linux Security Information(AppArmor)
systemctl status -l apparmor
aa-status

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# NTP Service Enabled(chrony)
systemctl daemon-reload

systemctl status -l chrony
systemctl enable chrony
systemctl is-enabled chrony

systemctl restart chrony
systemctl status -l chrony

sleep 3
chronyc tracking
chronyc sources -v
chronyc sourcestats -v

# Setting SystemClock and Timezone
if [ "${Timezone}" = "Asia/Tokyo" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl set-timezone Asia/Tokyo
	date
	dpkg-reconfigure --frontend noninteractive tzdata
elif [ "${Timezone}" = "UTC" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl set-timezone UTC
	date
	dpkg-reconfigure --frontend noninteractive tzdata
else
	echo "# Default SystemClock and Timezone"
	date
	dpkg-reconfigure --frontend noninteractive tzdata
fi

# Time synchronization with NTP server
date
chronyc tracking
chronyc sources -v
chronyc sourcestats -v
date

# Setting System Language
if [ "${Language}" = "ja_JP.UTF-8" ]; then
	# Custom Package Installation [language-pack-ja]
	apt-get install -y language-pack-ja fonts-ipafont
	echo "# Setting System Language -> $Language"
	locale
	# localectl status
	localectl set-locale LANG=ja_JP.utf8
	locale
	strings /etc/default/locale
elif [ "${Language}" = "en_US.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
	locale
	# localectl status
	localectl set-locale LANG=en_US.utf8
	locale
	strings /etc/default/locale
else
	echo "# Default Language"
	locale
	strings /etc/default/locale
fi

# Setting IP Protocol Stack (IPv4 Only) or (IPv4/IPv6 Dual stack)
if [ "${VpcNetwork}" = "IPv4" ]; then
	echo "# Setting IP Protocol Stack -> $VpcNetwork"
	
	# Disable IPv6 Uncomplicated Firewall (ufw)
	sed -i "s/IPV6=yes/IPV6=no/g" /etc/default/ufw

	# Disable IPv6 Kernel Module
	echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf
	
	# Disable IPv6 Kernel Parameter
	sysctl -a

	DisableIPv6Conf="/etc/sysctl.d/99-ipv6-disable.conf"

	cat /dev/null > $DisableIPv6Conf
	echo '# Custom sysctl Parameter for ipv6 disable' >> $DisableIPv6Conf
	echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> $DisableIPv6Conf
	echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> $DisableIPv6Conf

	sysctl --system
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
checkrestart -a

needrestart -v

#-------------------------------------------------------------------------------
# Reboot
#-------------------------------------------------------------------------------

# Instance Reboot
reboot
