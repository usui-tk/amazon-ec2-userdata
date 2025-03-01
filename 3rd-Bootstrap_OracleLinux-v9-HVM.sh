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
	Language="en_US.UTF-8"
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
# Parameter Settings
#-------------------------------------------------------------------------------

# Parameter Settings
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_OracleLinux-v9-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - Oracle Linux v9
#    https://www.oracle.com/technetwork/server-storage/linux/documentation/index.html
#    https://docs.oracle.com/en/operating-systems/oracle-linux/9/
#    http://yum.oracle.com/oracle-linux-9.html
#    https://github.com/oracle/oracle-linux
#    https://yum.oracle.com/repowatch/
#
#-------------------------------------------------------------------------------

# Cleanup repository information
dnf --enablerepo="*" --verbose clean all

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
	lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
if [ -f /etc/os-release ]; then
	cat "/etc/os-release"
fi

if [ -f /etc/redhat-release ]; then
	cat "/etc/redhat-release"
fi

if [ -f /etc/oracle-release ]; then
	cat "/etc/oracle-release"
fi

# Default installation package [rpm command]
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/command-log_rpm_installed-package.txt

# Default installation package [dnf command]
dnf list installed > /tmp/command-log_dnf_installed-package.txt

# Default repository package [dnf command]
dnf list all > /tmp/command-log_dnf_repository-package-list.txt

# Default repository package group [dnf command]
dnf group list -v > /tmp/command-log_dnf_repository-package-group-list.txt

# Default repository list [dnf command]
dnf repolist all > /tmp/command-log_dnf_repository-list.txt

# Default repository module [dnf command]
dnf module list > /tmp/command-log_dnf_module-list.txt

# systemd unit files
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

# systemd service config
systemctl list-units --type=service --all --no-pager > /tmp/command-log_systemctl_list-service-config.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------
# Yum Repositories (Oracle Linux v9)
#  http://yum.oracle.com/oracle-linux-9.html
#-------------------------------------------------------------------------------

# Cleanup repository information and Update dnf tools
dnf --enablerepo="*" --verbose clean all
dnf update -y dnf dnf-data

# Checking repository information
dnf repolist all
dnf module list

# Package Install Oracle Linux yum repository Files (from Oracle Linux Repository)
find /etc/yum.repos.d/

dnf list *release*el9

dnf install -y oraclelinux-release-el9 oracle-instantclient-release-23ai-el9 oracle-epel-release-el9 oracle-ocne-release-el9 oraclelinux-developer-release-el9
dnf --enablerepo="*" --verbose clean all

# dnf install -y oraclelinux-release-el9 oracle-instantclient-release-23ai-el9 oracle-epel-release-el9 oracle-ocne-release-el9 oraclelinux-developer-release-el9 oracle-java-jdk-release-el9
# dnf --enablerepo="*" --verbose clean all

find /etc/yum.repos.d/

# Check the OCI variables to be used in YUM
if [ -f /etc/yum/vars/ociregion ]; then
	cat /etc/yum/vars/ociregion
fi

if [ -f /etc/yum/vars/ocidomain ]; then
	cat /etc/yum/vars/ocidomain
fi

# Cleanup repository information
dnf --enablerepo="*" --verbose clean all

# Checking repository information
dnf repolist all
dnf module list

# Enable Yum Repository Data from Oracle Linux YUM repository (yum.oracle.com)
dnf config-manager --set-enabled ol9_baseos_latest
dnf config-manager --set-enabled ol9_UEKR7
dnf config-manager --set-enabled ol9_appstream
dnf config-manager --set-enabled ol9_addons
dnf config-manager --set-enabled ol9_codeready_builder
dnf config-manager --set-enabled ol9_oracle_instantclient23
dnf config-manager --set-enabled ol9_developer
dnf config-manager --set-enabled ol9_developer_EPEL
dnf config-manager --set-enabled ol9_olcne19
dnf config-manager --set-enabled ol9_ocne

# Disable Yum Repository Data from Oracle Linux YUM repository (yum.oracle.com)
dnf config-manager --set-disabled ol9_kvm_utils
dnf config-manager --set-disabled ol9_developer_UEKR7
dnf config-manager --set-disabled ol9_developer_kvm_utils
dnf config-manager --set-disabled ol9_distro_builder
dnf config-manager --set-disabled ol9_olcne17
dnf config-manager --set-disabled ol9_olcne18
# dnf config-manager --set-disabled ol9_oracle_instantclient

# Cleanup repository information
dnf --enablerepo="*" --verbose clean all

# Checking repository information
dnf repolist all
dnf module list

# Get Dnf/Yum Repository List (Exclude Dnf/Yum repository related to "BaseOS GA (x86_64), BaseOS (x86_64)")
repolist=$(dnf repolist all --quiet | grep -ie "enabled" -ie "disabled" | grep -ve "BaseOS GA (x86_64)" -ve "BaseOS (x86_64)" | awk '{print $1}' | awk '{ sub("/.*$",""); print $0; }' | sort)

# Oracle Linux YUM repository package [dnf command]
for repo in $repolist
do
	echo "[Target repository Name (Collect dnf/yum repository package list)] :" $repo
	dnf repository-packages ${repo} list > /tmp/command-log_dnf_repository-package-list_${repo}.txt
	sleep 1
done

# Default Package Update
dnf update -y

# Switching Linux-kernel packages (Switch from RHEL compatible kernel to Unbreakable Enterprise Kernel)
# https://docs.oracle.com/en/operating-systems/uek/7/relnotes7.0/index.html

if [ $(grubby --default-kernel | grep -ie "el9uek") ]; then
	echo "Linux Kernel Package Name : kernel-uek"
	# dnf remove -y kernel kernel-core
else
	echo "Linux Kernel Package Name : kernel"
	dnf install -y kernel-uek kernel-uek-devel
fi

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Oracle Linux Linux-Kernel Modules (from Oracle Linux Repository)
if [ $(grubby --default-kernel | grep -ie "el9uek") ]; then
	echo "Linux Kernel Package Name : kernel-uek"
	dnf install -y kernel-uek-modules kernel-uek-modules-extra
else
	echo "Linux Kernel Package Name : kernel"
	dnf install -y kernel-modules kernel-modules-extra
fi

# Package Install Oracle Linux System Administration Tools (from Oracle Linux Repository)
dnf install -y acpid arptables bash-completion bc bcc bcc-tools bind-utils blktrace bpftool bpftrace console-login-helper-messages-motdgen crash-trace-command crypto-policies curl dnf-data dnf-plugins-core dnf-utils dstat ebtables ethtool expect fio gdisk git gnutls-utils hdparm intltool iotop ipcalc iperf3 iproute-tc ipset iptraf-ng jq kexec-tools libbpf-tools libicu libzip-tools linuxptp lsof lvm2 lzop man-pages mc mcelog mdadm mlocate mtr nc net-snmp-utils net-tools nftables nmap nmap-ncat nmstate numactl numatop nvme-cli nvmetcli parted patchutils pmempool policycoreutils psacct psmisc python3-dnf-plugin-versionlock rsync smartmontools sos sos-audit stalld strace symlinks sysfsutils sysstat tcpdump time tlog tmpwatch traceroute tree tzdata unzip usermode util-linux util-linux-user vdo vim-enhanced wget wireshark-cli xfsdump xfsprogs yum-utils zip zsh zstd
dnf install -y cifs-utils nfs-utils nfs4-acl-tools
dnf install -y iscsi-initiator-utils lsscsi sg3_utils stratisd stratis-cli
dnf install -y "selinux-policy*" checkpolicy policycoreutils policycoreutils-python-utils policycoreutils-restorecond setools-console setools-console-analyses setroubleshoot-server strace udica
dnf install -y pcp pcp-conf pcp-export-pcp2json "pcp-pmda*" pcp-selinux pcp-system-tools pcp-zeroconf
dnf install -y rsyslog-mmnormalize rsyslog-mmaudit rsyslog-mmfields rsyslog-mmjsonparse

# Package Install Oracle Linux Cleanup tools (from Oracle Linux Repository)
# dnf install -y ovm-template-config*

# Package Install Oracle Linux Troubleshooting support tools (from Oracle Linux Repository)
# https://github.com/oracle/oled-tools
# https://github.com/oracle/bpftune
dnf install -y oled-tools
dnf install -y bpftune

# Package Install Oracle Linux Cloud Native Environment (from Oracle Linux Repository)
dnf install -y olcne-selinux olcne-utils olcnectl yq

#-------------------------------------------------------------------------------
# Custom Package Installation [kernel live-patching tools]
# https://access.redhat.com/solutions/2206511
#-------------------------------------------------------------------------------

# # Package Install Oracle Linux kernel live-patching tools (from Oracle Linux Repository)
# dnf install -y kpatch kpatch-dnf

# rpm -qi kpatch

# systemctl daemon-reload

# systemctl restart kpatch

# systemctl status -l kpatch

# # Configure kpatch software (Start Daemon kpatch)
# if [ $(systemctl is-enabled kpatch) = "disabled" ]; then
# 	systemctl enable kpatch
# 	systemctl is-enabled kpatch
# fi

# # kpatch information
# kpatch list

# # Package List (kernel live-patch)
# dnf list installed | grep kpatch

#-------------------------------------------------------------------------------
# Custom Package Installation [Cockpit]
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html-single/managing_systems_using_the_rhel_9_web_console/index
#-------------------------------------------------------------------------------

# Package Install Oracle Linux Web-Based support tools (from Oracle Linux Repository)
dnf install -y cockpit cockpit-packagekit cockpit-pcp cockpit-session-recording cockpit-storaged cockpit-system cockpit-ws

rpm -qi cockpit

systemctl daemon-reload

systemctl restart cockpit

systemctl status -l cockpit

# Configure cockpit.socket
if [ $(systemctl is-enabled cockpit.socket) = "disabled" ]; then
	systemctl enable --now cockpit.socket
	systemctl is-enabled cockpit.socket
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [Python 3.9]
#-------------------------------------------------------------------------------

# Package Install Python 3.9 Runtime (from Oracle Linux Repository)
dnf install -y python3 python3-pip python3-rpm-generators python3-rpm-macros python3-setuptools python3-test python3-wheel
# dnf install -y python3 python3-pip python3-rpm-generators python3-rpm-macros python3-setuptools python3-test python3-virtualenv python3-wheel

dnf install -y python3-dateutil python3-jmespath python3-pyasn1 python3-pyasn1 python3-pyasn1-modules python3-pyasn1-modules python3-pyyaml "python3-requests*" python3-six python3-urllib3
dnf install -y python3-distro
# dnf install -y python3-cloud-what
dnf install -y python3-argcomplete

# Version Information (Python 3.9)
python3 -V
pip3 -V

# Python package setting (python3-argcomplete)
activate-global-python-argcomplete

#-------------------------------------------------------------------------------
# Custom Package Installation [EPEL]
#-------------------------------------------------------------------------------

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
# dnf localinstall -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm"

# Cleanup repository information
dnf --enablerepo="*" --verbose clean all

# EPEL repository package [dnf command]
dnf repository-packages "ol9_developer_EPEL" list > /tmp/command-log_dnf_repository-package-list_ol9_developer_EPEL.txt

# Package Install Oracle Linux System Administration Tools (from EPEL Repository)
dnf --enablerepo="ol9_developer_EPEL" install -y aria2 atop bash-color-prompt byobu collectd collectd-utils colordiff dateutils fping glances htop iftop inotify-tools inxi ipv6calc jc lsb_release moreutils moreutils-parallel ncdu nload screen ssh-audit stressapptest unicornscan wdiff yamllint

# Package Install EC2 instance optimization tools (from EPEL Repository)
dnf --enablerepo="ol9_developer_EPEL" install -y amazon-ec2-utils ec2-hibinit-agent ec2-instance-connect

#-------------------------------------------------------------------------------
# Custom Package Installation [EPEL - OpenSCAP]
#-------------------------------------------------------------------------------

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
# dnf localinstall -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm"

# Cleanup repository information
dnf --enablerepo="*" --verbose clean all

# Package Install Oracle Linux System Administration Tools (from EPEL Repository)
dnf --enablerepo="ol9_developer_EPEL" install -y openscap openscap-engine-sce openscap-python3 openscap-report openscap-scanner openscap-utils scap-security-guide

# Open SCAP report generation

# OpenSCAP_Config="/usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml"
# ll /usr/share/xml/scap/ssg/content/
# oscap info ${OpenSCAP_Config}
# oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_ospp --results ssg-ds.xml --report ssg-ds.html ${OpenSCAP_Config}

#-------------------------------------------------------------------------------
# Custom Package Installation [Oracle Software Product]
#-------------------------------------------------------------------------------

# Package Install Oracle Database Utility (from Oracle Linux Repository)
# dnf install -y kmod-redhat-oracleasm oracleasm-support ocfs2-tools
dnf install -y ocfs2-tools
dnf install -y pcp-oracle-conf

# Download JDK Development Kit 17 RPM Package
# curl -sS "https://download.oracle.com/java/17/latest/jdk-17_linux-x64_bin.rpm" -o "/tmp/jdk-17_linux-x64_bin.rpm"

# Package Install JDK Development Kit 17 (from Local File)
# dnf localinstall -y "/tmp/jdk-17_linux-x64_bin.rpm"

# Package Install Oracle Database Developer Tool (from Oracle Linux Repository)
# https://yum.oracle.com/repo/OracleLinux/OL9/oracle/software/x86_64/index.html

# ---------------------------------------
# [workaround] Repository Configuration
# ---------------------------------------
# cat > /etc/yum.repos.d/oracle-software-ol9.repo << __EOF__
# [ol9_oracle_software]
# name=Oracle Software for Oracle Linux \$releasever (\$basearch)
# baseurl=https://yum\$ociregion.\$ocidomain/repo/OracleLinux/OL9/oracle/software/\$basearch/
# gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
# gpgcheck=1
# enabled=1
# __EOF__
# ---------------------------------------

# dnf install -y ords sqlcl

# Package Install Oracle Database Pre-Installation Tools (from Oracle Linux Repository)
dnf install -y oracle-database-preinstall-23ai

# Package Install Oracle Instant Client (from Oracle Linux Repository)
# https://yum.oracle.com/oracle-instant-client.html
dnf --enablerepo="ol9_oracle_instantclient23" install -y oracle-instantclient-basic oracle-instantclient-devel oracle-instantclient-jdbc oracle-instantclient-sqlplus oracle-instantclient-tools

#-------------------------------------------------------------------------------
# Get AWS Instance MetaData Service (IMDS v1, v2)
# https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
# https://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
#-------------------------------------------------------------------------------

# Getting an Instance Metadata Service v2 (IMDS v2) token
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`

if [ -n "$TOKEN" ]; then
	#-----------------------------------------------------------------------
	# Retrieving Metadata Using the Instance Metadata Service v2 (IMDS v2)
	#-----------------------------------------------------------------------

	# Instance MetaData
	Az=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/placement/availability-zone")
	AzId=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/placement/availability-zone-id")
	Region=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/placement/region")
	InstanceId=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/instance-id")
	InstanceType=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/instance-type")
	PrivateIp=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/local-ipv4")
	AmiId=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/ami-id")

	# IAM Role & STS Information
	if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
		RoleArn=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/iam/info" | jq -r '.InstanceProfileArn')
		RoleName=$(echo $RoleArn | cut -d '/' -f 2)
	fi

	if [ -n "$RoleName" ]; then
		StsCredential=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
		if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
			StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
			StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
			StsToken=$(echo $StsCredential | jq -r '.Token')
		fi
	fi

	# AWS Account ID
	if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
		AwsAccountId=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/dynamic/instance-identity/document" | jq -r '.accountId')
	fi

else
	#-----------------------------------------------------------------------
	# Retrieving Metadata Using the Instance Metadata Service v1 (IMDS v1)
	#-----------------------------------------------------------------------

	# Instance MetaData
	Az=$(curl -s "http://169.254.169.254/latest/meta-data/placement/availability-zone")
	AzId=$(curl -s "http://169.254.169.254/latest/meta-data/placement/availability-zone-id")
	Region=$(curl -s "http://169.254.169.254/latest/meta-data/placement/region")
	InstanceId=$(curl -s "http://169.254.169.254/latest/meta-data/instance-id")
	InstanceType=$(curl -s "http://169.254.169.254/latest/meta-data/instance-type")
	PrivateIp=$(curl -s "http://169.254.169.254/latest/meta-data/local-ipv4")
	AmiId=$(curl -s "http://169.254.169.254/latest/meta-data/ami-id")

	# IAM Role & STS Information
	if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
		RoleArn=$(curl -s "http://169.254.169.254/latest/meta-data/iam/info" | jq -r '.InstanceProfileArn')
		RoleName=$(echo $RoleArn | cut -d '/' -f 2)
	fi

	if [ -n "$RoleName" ]; then
		StsCredential=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
		if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
			StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
			StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
			StsToken=$(echo $StsCredential | jq -r '.Token')
		fi
	fi

	# AWS Account ID
	if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
		AwsAccountId=$(curl -s "http://169.254.169.254/latest/dynamic/instance-identity/document" | jq -r '.accountId')
	fi

fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI v2]
# https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html
#-------------------------------------------------------------------------------

# Package Install AWS-CLI v2 packages (from Oracle Linux Repository)
dnf --enablerepo="ol9_developer, ol9_developer_EPEL" -y install awscli2

aws --version

# Setting AWS-CLI default Region & Output format
aws configure << __EOF__


${Region}
json

__EOF__

# Setting AWS-CLI Logging
aws configure set cli_history enabled

# Setting AWS-CLI Pager settings
aws configure set cli_pager ''

# Getting AWS-CLI default Region & Output format
aws configure list
cat ~/.aws/config

#------------------------------------------------------------------------------
# Getting information about AWS services
#------------------------------------------------------------------------------

# Get AWS Security Token Service (AWS STS) Information
if [ -n "$RoleName" ]; then
	echo "# Get AWS Security Token Service (AWS STS) Information"
	aws sts get-caller-identity --output json
fi

# Get AWS Region List
if [ -n "$RoleName" ]; then
	echo "# Get AWS Region List"
	aws ec2 describe-regions --region ${Region} > "/var/log/user-data_aws-cli_aws-services_describe-regions.txt"
fi

# Get Amazon EC2 Instance Type List
if [ -n "$RoleName" ]; then
	echo "# Get Amazon EC2 Instance Type List"
	aws ec2 describe-instance-types --query 'InstanceTypes[?Hypervisor==`nitro`]' --output json --region ${Region} > "/var/log/user-data_aws-cli_aws-services_describe-instance-types_nitro-hypervisor.txt"
	aws ec2 describe-instance-types --query 'InstanceTypes[?Hypervisor==`xen`]' --output json --region ${Region} > "/var/log/user-data_aws-cli_aws-services_describe-instance-types_xen-hypervisor.txt"
fi

#------------------------------------------------------------------------------
# Getting information about Amazon EC2 Instance
#------------------------------------------------------------------------------

# Get Amazon EC2 Instance Information
if [ -n "$RoleName" ]; then
	echo "# Get Amazon EC2 Instance Information"
	aws ec2 describe-instances --instance-ids ${InstanceId} --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instances.txt"
fi

# Get Amazon EC2 Instance Type Information
if [ -n "$RoleName" ]; then
	echo "# Get Amazon EC2 Instance Type Information"
	aws ec2 describe-instance-types --query "InstanceTypes[?InstanceType==\`${InstanceType}\`]" --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types.txt"
fi

# Get Amazon EC2 Instance attached EBS Volume Information
if [ -n "$RoleName" ]; then
	echo "# Get Amazon EC2 Instance attached EBS Volume Information"
	aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=${InstanceId} --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-volumes.txt"
fi

# Get Amazon EC2 Instance attached VPC Security Group Information
if [ -n "$RoleName" ]; then
	echo "# Get Amazon EC2 Instance attached VPC Security Group Information"
	aws ec2 describe-security-groups --group-ids $(aws ec2 describe-instances --instance-id ${InstanceId} --query "Reservations[].Instances[].SecurityGroups[].GroupId[]" --output text --region ${Region}) --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-security-groups.txt"
fi

# Get AMI information of this Amazon EC2 instance
if [ -n "$RoleName" ]; then
	echo "# Get AMI information of this Amazon EC2 instance"
	aws ec2 describe-images --image-ids ${AmiId} --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-images.txt"
fi

#------------------------------------------------------------------------------
# Getting information about Amazon EC2 Instance Attribute
# [Network Interface Performance Attribute]
#------------------------------------------------------------------------------
# - Summary of Networking and Storage Features
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#instance-type-summary-table
# - ENA (Elastic Network Adapter)
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
# - ENA Express (Elastic Network Adapter Express)
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ena-express.html
# - Elastic Fabric Adapter (EFA)
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/efa.html
# - Single-root I/O virtualization (SR-IOV)
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sriov-networking.html
#------------------------------------------------------------------------------

# Get EC2 Instance Attribute [Network Interface Performance Attribute]
if [ -n "$RoleName" ]; then
	echo "# Get EC2 Instance Attribute [Network Interface Performance Attribute]"

	# Get EC2 Instance Attribute [Network Interface Performance Attribute - ENA (Elastic Network Adapter)]
	if [[ $(aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo.EnaSupport" --output text --region ${Region}) == "required" ]]; then
		echo "EnaSupport is available for $InstanceType"

		echo "# Get EC2 Instance Attribute [Network Interface Performance Attribute - ENA (Elastic Network Adapter)]"
		aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo" --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types_NetworkInfo_ENA.txt"

		# Get Linux Kernel Module(modinfo ena)
		echo "# Get Linux Kernel Module(modinfo ena)"
		if [ $(lsmod | awk '{print $1}' | grep -x ena) ]; then
			modinfo ena

			if [ $(command -v nmcli) ]; then
				# Get Network Interface Information
				ethtool -S $(nmcli -t -f DEVICE device | grep -v lo)
				ethtool -c $(nmcli -t -f DEVICE device | grep -v lo)
			fi
		fi
	fi

	# Get EC2 Instance Attribute [Network Interface Performance Attribute - ENA Express (Elastic Network Adapter Express)]
	if [[ $(aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo.EnaSrdSupported" --output text --region ${Region}) == "true" ]]; then
		echo "EnaSrdSupported is available for $InstanceType"

		echo "# Get EC2 Instance Attribute [Network Interface Performance Attribute - ENA Express (Elastic Network Adapter Express)]"
		aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo" --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types_NetworkInfo_ENA_Express.txt"

		# Get Linux Kernel Module(modinfo ena)
		echo "# Get Linux Kernel Module(modinfo ena)"
		if [ $(lsmod | awk '{print $1}' | grep -x ena) ]; then
			modinfo ena

			if [ $(command -v nmcli) ]; then
				# Get Network Interface Information
				ethtool -S $(nmcli -t -f DEVICE device | grep -v lo)
				ethtool -c $(nmcli -t -f DEVICE device | grep -v lo)
			fi
		fi
	fi

	# Get EC2 Instance Attribute [Network Interface Performance Attribute - Elastic Fabric Adapter (EFA)]
	if [[ $(aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo.EfaSupported" --output text --region ${Region}) == "true" ]]; then
		echo "EfaSupported is available for $InstanceType"

		echo "# Get EC2 Instance Attribute [Network Interface Performance Attribute - Elastic Fabric Adapter (EFA)]"
		aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].NetworkInfo" --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types_NetworkInfo_EFA.txt"
	fi

	# Get EC2 Instance Attribute [Network Interface Performance Attribute - Single-root I/O virtualization (SR-IOV)]
	if [[ $(aws ec2 describe-instance-attribute --instance-id $InstanceId --attribute sriovNetSupport --query 'SriovNetSupport.Value' --output text --region ${Region}) == "simple" ]]; then
		echo "SriovNetSupport is available for $InstanceType"

		echo "# Get EC2 Instance Attribute [Network Interface Performance Attribute - Single-root I/O virtualization (SR-IOV)]"
		aws ec2 describe-instance-attribute --instance-id $InstanceId --attribute sriovNetSupport --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types_NetworkInfo_SR-IOV.txt"

		# Get Linux Kernel Module(modinfo ixgbevf)
		echo "# Get Linux Kernel Module(modinfo ixgbevf)"
		if [ $(lsmod | awk '{print $1}' | grep -x ixgbevf) ]; then
			modinfo ixgbevf

			if [ $(command -v nmcli) ]; then
				# Get Network Interface Information
				ethtool -S $(nmcli -t -f DEVICE device | grep -v lo)
				ethtool -c $(nmcli -t -f DEVICE device | grep -v lo)
			fi
		fi
	fi
fi

#------------------------------------------------------------------------------
# Getting information about Amazon EC2 Instance Attribute
# [Storage Interface Performance Attribute]
#------------------------------------------------------------------------------
# - Summary of Networking and Storage Features
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#instance-type-summary-table
# - EBS Optimized Instance
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSOptimized.html
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSPerformance.html
# - Nitro-based Instances
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#ec2-nitro-instances
# - Amazon EBS and NVMe Volumes
#   http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nvme-ebs-volumes.html
# - SSD Instance Store Volumes
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ssd-instance-store.html
#------------------------------------------------------------------------------

# Get EC2 Instance Attribute [Storage Interface Performance Attribute]
if [ -n "$RoleName" ]; then
	echo "# Get EC2 Instance Attribute [Storage Interface Performance Attribute]"

	# Get EC2 Instance Attribute [Storage Interface Performance Attribute - EBS Optimized Instance]
	if [[ $(aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].EbsInfo.EbsOptimizedSupport" --output text --region ${Region}) == "default" ]]; then
		echo "EbsOptimizedSupport is available for $InstanceType"

		echo "# Get EC2 Instance Attribute [Storage Interface Performance Attribute - EBS Optimized Instance]"
		aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].EbsInfo" --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-ec2-instance_describe-instance-types_EbsInfo.txt"
	fi

	# Get EC2 Instance Attribute [Storage Interface Performance Attribute - Amazon EBS and NVMe Volumes]
	if [[ $(aws ec2 describe-instance-types --filters "Name=instance-type,Values=${InstanceType}" --query "InstanceTypes[].EbsInfo.NvmeSupport" --output text --region ${Region}) == "required" ]]; then
		echo "NvmeSupport is available for $InstanceType"

		# Get Linux Kernel Module(modinfo nvme)
		echo "# Get Linux Kernel Module(modinfo nvme)"
		if [ $(lsmod | awk '{print $1}' | grep -x nvme) ]; then
			modinfo nvme
		fi

		# Get NVMe Device(nvme list)
		# http://www.spdk.io/doc/nvme-cli.html
		# https://github.com/linux-nvme/nvme-cli
		if [ $(command -v nvme) ]; then
			echo "# Get NVMe Device(nvme list)"
			nvme list
		fi
	fi

fi

# Get PCI-Express Device(lspci -v)
if [ $(command -v lspci) ]; then
	echo "# Get PCI-Express Device(lspci -v)"
	lspci -v
fi

# Get Disk[MountPoint] Information (lsblk -a)
if [ $(command -v lsblk) ]; then
	echo "# Get Disk[MountPoint] Information (lsblk -a)"
	lsblk -a
fi


# Get Linux Block Device Read-Ahead Value(blockdev --report)
if [ $(command -v blockdev) ]; then
	echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
	blockdev --report
fi

#------------------------------------------------------------------------------
# Getting information about Amazon Machine Image
#------------------------------------------------------------------------------

# Get Amazon Machine Image Information
if [ -n "$RoleName" ]; then

	# Get the latest AMI information of the OS type of this EC2 instance from Public AMI
	echo "# Get Amazon Machine Image Information"

	NewestAmiInfo=$(aws ec2 describe-images --owner "131827586825" --filter "Name=name,Values=OL9.*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)|[0]' --output json --region ${Region})
	NewestAmiId=$(echo $NewestAmiInfo| jq -r '.ImageId')
	aws ec2 describe-images --image-ids ${NewestAmiId} --output json --region ${Region} > "/var/log/user-data_aws-cli_amazon-machine-images_describe-describe-images.txt"
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------

dnf install --nogpgcheck -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

rpm -qi amazon-ssm-agent

systemctl daemon-reload

systemctl restart amazon-ssm-agent

systemctl status -l amazon-ssm-agent

# Configure AWS Systems Manager Agent software (Start Daemon awsagent)
if [ $(systemctl is-enabled amazon-ssm-agent) = "disabled" ]; then
	systemctl enable amazon-ssm-agent
	systemctl is-enabled amazon-ssm-agent
fi

ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Install [Amazon CloudWatch Agent]
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/download-cloudwatch-agent-commandline.html
# https://github.com/aws/amazon-cloudwatch-agent
#-------------------------------------------------------------------------------

dnf install --nogpgcheck -y "https://s3.amazonaws.com/amazoncloudwatch-agent/oracle_linux/amd64/latest/amazon-cloudwatch-agent.rpm"

rpm -qi amazon-cloudwatch-agent

cat /opt/aws/amazon-cloudwatch-agent/bin/CWAGENT_VERSION

cat /opt/aws/amazon-cloudwatch-agent/etc/common-config.toml

systemctl daemon-reload

# Configure Amazon CloudWatch Agent software (Start Daemon awsagent)
if [ $(systemctl is-enabled amazon-cloudwatch-agent) = "disabled" ]; then
	systemctl enable amazon-cloudwatch-agent
	systemctl is-enabled amazon-cloudwatch-agent
fi

# Configure Amazon CloudWatch Agent software (Monitor settings)
curl -sS ${CWAgentConfig} -o "/tmp/config.json"
cat "/tmp/config.json"

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/tmp/config.json -s

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a stop
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a start

systemctl status -l amazon-cloudwatch-agent

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status

# View Amazon CloudWatch Agent config files
cat /opt/aws/amazon-cloudwatch-agent/etc/common-config.toml

cat /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Rescue for Linux (ec2rl)]
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Linux-Server-EC2Rescue.html
# https://github.com/awslabs/aws-ec2rescue-linux
#-------------------------------------------------------------------------------

# Package Amazon EC2 Administration Tools (from S3 Bucket)
curl -sS "https://s3.amazonaws.com/ec2rescuelinux/ec2rl-bundled.tgz" -o "/tmp/ec2rl-bundled.tgz"

mkdir -p "/opt/aws"

rm -rf /opt/aws/ec2rl*

tar -xzf "/tmp/ec2rl-bundled.tgz" -C "/opt/aws"

mv --force /opt/aws/ec2rl* "/opt/aws/ec2rl"

cat > /etc/profile.d/ec2rl.sh << __EOF__
export PATH=\$PATH:/opt/aws/ec2rl
__EOF__

source /etc/profile.d/ec2rl.sh

# Check Version
/opt/aws/ec2rl/ec2rl version

/opt/aws/ec2rl/ec2rl list

# Required Software Package
# /opt/aws/ec2rl/ec2rl software-check

# Diagnosis [dig modules]
# /opt/aws/ec2rl/ec2rl run --only-modules=dig --domain=amazon.com

#-------------------------------------------------------------------------------
# Custom Package Installation [Ansible]
#-------------------------------------------------------------------------------

# Package Install Ansible (from Oracle Linux Repository)
dnf install -y ansible-core ansible-pcp ansible-test

# Package Install Oracle Linux System Administration Tools (from EPEL Repository)
dnf --enablerepo="ol9_developer_EPEL" install -y ansible-collection-community-general

ansible --version

ansible localhost -m setup

#-------------------------------------------------------------------------------
# Custom Package Installation [fluentd]
# https://docs.fluentd.org/installation/install-by-rpm
#-------------------------------------------------------------------------------

curl -fsSL https://toolbelt.treasuredata.com/sh/install-redhat-fluent-package5-lts.sh | sh

rpm -qi fluent-package

systemctl daemon-reload

systemctl restart fluentd

systemctl status -l fluentd

# Configure fluentd software (Start Daemon fluentd)
if [ $(systemctl is-enabled fluentd) = "disabled" ]; then
	systemctl enable fluentd
	systemctl is-enabled fluentd
fi

# Package bundled ruby gem package information
/opt/fluent/bin/fluent-gem list

#-------------------------------------------------------------------------------
# Custom Package Installation [Terraform]
# https://www.terraform.io/docs/cli/install/yum.html
# http://yum.oracle.com/repo/OracleLinux/OL9/developer/x86_64/index.html
#-------------------------------------------------------------------------------

# Repository Configuration (HashiCorp Linux Repository)
dnf config-manager --add-repo "https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo"

cat /etc/yum.repos.d/hashicorp.repo

# Cleanup repository information
dnf clean all

# HashiCorp Linux repository package [dnf command]
dnf repository-packages hashicorp list > /tmp/command-log_dnf_repository-package-list_hashicorp.txt

# Package Install Infrastructure as Code (IaC) Tools (from HashiCorp Linux Repository)
dnf --enablerepo="hashicorp" -y install terraform

# Package Install Infrastructure as Code (IaC) Tools (from Oracle Linux Repository)
dnf --enablerepo="ol9_developer" -y install terraform-provider-oci

rpm -qi terraform

terraform version

# Configure terraform software

## terraform -install-autocomplete
cat > /etc/profile.d/terraform.sh << __EOF__
if [ -n "\$BASH_VERSION" ]; then
   complete -C /usr/bin/terraform terraform
fi
__EOF__

source /etc/profile.d/terraform.sh

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
dnf clean all

#-------------------------------------------------------------------------------
# System information collection
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

# Disk Information(MountPoint) [lsblk -f]
lsblk -f

# Disk Information(File System) [df -khT]
df -khT

# Network Information(Network Interface) [ip addr show]
ip addr show

# Network Information(Routing Table) [ip route show]
ip route show

# Network Information(Firewall Service) [firewalld]
if [ $(command -v firewall-cmd) ]; then
	# Network Information(Firewall Service) [systemctl status -l firewalld]
	systemctl status -l firewalld
	# Network Information(Firewall Service) [firewall-cmd --list-all]
	# firewall-cmd --list-all
fi

# Linux Security Information(SELinux) [getenforce] [sestatus]
getenforce

sestatus

#-------------------------------------------------------------------------------
# Configure Amazon Time Sync Service
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
#-------------------------------------------------------------------------------

# Configure NTP Client software (Install chrony Package)
dnf install -y chrony

rpm -qi chrony

if [ $(systemctl is-active chronyd) = "active" ]; then
	systemctl daemon-reload
	systemctl restart chronyd
	sleep 3
	systemctl status -l chronyd
else
	systemctl daemon-reload
	systemctl start chronyd
	sleep 3
	systemctl status -l chronyd
fi

# Configure NTP Client software (Start Daemon chronyd)
if [ $(systemctl is-enabled chronyd) = "disabled" ]; then
	systemctl enable chronyd
	systemctl is-enabled chronyd
fi

# Contents of the configuration file
ChronyConfigFile="/etc/chrony.conf"
cat ${ChronyConfigFile}

# Configure NTP Client software (Enable log settings in Chrony configuration file)
sed -i 's/#log measurements statistics tracking/log measurements statistics tracking/g' ${ChronyConfigFile}

# Configure NTP Client software (Activate Amazon Time Sync Service settings in the Chrony configuration file)
if [ $(cat ${ChronyConfigFile} | grep -ie "169.254.169.123" | wc -l) = "0" ]; then
	echo "NTP server (169.254.169.123) for Amazon Time Sync Service is not configured in the configuration file."

	# Configure the NTP server (169.254.169.123) for Amazon Time Sync Service in the configuration file.
	if [ $(cat ${ChronyConfigFile} | grep -ie ".pool.ntp.org" | wc -l) = "0" ]; then
		# Variables (for editing the Chrony configuration file)
		VAR_CHRONY_NUM="1"

		# Change settings (Chrony configuration file)
		sed -i "${VAR_CHRONY_NUM}"'s/^/# Use the Amazon Time Sync Service.\nserver 169.254.169.123 prefer iburst minpoll 4 maxpoll 4\n\n/' ${ChronyConfigFile}
	else
		# Variables (for editing the Chrony configuration file)
		VAR_CHRONY_STR=$(cat ${ChronyConfigFile} | grep -ie "pool" -ie "server" | tail -n 1)
		VAR_CHRONY_NUM=`expr $(grep -e "$VAR_CHRONY_STR" -n ${ChronyConfigFile} | sed -e 's/:.*//g') + 1`

		# Change settings (Chrony configuration file)
		sed -i "${VAR_CHRONY_NUM}"'s/^/\n# Use the Amazon Time Sync Service.\nserver 169.254.169.123 prefer iburst minpoll 4 maxpoll 4\n\n/' ${ChronyConfigFile}
	fi

	# Contents of the configuration file
	cat ${ChronyConfigFile}
fi

# Configure NTP Client software (Check the status of time synchronization by Chrony)
if [ $(systemctl is-active chronyd) = "active" ]; then
	systemctl daemon-reload
	systemctl restart chronyd
else
	systemctl daemon-reload
	systemctl start chronyd
fi

if [ $(command -v chronyc) ]; then
	sleep 3
	chronyc tracking
	sleep 3
	chronyc sources -v
	sleep 3
	chronyc sourcestats -v
fi

#-------------------------------------------------------------------------------
# Configure Tuned
#-------------------------------------------------------------------------------

# Package Install Tuned (from Oracle Linux Repository)
dnf install -y tuned tuned-utils tuned-profiles-oracle tuned-profiles-mssql

rpm -qi tuned

systemctl daemon-reload

systemctl restart tuned

systemctl status -l tuned

# Configure Tuned software (Start Daemon tuned)
if [ $(systemctl is-enabled tuned) = "disabled" ]; then
	systemctl enable tuned
	systemctl is-enabled tuned
fi

# Configure Tuned software (select profile - aws)
tuned-adm list

tuned-adm active
tuned-adm profile aws
tuned-adm active

#-------------------------------------------------------------------------------
# Configure ACPI daemon (Advanced Configuration and Power Interface)
#-------------------------------------------------------------------------------

# Configure ACPI daemon software (Install acpid Package)
dnf install -y acpid

rpm -qi acpid

systemctl daemon-reload

systemctl restart acpid

systemctl status -l acpid

# Configure NTP Client software (Start Daemon chronyd)
if [ $(systemctl is-enabled acpid) = "disabled" ]; then
	systemctl enable acpid
	systemctl is-enabled acpid
fi

#-------------------------------------------------------------------------------
# Configure Kernel package optimization (Remove RHEL-compatible kernel packages)
#-------------------------------------------------------------------------------

# Show Linux kernel package name Information
if [ $(command -v grubby) ]; then
	DEFAULTKERNEL=$(rpm -qf `grubby --default-kernel` | sed 's/\(.*\)-[0-9].*-.*/\1/')
	echo "Linux kernel package name :" $DEFAULTKERNEL
	grubby --info=ALL
else
	DEFAULTKERNEL=$(rpm -qa | grep -ie `uname -r` | grep -ie "kernel-" | awk '{print length, $0}' | sort -n | head -n 1 | awk '{print $2}')
	echo "Linux kernel package name :" $DEFAULTKERNEL
fi

# Remove RHEL-compatible kernel packages
if [ $(rpm -qa | grep -ie "kernel-core") ]; then
	echo "Remove RHEL-compatible kernel packages"

	# Information on installed kernel packages
	rpm -qa | grep -ie "kernel-" | sort

	# Removing old kernel packages
	dnf remove -y kernel-core
	sleep 5

	# Information on installed kernel packages
	rpm -qa | grep -ie "kernel-" | sort

	# Show Linux Boot Program information
	if [ $(command -v grubby) ]; then
		grubby --info=ALL
	fi
fi

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting SELinux
getenforce
sestatus

if [ $(getenforce) = "Enforcing" ]; then
	# Setting SELinux disabled mode
	#  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index#changing-selinux-modes-at-boot-time_changing-selinux-states-and-modes
	# grubby --info=ALL
	# grubby --update-kernel ALL --args selinux=0
	# grubby --info=ALL

	# Setting SELinux permissive mode
	#  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index#changing-selinux-modes-at-boot-time_changing-selinux-states-and-modes
	grubby --info=ALL
	grubby --update-kernel ALL --args enforcing=0
	grubby --info=ALL

	setenforce 0
	sleep 5
	getenforce
fi

# Setting System crypto policy (Default -> FUTURE)
update-crypto-policies --show
# update-crypto-policies --set FUTURE
# update-crypto-policies --is-applied

# Setting SystemClock and Timezone
if [ "${Timezone}" = "Asia/Tokyo" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl status --all --no-pager
	timedatectl set-timezone Asia/Tokyo
	timedatectl status --all --no-pager
	date
elif [ "${Timezone}" = "UTC" ]; then
	echo "# Setting SystemClock and Timezone -> $Timezone"
	date
	timedatectl status --all --no-pager
	timedatectl set-timezone UTC
	timedatectl status --all --no-pager
	date
else
	echo "# Default SystemClock and Timezone"
	timedatectl status --all --no-pager
	date
fi

# Setting System Language
if [ "${Language}" = "ja_JP.UTF-8" ]; then
	# Custom Package Installation
	dnf install -y langpacks-ja glibc-langpack-ja google-noto-sans-cjk-ttc-fonts google-noto-serif-cjk-ttc-fonts

	echo "# Setting System Language -> $Language"
	locale
	localectl status --no-pager
	localectl list-locales --no-pager | grep ja_
	localectl set-locale LANG=ja_JP.utf8
	localectl status --no-pager
	locale
	strings /etc/locale.conf
	source /etc/locale.conf
elif [ "${Language}" = "en_US.UTF-8" ]; then
	echo "# Setting System Language -> $Language"
	locale
	localectl status --no-pager
	localectl list-locales --no-pager | grep en_
	localectl set-locale LANG=en_US.utf8
	localectl status --no-pager
	locale
	strings /etc/locale.conf
	source /etc/locale.conf
else
	echo "# Default Language"
	locale
	localectl status --no-pager
	strings /etc/locale.conf
fi

# Setting IP Protocol Stack (IPv4 Only) or (IPv4/IPv6 Dual stack)
if [ "${VpcNetwork}" = "IPv4" ]; then
	echo "# Setting IP Protocol Stack -> $VpcNetwork"

	# Disable IPv6 Kernel Module
	grubby --info=ALL
	grubby --update-kernel ALL --args ipv6.disable=1
	grubby --info=ALL

elif [ "${VpcNetwork}" = "IPv6" ]; then
	echo "# Show IP Protocol Stack -> $VpcNetwork"
	echo "# Show IPv6 Network Interface Address"
	ifconfig
	echo "# Show IPv6 Kernel Module"
	lsmod | awk '{print $1}' | grep ipv6
	echo "# Show Network Listen Address and report"
	netstat -an -A inet6
	echo "# Show Network Routing Table"
	netstat -r -A inet6
else
	echo "# Default IP Protocol Stack"
	echo "# Show IPv6 Network Interface Address"
	ifconfig
	echo "# Show IPv6 Kernel Module"
	lsmod | awk '{print $1}' | grep ipv6
	echo "# Show Network Listen Address and report"
	netstat -an -A inet6
	echo "# Show Network Routing Table"
	netstat -r -A inet6
fi

#-------------------------------------------------------------------------------
# Reboot
#-------------------------------------------------------------------------------

# Instance Reboot
reboot
