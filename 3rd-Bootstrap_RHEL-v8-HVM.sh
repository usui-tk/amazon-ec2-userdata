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
CWAgentConfig="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Config_AmazonCloudWatchAgent/AmazonCloudWatchAgent_RHEL-v8-HVM.json"

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - RHEL v8
#    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/
#    https://access.redhat.com/support/policy/updates/extras
#    https://access.redhat.com/support/policy/updates/rhel-app-streams-life-cycle
#    https://access.redhat.com/articles/1150793
#    https://access.redhat.com/solutions/3358
#
#    https://access.redhat.com/articles/3135121
#
#    https://aws.amazon.com/marketplace/pp/B07T4SQ5RZ
#
#-------------------------------------------------------------------------------

# Cleanup repository information
dnf clean all

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
    lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
cat /etc/os-release

cat /etc/redhat-release

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
#  - RHEL v8
#      (RHUI Client Package:rh-amazon-rhui-client)
#
#      Red Hat Dnf/Yum Repository Default Status (Enable/Disable)
#      [Default - Enable]
#          rhel-8-baseos-rhui-rpms
#          rhel-8-appstream-rhui-rpms
#          rhui-client-config-server-8
#      [Default - Disable]
#          rhui-codeready-builder-for-rhel-8-rhui-rpms
#-------------------------------------------------------------------------------
#  - RHEL v8 (HA:High Availability)
#      (RHUI Client Package:rh-amazon-rhui-client-ha)
#
#      Red Hat Yum Repository Default Status (Enable/Disable)
#      [Default - Enable]
#          rhel-8-baseos-rhui-rpms
#          rhel-8-appstream-rhui-rpms
#          rhui-rhel-8-for-x86_64-highavailability-rhui-rpms
#          rhui-client-config-server-8-ha
#      [Default - Disable]
#          rhel-8-supplementary-rhui-rpms
#          rhui-codeready-builder-for-rhel-8-rhui-rpms
#-------------------------------------------------------------------------------
#  - RHEL v8 (SAP Bundle)
#      (RHUI Client Package:rh-amazon-rhui-client-sap-bundle-e4s)
#
#      Red Hat Yum Repository Default Status (Enable/Disable)
#      [Default - Enable]
#          rhel-8-for-x86_64-baseos-e4s-rhui-rpms
#          rhel-8-for-x86_64-appstream-e4s-rhui-rpms
#          rhel-8-for-x86_64-highavailability-e4s-rhui-rpms
#          rhel-8-for-x86_64-sap-netweaver-e4s-rhui-rpms
#          rhel-8-for-x86_64-sap-solutions-e4s-rhui-rpms
#          rhui-client-config-server-8-sap-bundle
#      [Default - Disable]
#          <NONE>
#-------------------------------------------------------------------------------

# Red Hat Update Infrastructure Client Package Update (Supports major version upgrade of RHUI)
dnf --enablerepo="*" --verbose clean all

if [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-sap-bundle-e4s") ]; then
	# RHUI configuration (RHEL-SAP Bundle repository)
	echo "RHUI configuration (RHEL-SAP Bundle repository)"
	rpm -qi rh-amazon-rhui-client-sap-bundle-e4s
	dnf update -y rh-amazon-rhui-client-sap-bundle-e4s
	dnf update -y dnf dnf-data
	dnf --enablerepo="*" --verbose clean all
elif [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-ha") ]; then
	# RHUI configuration (RHEL-High Availability repository)
	echo "RHUI configuration (RHEL-High Availability repository)"
	rpm -qi rh-amazon-rhui-client-ha
	dnf update -y rh-amazon-rhui-client-ha
	dnf update -y dnf dnf-data
	dnf --enablerepo="*" --verbose clean all
elif [ $(rpm -qa | grep -ve "rh-amazon-rhui-client-sap-bundle" -ve "rh-amazon-rhui-client-ha" | grep -ie "rh-amazon-rhui-client") ]; then
	# RHUI configuration (RHEL-Standard repository)
	echo "RHUI configuration (RHEL-Standard repository)"
	rpm -qi rh-amazon-rhui-client
	dnf update -y rh-amazon-rhui-client
	dnf update -y dnf dnf-data
	dnf --enablerepo="*" --verbose clean all
else
	# RHUI configuration (RHEL-Standard repository)
	rpm -qi rh-amazon-rhui-client
	dnf update -y rh-amazon-rhui-client
	dnf update -y dnf dnf-data
	dnf --enablerepo="*" --verbose clean all
fi

# Checking repository information
dnf repolist all
dnf module list

# Get Dnf/Yum Repository List (Exclude Dnf/Yum repository related to "beta, debug, source, test, epel")
repolist=$(dnf repolist all --quiet | grep -ie "enabled" -ie "disabled" | grep -ve "beta" -ve "debug" -ve "source" -ve "test" -ve "epel" | awk '{print $1}' | awk '{ sub("/.*$",""); print $0; }' | sort)

# Enable Dnf/Yum Repository Data from RHUI (Red Hat Update Infrastructure)
for repo in $repolist
do
	echo "[Target repository Name (Enable dnf/yum repository)] :" $repo
	dnf config-manager --set-enabled ${repo}
	sleep 3
done

# Checking repository information
dnf repolist all
dnf module list

# Red Hat Update Infrastructure Client Package Update (Supports minor version upgrade of RHUI)
dnf --enablerepo="*" --verbose clean all

if [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-sap-bundle-e4s") ]; then
	# RHUI configuration (RHEL-SAP Bundle repository)
	echo "RHUI configuration (RHEL-SAP Bundle repository)"
	rpm -qi rh-amazon-rhui-client-sap-bundle-e4s
	dnf update -y rh-amazon-rhui-client-sap-bundle-e4s
	dnf update -y dnf dnf-data
	dnf --enablerepo="*" --verbose clean all
elif [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-ha") ]; then
	# RHUI configuration (RHEL-High Availability repository)
	echo "RHUI configuration (RHEL-High Availability repository)"
	rpm -qi rh-amazon-rhui-client-ha
	dnf update -y rh-amazon-rhui-client-ha
	dnf update -y dnf dnf-data
	dnf --enablerepo="*" --verbose clean all
elif [ $(rpm -qa | grep -ve "rh-amazon-rhui-client-sap-bundle" -ve "rh-amazon-rhui-client-ha" | grep -ie "rh-amazon-rhui-client") ]; then
	# RHUI configuration (RHEL-Standard repository)
	echo "RHUI configuration (RHEL-Standard repository)"
	rpm -qi rh-amazon-rhui-client
	dnf update -y rh-amazon-rhui-client
	dnf update -y dnf dnf-data
	dnf --enablerepo="*" --verbose clean all
else
	# RHUI configuration (RHEL-Standard repository)
	rpm -qi rh-amazon-rhui-client
	dnf update -y rh-amazon-rhui-client
	dnf update -y dnf dnf-data
	dnf --enablerepo="*" --verbose clean all
fi

# Get Dnf/Yum Repository List (Exclude Dnf/Yum repository related to "beta, debug, source, test, epel")
repolist=$(dnf repolist all --quiet | grep -ie "enabled" -ie "disabled" | grep -ve "beta" -ve "debug" -ve "source" -ve "test" -ve "epel" | awk '{print $1}' | awk '{ sub("/.*$",""); print $0; }' | sort)

# Enable Dnf/Yum Repository Data from RHUI (Red Hat Update Infrastructure)
for repo in $repolist
do
	echo "[Target repository Name (Enable dnf/yum repository)] :" $repo
	dnf config-manager --set-enabled ${repo}
	sleep 3
done

# Checking repository information
dnf repolist all
dnf module list

# RHEL/RHUI repository package [dnf command]
for repo in $repolist
do
	echo "[Target repository Name (Collect dnf/yum repository package list)] :" $repo
	dnf repository-packages ${repo} list > /tmp/command-log_dnf_repository-package-list_${repo}.txt
	sleep 3
done

# Cleanup repository information
dnf --enablerepo="*" --verbose clean all

# Default Package Update
dnf update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install RHEL Linux-Kernel Modules (from Red Hat Official Repository)
dnf install -y kernel-modules kernel-modules-extra

# Package Install RHEL System Administration Tools (from Red Hat Official Repository)
dnf install -y abrt abrt-cli acpid arptables bash-completion bc bcc bcc-tools bind-utils blktrace bpftool bpftrace crash-trace-command crypto-policies curl dnf-data dnf-plugins-core dnf-utils dstat ebtables ethtool expect fio gdisk git gnutls-utils hdparm intltool iotop ipcalc iperf3 iproute-tc ipset iptraf-ng jq kexec-tools libicu linuxptp lsof lvm2 lzop man-pages mc mcelog mdadm mlocate mtr nc ncompress net-snmp-utils net-tools nftables nmap nmap-ncat nmstate numactl nvme-cli nvmetcli parted patchutils pmempool psacct psmisc python3-dnf-plugin-versionlock rsync smartmontools sos sos-audit stalld strace symlinks sysfsutils sysstat tcpdump time tlog tmpwatch traceroute tree tzdata unzip usermode util-linux util-linux-user vdo vim-enhanced wget wireshark-cli xfsdump xfsprogs yum-utils zip zsh zstd
dnf install -y cifs-utils nfs-utils nfs4-acl-tools
dnf install -y iscsi-initiator-utils lsscsi sg3_utils stratisd stratis-cli
dnf install -y "selinux-policy*" checkpolicy policycoreutils policycoreutils-python-utils policycoreutils-restorecond setools-console setools-console-analyses setroubleshoot-server udica
dnf install -y pcp pcp-export-pcp2json pcp-manager "pcp-pmda*" pcp-selinux pcp-system-tools pcp-zeroconf

# Package Install Red Hat Enterprise Linux support tools (from Red Hat Official Repository)
dnf install -y redhat-lsb-core redhat-support-tool insights-client rhel-system-roles

# Package Install RHEL-SAP System Administration Tools (from Red Hat Official Repository)
if [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-sap-bundle-e4s") ]; then
	dnf install -y sapconf
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [kernel live-patching tools]
# https://access.redhat.com/solutions/2206511
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_monitoring_and_updating_the_kernel/applying-patches-with-kernel-live-patching_managing-monitoring-and-updating-the-kernel
#-------------------------------------------------------------------------------

# Package Install Red Hat Enterprise Linux kernel live-patching tools (from Red Hat Official Repository)
dnf install -y kpatch kpatch-dnf

rpm -qi kpatch

systemctl daemon-reload

systemctl restart kpatch

systemctl status -l kpatch

# Configure kpatch software (Start Daemon kpatch)
if [ $(systemctl is-enabled kpatch) = "disabled" ]; then
	systemctl enable kpatch
	systemctl is-enabled kpatch
fi

# kpatch information
kpatch list

# Package List (kernel live-patch)
dnf list installed | grep kpatch

#-------------------------------------------------------------------------------
# Custom Package Installation [Cockpit]
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_systems_using_the_rhel_8_web_console/index
#-------------------------------------------------------------------------------

# Package Install Red Hat Enterprise Linux Web-Based support tools (from Red Hat Official Repository)
dnf install -y cockpit cockpit-dashboard cockpit-packagekit cockpit-session-recording cockpit-storaged cockpit-system cockpit-ws

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
# Custom Package Installation [Python 3.6]
#-------------------------------------------------------------------------------

# DNF-Module Enable Python 3.6 Runtime (from Red Hat Official Repository)
dnf module list | grep python3
dnf install -y @python36
dnf module list | grep python3

# Package Install Python 3.6 Runtime (from Red Hat Official Repository)
dnf install -y python3 python3-pip python3-rpm-generators python3-rpm-macros python3-setuptools python3-test python3-virtualenv python3-wheel
dnf install -y python3-asn1crypto python3-dateutil python3-docutils python3-humanize python3-jmespath python3-pyasn1 python3-pyasn1-modules python3-pyyaml python3-six python3-urllib3
dnf install -y python3-argcomplete

# Version Information (Python 3.6)
python3 -V
pip3 -V

# Python package introduction and setting
alternatives --list
alternatives --set python "/usr/bin/python3"
alternatives --list

which python
python --version

# Python package setting (python3-argcomplete)
activate-global-python-argcomplete

#-------------------------------------------------------------------------------
# Custom Package Installation [Python 3.9]
#-------------------------------------------------------------------------------

# DNF-Module Enable Python 3.9 Runtime (from Red Hat Official Repository)
# dnf module list | grep python3
# dnf install -y @python39
# dnf module list | grep python3

# Package Install Python 3.9 Runtime (from Red Hat Official Repository)
# dnf install -y python39 python39-devel python39-pip python39-rpm-macros python39-setuptools python39-test python39-wheel
# dnf install -y python39-pyyaml python39-six python39-urllib3

# Version Information (Python 3.9)
# python3.9 -V
# pip3.9 -V

#-------------------------------------------------------------------------------
# Custom Package Installation [EPEL]
#-------------------------------------------------------------------------------

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
# dnf localinstall -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm"

cat > /etc/yum.repos.d/epel-bootstrap.repo << __EOF__
[epel-bootstrap]
name=Extra Packages for Enterprise Linux \$releasever - \$basearch
#baseurl=https://download.fedoraproject.org/pub/epel/\$releasever/Everything/\$basearch
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-\$releasever&arch=\$basearch&infra=\$infra&content=\$contentdir
failovermethod=priority
enabled=0
gpgcheck=0
__EOF__

dnf clean all

if [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-sap-bundle-e4s") ]; then
	################################################################################
	# [Workaround] EPEL Repository Configuration for RHEL-SAP Bundle
	################################################################################

	# Install EPEL yum repository
	dnf localinstall -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm"

	# [Workaround] Fixed values for variables ($releasever)
	if [ $(grep -l '$releasever' /etc/yum.repos.d/epel* | wc -l) != "0" ]; then
		grep -l '$releasever' /etc/yum.repos.d/epel* | xargs sed -i -e 's|$releasever|8|g'
	fi

	# Delete dnf/yum temporary data
	rm -f /etc/yum.repos.d/epel-bootstrap.repo
else
	# Install EPEL yum repository
	dnf --enablerepo="epel-bootstrap" -y install epel-release

	# Delete dnf/yum temporary data
	rm -f /etc/yum.repos.d/epel-bootstrap.repo
	rm -rf /var/cache/dnf/epel-bootstrap*
fi

# Disable EPEL yum repository
egrep '^\[|enabled' /etc/yum.repos.d/epel*
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel-*.repo
egrep '^\[|enabled' /etc/yum.repos.d/epel*

# Cleanup repository information
dnf --enablerepo="*" --verbose clean all

# EPEL repository package [dnf command]
dnf repository-packages epel list > /tmp/command-log_dnf_repository-package-list_epel.txt
dnf repository-packages epel-modular list > /tmp/command-log_dnf_repository-package-list_epel-modular.txt
dnf repository-packages epel-testing list > /tmp/command-log_dnf_repository-package-list_epel-testing.txt
dnf repository-packages epel-testing-modular list > /tmp/command-log_dnf_repository-package-list_epel-testing-modular.txt

# Package Install RHEL System Administration Tools (from EPEL Repository)
if [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-sap-bundle-e4s") ]; then
	# Utilities to be installed from the EPEL repository (RHEL-SAP Bundle)
	dnf --enablerepo="epel" install -y atop bcftools bpytop byobu collectd collectd-utils colordiff dateutils fping glances htop httping iftop inotify-tools inxi ipv6calc ncdu nload screen srm stressapptest tcping unicornscan wdiff yamllint
else
	# Utilities to be installed from the EPEL repository
	dnf --enablerepo="epel" install -y atop bcftools bpytop byobu collectd collectd-utils colordiff dateutils fping glances htop httping iftop inotify-tools inxi ipv6calc moreutils moreutils-parallel ncdu nload screen srm stressapptest tcping unicornscan wdiff yamllint
fi

# Package Install EC2 instance optimization tools (from EPEL Repository)
dnf --enablerepo="epel" install -y ec2-hibinit-agent

# Package Install RHEL System Administration Tools (from EPEL-Playground Repository)
# dnf --enablerepo="epel-playground" install -y jnettop

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

# Package download AWS-CLI v2 Tools (from Bundle Installer)
curl -sS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
unzip -oq "/tmp/awscliv2.zip" -d /tmp/

# Package Install AWS-CLI v2 Tools (from Bundle Installer)
/tmp/aws/install -i "/opt/aws/awscli" -b "/usr/bin" --update

aws --version

# Configuration AWS-CLI tools
cat > /etc/bash_completion.d/aws_bash_completer << __EOF__
# Typically that would be added under one of the following paths:
# - /etc/bash_completion.d
# - /usr/local/etc/bash_completion.d
# - /usr/share/bash-completion/completions

complete -C aws_completer aws
__EOF__

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

# Get AWS Region Information
if [ -n "$RoleName" ]; then
	echo "# Get AWS Region Infomation"
	aws ec2 describe-regions --region ${Region}
fi

# Get AMI information of this EC2 instance
if [ -n "$RoleName" ]; then
	echo "# Get AMI information of this EC2 instance"
	aws ec2 describe-images --image-ids ${AmiId} --output json --region ${Region}
fi

# Get the latest AMI information of the OS type of this EC2 instance from Public AMI
if [ -n "$RoleName" ]; then
	if [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-sap-bundle-e4s") ]; then
		# Get Newest AMI Information from Public AMI (RHEL-SAP Bundle)
		echo "# Get Newest AMI Information from Public AMI (RHEL-SAP Bundle)"
		LatestAmiId=$(aws ec2 describe-images --owner "679593333241" --filters "Name=name,Values=RHEL-8.?.0-SAP-HVM*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)' --output json --region ${Region} | jq -r '[.[] | select(contains({Name: "BETA"}) | not)] | .[0].ImageId')
		aws ec2 describe-images --image-ids ${LatestAmiId} --output json --region ${Region}
	elif [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-ha") ]; then
		# Get Newest AMI Information from Public AMI (RHEL-HA)
		echo "# Get Newest AMI Information from Public AMI (RHEL-HA)"
		LatestAmiId=$(aws ec2 describe-images --owner "309956199498" --filters "Name=name,Values=RHEL_HA-8.*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)' --output json --region ${Region} | jq -r '[.[] | select(contains({Name: "BETA"}) | not)] | .[0].ImageId')
		aws ec2 describe-images --image-ids ${LatestAmiId} --output json --region ${Region}
	elif [ $(rpm -qa | grep -ve "rh-amazon-rhui-client-sap-bundle-e4s" -ve "rh-amazon-rhui-client-ha" | grep -ie "rh-amazon-rhui-client") ]; then
		# Get Newest AMI Information from Public AMI (RHEL)
		echo "# Get Newest AMI Information from Public AMI (RHEL)"
		LatestAmiId=$(aws ec2 describe-images --owner "309956199498" --filters "Name=name,Values=RHEL-8.*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)' --output json --region ${Region} | jq -r '[.[] | select(contains({Name: "BETA"}) | not)] | .[0].ImageId')
		aws ec2 describe-images --image-ids ${LatestAmiId} --output json --region ${Region}
	else
		# Get Newest AMI Information from Public AMI (RHEL)
		echo "# Get Newest AMI Information from Public AMI (RHEL)"
		LatestAmiId=$(aws ec2 describe-images --owner "309956199498" --filters "Name=name,Values=RHEL-8.*" "Name=virtualization-type,Values=hvm" "Name=architecture,Values=x86_64" --query 'sort_by(Images[].{YMD:CreationDate,Name:Name,ImageId:ImageId},&YMD)|reverse(@)' --output json --region ${Region} | jq -r '[.[] | select(contains({Name: "BETA"}) | not)] | .[0].ImageId')
		aws ec2 describe-images --image-ids ${LatestAmiId} --output json --region ${Region}
	fi
fi

# Get the AMI information of the RHEL from Public AMI
if [ -n "$RoleName" ]; then
	# Get the AMI information of the RHEL from Public AMI (RHEL v8)
	echo "# Get the AMI information of the RHEL from Public AMI (RHEL v8)"
	aws ec2 describe-images --owners "309956199498" --query 'sort_by(Images, &CreationDate)[*].[CreationDate,Name,ImageId]' --filters "Name=name,Values=RHEL-8.*" --output table --region ${Region}
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

# Get EC2 Instance attached VPC Security Group Information
if [ -n "$RoleName" ]; then
	echo "# Get EC2 Instance attached VPC Security Group Information"
	aws ec2 describe-security-groups --group-ids $(aws ec2 describe-instances --instance-id ${InstanceId} --query "Reservations[].Instances[].SecurityGroups[].GroupId[]" --output text --region ${Region}) --output json --region ${Region}
fi

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
#
# - Summary of Networking and Storage Features
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#instance-type-summary-table
# - ENA (Elastic Network Adapter)
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
# - SR-IOV
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sriov-networking.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(a1.*|c5.*|c5a.*|c5ad.*|c5adn.*|c5an.*|c5d.*|c5n.*|e3.*|f1.*|g3.*|g3s.*|g4dn.*|h1.*|i3.*|i3en.*|i3p.*|m5.*|m5a.*|m5ad.*|m5d.*|m5dn.*|m5n.*|p2.*|p3.*|p3dn.*|r4.*|r5.*|r5a.*|r5ad.*|r5d.*|r5dn.*|r5n.*|t3.*|t3a.*|x1.*|x1e.*|z1d.*|m4.16xlarge|u-*tb1.metal)$ ]]; then
		# Get EC2 Instance Attribute(Elastic Network Adapter Status)
		echo "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
		aws ec2 describe-instances --instance-id ${InstanceId} --query Reservations[].Instances[].EnaSupport --output json --region ${Region}

		# Get Linux Kernel Module(modinfo ena)
		echo "# Get Linux Kernel Module(modinfo ena)"
		if [ $(lsmod | awk '{print $1}' | grep -x ena) ]; then
			modinfo ena
		fi
	elif [[ "$InstanceType" =~ ^(c3.*|c4.*|d2.*|i2.*|r3.*|m4.*)$ ]]; then
		# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
		echo "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}

		# Get Linux Kernel Module(modinfo ixgbevf)
		echo "# Get Linux Kernel Module(modinfo ixgbevf)"
		if [ $(lsmod | awk '{print $1}' | grep -x ixgbevf) ]; then
			modinfo ixgbevf
		fi
	else
		echo "# Not Target Instance Type :" $InstanceType
	fi
fi

# Get EC2 Instance Attribute[Storage Interface Performance Attribute]
#
# - Summary of Networking and Storage Features
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#instance-type-summary-table
# - EBS Optimized Instance
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSOptimized.html
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSPerformance.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(a1.*|c1.*|c3.*|c4.*|c5.*|c5a.*|c5ad.*|c5adn.*|c5an.*|c5d.*|c5n.*|d2.*|e3.*|f1.*|g2.*|g3.*|g3s.*|g4dn.*|h1.*|i2.*|i3.*|i3en.*|i3p.*|m1.*|m2.*|m3.*|m4.*|m5.*|m5a.*|m5ad.*|m5d.*|m5dn.*|m5n.*|p2.*|p3.*|p3dn.*|r3.*|r4.*|r5.*|r5a.*|r5ad.*|r5d.*|r5dn.*|r5n.*|t3.*|t3a.*|x1.*|x1e.*|z1d.*|u-*tb1.metal)$ ]]; then
		# Get EC2 Instance Attribute(EBS-optimized instance Status)
		echo "# Get EC2 Instance Attribute(EBS-optimized instance Status)"
		aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute ebsOptimized --output json --region ${Region}

		# Get Linux Block Device Read-Ahead Value(blockdev --report)
		echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
		blockdev --report
	else
		# Get Linux Block Device Read-Ahead Value(blockdev --report)
		echo "# Get Linux Block Device Read-Ahead Value(blockdev --report)"
		blockdev --report
	fi
fi

# Get EC2 Instance attached NVMe Device Information
#
# - Summary of Networking and Storage Features
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#instance-type-summary-table
#
# - Nitro-based Instances
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#ec2-nitro-instances
# - Amazon EBS and NVMe Volumes
#   http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nvme-ebs-volumes.html
# - SSD Instance Store Volumes
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ssd-instance-store.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(a1.*|c5.*|c5a.*|c5ad.*|c5adn.*|c5an.*|c5d.*|c5n.*|f1.*|g4dn.*|i3.*|i3en.*|i3p.*|m5.*|m5a.*|m5ad.*|m5d.*|m5dn.*|m5n.*|p3dn.*|r5.*|r5a.*|r5ad.*|r5d.*|r5dn.*|r5n.*|t3.*|t3a.*|z1d.*|u-*tb1.metal)$ ]]; then

		# Get Linux Kernel Module(modinfo nvme)
		echo "# Get Linux Kernel Module(modinfo nvme)"
		if [ $(lsmod | awk '{print $1}' | grep -x nvme) ]; then
			modinfo nvme
		fi

		# Get NVMe Device(nvme list)
		# http://www.spdk.io/doc/nvme-cli.html
		# https://github.com/linux-nvme/nvme-cli
		if [ $(lsmod | awk '{print $1}' | grep -x nvme) ]; then
			if [ $(command -v nvme) ]; then
				echo "# Get NVMe Device(nvme list)"
				nvme list
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

	else
		echo "# Not Target Instance Type :" $InstanceType
	fi
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

dnf install --nogpgcheck -y "https://s3.amazonaws.com/amazoncloudwatch-agent/redhat/amd64/latest/amazon-cloudwatch-agent.rpm"

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

# Configure Amazon CloudWatch Agent software (OpenTelemetry Collector settings)
/usr/bin/amazon-cloudwatch-agent-ctl -a fetch-config -o default -s

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

# Cleanup repository information
dnf --enablerepo="*" --verbose clean all

# Package Install RHEL System Administration Tools (from Red Hat Official Repository)
# dnf install -y ansible ansible-doc rhel-system-roles

if [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-sap-bundle-e4s") ]; then
	# Package Install Ansible (from Red Hat Official Repository)
	dnf install -y ansible rhel-system-roles-sap

	rpm -qi ansible

	ansible --version

	ansible localhost -m setup
else
	if [ $(dnf repolist all --quiet | grep -ie "enabled" -ie "disabled" | grep -ve "beta" -ve "debug" -ve "source" -ve "test" -ve "epel" | awk '{print $1}' | grep -ie  "ansible-2-for-rhel-8-rhui-rpms") ]; then
		# Package Install Ansible (from Red Hat Official Repository)
		dnf install -y ansible

		ansible --version

		ansible localhost -m setup
	else
		# Package Install Ansible (from EPEL Repository)
		dnf --enablerepo="epel" install -y ansible ansible-doc

		ansible --version

		ansible localhost -m setup
	fi
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [fluentd]
# https://docs.fluentd.org/installation/install-by-rpm
#-------------------------------------------------------------------------------

if [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-sap-bundle-e4s") ]; then
	################################################################################
	# [Workaround] TreasureData Repository Configuration for RHEL-SAP Bundle
	################################################################################

	# add GPG key
	rpm --import "https://packages.treasuredata.com/GPG-KEY-td-agent"

	# add treasure data repository to yum
	echo "[treasuredata]" > /etc/yum.repos.d/td.repo
	echo "name=TreasureData" >> /etc/yum.repos.d/td.repo
	echo "baseurl=http://packages.treasuredata.com/4/redhat/8/\$basearch" >> /etc/yum.repos.d/td.repo
	echo "gpgcheck=1" >> /etc/yum.repos.d/td.repo
	echo "gpgkey=https://packages.treasuredata.com/GPG-KEY-td-agent" >> /etc/yum.repos.d/td.repo

	# Cleanup repository information
	dnf --enablerepo="*" --verbose clean all

	# Package Install fluentd (from fluentd Official Repository)
	dnf --enablerepo="treasuredata" install -y td-agent
else
	# Package Install fluentd (Setup with vendor installation scripts)
	curl -fsSL "https://toolbelt.treasuredata.com/sh/install-redhat-td-agent4.sh" | sh
fi

rpm -qi td-agent

systemctl daemon-reload

systemctl restart td-agent

systemctl status -l td-agent

# Configure fluentd software (Start Daemon td-agent)
if [ $(systemctl is-enabled td-agent) = "disabled" ]; then
	systemctl enable td-agent
	systemctl is-enabled td-agent
fi

# Package bundled ruby gem package information
/opt/td-agent/bin/fluent-gem list

#-------------------------------------------------------------------------------
# Custom Package Installation [Terraform]
# https://www.terraform.io/docs/cli/install/yum.html
#-------------------------------------------------------------------------------

# Repository Configuration (HashiCorp Linux Repository)
dnf config-manager --add-repo "https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo"

if [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-sap-bundle-e4s") ]; then
	################################################################################
	# [Workaround] HashiCorp Repository Configuration for RHEL-SAP Bundle
	################################################################################

	# Check the repository configuration file
	cat /etc/yum.repos.d/hashicorp.repo

	# [Workaround] Fixed values for variables ($releasever)
	if [ $(grep -l '$releasever' /etc/yum.repos.d/hashicorp.repo | wc -l) != "0" ]; then
		grep -l '$releasever' /etc/yum.repos.d/hashicorp.repo | xargs sed -i -e 's|$releasever|8|g'
	fi

	# Check the repository configuration file
	cat /etc/yum.repos.d/hashicorp.repo
else
	# Check the repository configuration file
	cat /etc/yum.repos.d/hashicorp.repo
fi

# Cleanup repository information
dnf --enablerepo="*" --verbose clean all

# HashiCorp Linux repository package [dnf command]
dnf repository-packages hashicorp list > /tmp/command-log_dnf_repository-package-list_hashicorp.txt

# Package Install Infrastructure as Code (IaC) Tools (from HashiCorp Linux Repository)
dnf --enablerepo="hashicorp" -y install terraform

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

# Package Install Tuned (from Red Hat Official Repository)
if [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-sap-bundle-e4s") ]; then
	dnf install -y tuned tuned-utils tuned-profiles-oracle tuned-profiles-mssql tuned-profiles-sap tuned-profiles-sap-hana
else
	dnf install -y tuned tuned-utils tuned-profiles-oracle tuned-profiles-mssql
fi

rpm -qi tuned

systemctl daemon-reload

systemctl restart tuned

systemctl status -l tuned

# Configure Tuned software (Start Daemon tuned)
if [ $(systemctl is-enabled tuned) = "disabled" ]; then
	systemctl enable tuned
	systemctl is-enabled tuned
fi

# Configure Tuned software (select profile - throughput-performance)
tuned-adm list

tuned-adm active

if [ $(rpm -qa | grep -ie "rh-amazon-rhui-client-sap-bundle-e4s") ]; then
	# tuned-adm profile sap-netweaver
	# tuned-adm profile sap-hana
	tuned-adm profile throughput-performance
else
	tuned-adm profile throughput-performance
fi

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
# System Setting
#-------------------------------------------------------------------------------

# Setting SELinux permissive mode
getenforce
sestatus

cat /etc/selinux/config
sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
cat /etc/selinux/config

if [ $(getenforce) = "Enforcing" ]; then
	setenforce 0
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
	echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf

	# Disable IPv6 Kernel Parameter
	sysctl -a

	DisableIPv6Conf="/etc/sysctl.d/90-ipv6-disable.conf"

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
