#!/bin/bash -v

set -e -x

# Logger
exec > >(tee /var/log/user-data_3rd-bootstrap.log || logger -t user-data -s 2> /dev/console) 2>&1

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

dnf install -y oraclelinux-release-el9 oracle-instantclient-release-23ai-el9 oracle-epel-release-el9 oracle-olcne-release-el9.x86_64 oraclelinux-developer-release-el9
dnf --enablerepo="*" --verbose clean all

find /etc/yum.repos.d/

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

# Package Install Oracle Linux System Administration Tools (from EPEL Repository)
dnf --enablerepo="ol9_developer_EPEL" install -y atop bash-color-prompt byobu collectd collectd-utils colordiff dateutils fping glances htop iftop inotify-tools inxi ipv6calc jc lsb_release moreutils moreutils-parallel ncdu nload screen stressapptest unicornscan wdiff yamllint

# dnf --enablerepo="ol9_developer_EPEL" install -y atop bash-color-prompt bcftools bpytop byobu collectd collectd-utils colordiff dateutils fping glances htop httping iftop inotify-tools inxi ipv6calc jc jnettop lsb_release moreutils moreutils-parallel ncdu nload screen srm stressapptest tcping unicornscan wdiff yamllint

# Package Install EC2 instance optimization tools (from EPEL Repository)
dnf --enablerepo="ol9_developer_EPEL" install -y amazon-ec2-utils ec2-hibinit-agent ec2-instance-connect

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
dnf --enablerepo="*" --verbose clean all

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
# System Setting
#-------------------------------------------------------------------------------

# Setting SELinux
getenforce
sestatus

if [ $(getenforce) = "Enforcing" ]; then
	# Setting SELinux permissive mode
	#  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html-single/using_selinux/index#changing-selinux-modes-at-boot-time_changing-selinux-states-and-modes
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
echo "# Setting SystemClock and Timezone -> Asia/Tokyo"
date
timedatectl status --all --no-pager
timedatectl set-timezone Asia/Tokyo
timedatectl status --all --no-pager
date

# Setting System Language
dnf install -y langpacks-ja glibc-langpack-ja google-noto-sans-cjk-ttc-fonts google-noto-serif-cjk-ttc-fonts

echo "# Setting System Language -> en_US.utf8"
locale
localectl status --no-pager
localectl list-locales --no-pager | grep en_
localectl set-locale LANG=en_US.utf8
localectl status --no-pager
locale
strings /etc/locale.conf
source /etc/locale.conf

# Disable IPv6 Kernel Module
grubby --info=ALL
grubby --update-kernel ALL --args ipv6.disable=1
grubby --info=ALL



################################################################################
################################################################################
#                   Building GitLab Server (v17)                               #
################################################################################
################################################################################
# https://docs.gitlab.com/omnibus/installation/
# https://packages.gitlab.com/gitlab/
################################################################################

#-------------------------------------------------------------------------------
# GitLab Server dependency installation
#-------------------------------------------------------------------------------
dnf install -y curl policycoreutils openssh-server perl

#-------------------------------------------------------------------------------
# GitLab Server dependency installation [Postfix]
#-------------------------------------------------------------------------------
dnf install -y postfix

# Initial setup and automatic startup configuration of the postfix service
if [ $(systemctl is-enabled postfix) = "disabled" ]; then
	systemctl enable postfix --now
	systemctl is-enabled postfix
	systemctl status -l postfix
fi

# Postfix configuration (IPv6 Disable)
cat /etc/postfix/main.cf | grep -ie "inet_protocols"

sed -i "s|inet_protocols = all|inet_protocols = ipv4|g" "/etc/postfix/main.cf"

cat /etc/postfix/main.cf | grep -ie "inet_protocols"

# Restart of the Postfix service
systemctl restart postfix
systemctl status -l postfix

#-------------------------------------------------------------------------------
# Firewall configuration
#-------------------------------------------------------------------------------
firewall-cmd --state
firewall-cmd --list-all

firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --permanent --zone=public --add-service=https
firewall-cmd --reload

firewall-cmd --list-all

#-------------------------------------------------------------------------------
# GitLab Server installation [GitLab Server v17]
#-------------------------------------------------------------------------------

# Configuration scripts for GitLab Server (Enterprise Edition) package repositories
# curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.rpm.sh | bash

# Configuration scripts for GitLab Server (Community Edition) package repositories
curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.rpm.sh | bash
dnf --enablerepo="*" --verbose clean all

dnf repolist enabled

dnf makecache -y

# GitLab Server (Enterprise Edition)
# dnf --showduplicates list gitlab-ee
# dnf install -y gitlab-ee

# GitLab Server (Community Edition)
dnf --showduplicates list gitlab-ce
dnf install -y gitlab-ce

rpm -qi gitlab-ce

# Getting an Instance Metadata Service v2 (IMDS v2) token
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`

if [ -n "$TOKEN" ]; then
	#-----------------------------------------------------------------------
	# Retrieving Metadata Using the Instance Metadata Service v2 (IMDS v2)
	#-----------------------------------------------------------------------

	# Instance MetaData
	PublicIpv4=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/public-ipv4")
	PublicHostname=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s "http://169.254.169.254/latest/meta-data/public-hostname")

	# Debug - URL
	echo "http://$PublicIpv4"
fi

# Update GitLab Server external URL information (using Public IPv4 address assigned by AWS)
if [ -n "$PublicIpv4" ]; then

	# Update GitLab Server external URL information
	cat /etc/gitlab/gitlab.rb | grep -ie "external_url"

	sed -i "s|external_url 'http://gitlab.example.com'|external_url 'http://$PublicIpv4'|g" "/etc/gitlab/gitlab.rb"

	cat /etc/gitlab/gitlab.rb | grep -ie "external_url"

	gitlab-ctl show-config | grep -ie "external_url"

	gitlab-ctl reconfigure

	gitlab-ctl show-config | grep -ie "external_url"

	# gitlab-ctl status

	systemctl status -l gitlab-runsvdir
fi

#-------------------------------------------------------------------------------
# GitLab Server Configuration [GitLab Server v17]
#-------------------------------------------------------------------------------
# SMTP Configuration
# https://docs.gitlab.com/omnibus/settings/smtp.html
#-------------------------------------------------------------------------------
# Troubleshooting
# https://docs.gitlab.com/omnibus/troubleshooting.html
#-------------------------------------------------------------------------------


#-------------------------------------------------------------------------------
# Access to the GitLab Management Console
#-------------------------------------------------------------------------------
# Connect to GitLab Management Console by opening the following URL in a web browser:
#    http://${Public IP}
# Initial credentials : username = "root" / password = [cat /etc/gitlab/initial_root_password]"
#-------------------------------------------------------------------------------

cat /etc/gitlab/initial_root_password

#-------------------------------------------------------------------------------
# Reboot
#-------------------------------------------------------------------------------

# Instance Reboot
reboot
