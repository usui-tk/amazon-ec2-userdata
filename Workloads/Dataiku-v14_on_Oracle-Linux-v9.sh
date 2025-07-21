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

dnf install -y oraclelinux-release-el9 oracle-epel-release-el9 oracle-ocne-release-el9 oraclelinux-developer-release-el9 oracle-instantclient-release-23ai-el9 oracle-java-jdk-release-el9

dnf --enablerepo="*" --verbose clean all

find /etc/yum.repos.d/

# Checking repository information
dnf repolist all
dnf module list

# Enable Yum Repository Data from Oracle Linux YUM repository (yum.oracle.com)
dnf config-manager --set-enabled ol9_baseos_latest
dnf config-manager --set-enabled ol9_UEKR8
dnf config-manager --set-enabled ol9_appstream
dnf config-manager --set-enabled ol9_addons
dnf config-manager --set-enabled ol9_codeready_builder
dnf config-manager --set-enabled ol9_oracle_instantclient23
dnf config-manager --set-enabled ol9_java
dnf config-manager --set-enabled ol9_developer
dnf config-manager --set-enabled ol9_developer_EPEL
dnf config-manager --set-enabled ol9_olcne19
dnf config-manager --set-enabled ol9_ocne

# Disable Yum Repository Data from Oracle Linux YUM repository (yum.oracle.com)
dnf config-manager --set-disabled ol9_UEKR7
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
dnf install -y acpid arptables bash-completion bc bcc bcc-tools bind-utils blktrace bpftool bpftrace bzip2 console-login-helper-messages-motdgen crash-trace-command crypto-policies curl dnf-data dnf-plugins-core dnf-utils dstat ebtables ethtool expect fio gdisk git gnutls-utils hdparm intltool iotop ipcalc iperf3 iproute-tc ipset iptraf-ng jq kexec-tools libbpf-tools libicu libzip-tools linuxptp lsof lvm2 lzop man-pages mc mcelog mdadm mlocate mtr nc net-snmp-utils net-tools nftables nmap nmap-ncat nmstate numactl numatop nvme-cli nvmetcli parted patchutils pmempool policycoreutils psacct psmisc python3-dnf-plugin-versionlock rsync smartmontools sos sos-audit stalld strace symlinks sysfsutils sysstat tcpdump time tlog tmpwatch traceroute tree tzdata unzip usermode util-linux util-linux-user vdo vim-enhanced wget wireshark-cli xfsdump xfsprogs yum-utils zip zsh zstd

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
dnf --enablerepo="ol9_developer_EPEL" install -y aria2 atop bash-color-prompt byobu collectd collectd-utils colordiff colorized-logs crudini dateutils fping glances htop iftop inotify-tools inxi ipv6calc jc lsb_release moreutils moreutils-parallel ncdu nkf nload screen ssh-audit stressapptest unicornscan wdiff yamllint

# Package Install EC2 instance optimization tools (from EPEL Repository)
dnf --enablerepo="ol9_developer_EPEL" install -y amazon-ec2-utils ec2-hibinit-agent ec2-instance-connect

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
#          Building Dataiku Data Science Studio / DSS (v14)                    #
################################################################################
################################################################################
# https://doc.dataiku.com/dss/latest/release_notes/index.html
# https://doc.dataiku.com/dss/latest/installation/custom/index.html
################################################################################

#-------------------------------------------------------------------------------
# Dataiku dependency installation [Java]
# https://doc.dataiku.com/dss/latest/installation/custom/initial-install.html#manual-dependency-installation
#-------------------------------------------------------------------------------
dnf install -y java-17-openjdk java-17-openjdk-devel java-17-openjdk-headless

#-------------------------------------------------------------------------------
# Dataiku dependency installation [nginx]
# https://doc.dataiku.com/dss/latest/installation/custom/initial-install.html#manual-dependency-installation
#-------------------------------------------------------------------------------
dnf module list nginx
dnf module enable nginx:1.26 -y
dnf module install nginx:1.26 -y
dnf module list nginx
nginx -V

# Package Install nginx modules (from EPEL Repository)
# dnf --enablerepo="ol9_developer_EPEL" install -y nginx-mod-headers-more

# nginx Server configuration
cat /etc/nginx/nginx.conf | grep -ie "server" -ie "listen"

sed -i '/listen\s*\[::\]:80;/s/^/#/' "/etc/nginx/nginx.conf"

cat /etc/nginx/nginx.conf | grep -ie "server" -ie "listen"

nginx -t

# Initial setup and automatic startup configuration of the nginx service
if [ $(systemctl is-enabled nginx) = "disabled" ]; then
	systemctl enable nginx --now
	systemctl is-enabled nginx
	systemctl status -l nginx
fi

#-------------------------------------------------------------------------------
# Dataiku dependency installation [nodejs and npm]
#-------------------------------------------------------------------------------
dnf module list nodejs
dnf module enable nodejs:22 -y
dnf module install nodejs:22 -y
dnf module list nodejs
npm -v

#-------------------------------------------------------------------------------
# Dataiku dependency installation [R]
# https://doc.dataiku.com/dss/latest/installation/custom/r.html
#-------------------------------------------------------------------------------
dnf install -y R R-devel R-core R-core-devel R-java R-java-devel R-highlight

# dnf install -y R-RInside R-RInside-devel R-Rcpp R-Rcpp-devel R-littler R-rJava R-rlecuyer

#-------------------------------------------------------------------------------
# Dataiku dependency installation [Others]
#-------------------------------------------------------------------------------
dnf install -y libcurl-devel libxml2-devel libXScrnSaver mesa-libgbm
dnf install -y pandoc texlive-ec texlive-gsftopk texlive-metafont texlive-updmap-map texlive-xcolor

#-------------------------------------------------------------------------------
# Firewall configuration (Dataiku DSS)
#-------------------------------------------------------------------------------

firewall-cmd --state
firewall-cmd --list-all

firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --permanent --zone=public --add-service=https
firewall-cmd --permanent --zone=public --add-port=10000/tcp

firewall-cmd --reload

firewall-cmd --list-all

#-------------------------------------------------------------------------------
# Download the Dataiku DSS package
# https://cdn.downloads.dataiku.com/public/dss/
#-------------------------------------------------------------------------------

# Change working directory
cd /tmp

# Identification of DSS (v14) version
curl -s https://cdn.downloads.dataiku.com/public/dss/ | grep -oP '(?<=href=")[^"]+' | grep -E '^([0-9]+\.)+[0-9]+/$' | sort -V | grep -ie "14.*"

# Latest version of DSS (v14) version
DssVersion=$(curl -s https://cdn.downloads.dataiku.com/public/dss/ | grep -oP '(?<=href=")[^"]+' | grep -E '^([0-9]+\.)+[0-9]+/$' | sort -V | grep -ie "14.*" | tail -n 1 | sed 's|/$||')

# Debug - DSS (v14) Latest version
echo "$DssVersion"

curl -s https://cdn.downloads.dataiku.com/public/dss/${DssVersion}/ | grep -oP '(?<=href=")[^"]+' | grep -v '^\./$' | awk -v version="$DssVersion" '{print "https://cdn.downloads.dataiku.com/public/dss/" version "/" $1}'

# Download and Extract Archive Files
curl -sS "https://cdn.downloads.dataiku.com/public/dss/$DssVersion/dataiku-dss-$DssVersion.tar.gz" -o "/tmp/dataiku-dss-14.tar.gz"

mkdir -p "/opt/dataiku"
mkdir -p "/opt/dataiku/dss_data"

tar -xzf "/tmp/dataiku-dss-14.tar.gz" -C "/opt/dataiku"
chown -Rh ec2-user:ec2-user "/opt/dataiku"

#-------------------------------------------------------------------------------
# Deploy the Dataiku DSS package
# https://cdn.downloads.dataiku.com/public/dss/
#-------------------------------------------------------------------------------

su ec2-user -c "/opt/dataiku/dataiku-dss-$DssVersion/installer.sh -d /opt/dataiku/dss_data -p 10000"

"/opt/dataiku/dataiku-dss-$DssVersion/scripts/install/install-boot.sh" "/opt/dataiku/dss_data" ec2-user

systemctl daemon-reload

systemctl restart dataiku

systemctl status -l dataiku

# Initial setup and automatic startup configuration of the dataiku service
if [ $(systemctl is-enabled dataiku) = "disabled" ]; then
	systemctl enable dataiku --now
	systemctl is-enabled dataiku
	systemctl status -l dataiku
fi

sleep 3

# Shutdown of the dataiku service
if [ $(systemctl is-active dataiku) = "active" ]; then
	systemctl stop dataiku
	sleep 3
fi

#-------------------------------------------------------------------------------
# Setting up DSS item exports to PDF or images
# https://doc.dataiku.com/dss/latest/installation/custom/graphics-export.html
#-------------------------------------------------------------------------------

su ec2-user -c "/opt/dataiku/dss_data/bin/dssadmin install-graphics-export"

#-------------------------------------------------------------------------------
# Dataiku and R integration
# https://doc.dataiku.com/dss/latest/installation/custom/r.html
#-------------------------------------------------------------------------------

# su ec2-user -c "/opt/dataiku/dss_data/bin/dssadmin install-R-integration"

#-------------------------------------------------------------------------------
# Dataiku dependency installation [Database drivers for Oracle Database]
# https://doc.dataiku.com/dss/latest/installation/custom/jdbc.html
# http://www.oracle.com/technetwork/database/features/jdbc/index-091264.html
#-------------------------------------------------------------------------------

# Oracle Database 23ai (23.4.0.24.05) JDBC Driver / Implements JDBC 4.3 spec and certified with JDK11, JDK17, JDK19, and JDK21
curl -sS "https://download.oracle.com/otn-pub/otn_software/jdbc/234/ojdbc11.jar" -o "/opt/dataiku/dss_data/lib/jdbc/ojdbc11.jar"

# Oracle Database 23ai (23.4.0.24.05) JDBC Driver / Implements JDBC 4.2 spec and certified with JDK8 and JDK11
# curl -sS "https://download.oracle.com/otn-pub/otn_software/jdbc/234/ojdbc8.jar" -o "/opt/dataiku/dss_data/lib/jdbc/ojdbc8.jar"


# Oracle Database 19c (19.23.0.0) JDBC Driver  / Implements JDBC 4.3 spec and certified with JDK11 and JDK17
# curl -sS "https://download.oracle.com/otn-pub/otn_software/jdbc/1923/ojdbc10.jar" -o "/opt/dataiku/dss_data/lib/jdbc/ojdbc10.jar"

# Oracle Database 19c (19.23.0.0) JDBC Driver  / Implements JDBC 4.2 spec and certified with JDK8, JDK11, JDK17, and JDK19
# curl -sS "https://download.oracle.com/otn-pub/otn_software/jdbc/1923/ojdbc8.jar" -o "/opt/dataiku/dss_data/lib/jdbc/ojdbc8.jar"

#-------------------------------------------------------------------------------
# Dataiku dependency installation [Database drivers for MySQL Database]
# https://doc.dataiku.com/dss/latest/installation/custom/jdbc.html
# https://dev.mysql.com/downloads/connector/j/
#-------------------------------------------------------------------------------

dnf install --nogpgcheck -y "https://cdn.mysql.com//Downloads/Connector-J/mysql-connector-j-8.4.0-1.el9.noarch.rpm"

rpm -ql mysql-connector-j

ln -s /usr/share/java/mysql-connector-java.jar /opt/dataiku/dss_data/lib/jdbc/mysql-connector-java.jar

ls -l /opt/dataiku/dss_data/lib/jdbc/mysql-connector-java.jar
ls -l /usr/share/java

#-------------------------------------------------------------------------------
# Dataiku dependency installation [Database drivers for PostgreSQL Database]
# https://doc.dataiku.com/dss/latest/installation/custom/jdbc.html
# https://doc.dataiku.com/dss/latest/installation/custom/jdbc.html#postgresql-support
#-------------------------------------------------------------------------------
dnf module list postgresql
dnf module enable postgresql:16 -y
dnf install -y postgresql postgresql-jdbc
dnf module list postgresql
psql --version

rpm -ql postgresql-jdbc

ln -s /usr/share/java/postgresql-jdbc/postgresql.jar /opt/dataiku/dss_data/lib/jdbc/postgresql.jar

ls -l /opt/dataiku/dss_data/lib/jdbc/postgresql.jar

#-------------------------------------------------------------------------------
# Advanced Java runtime configuration
# https://doc.dataiku.com/dss/latest/installation/custom/advanced-java-customization.html
#-------------------------------------------------------------------------------

cat "/opt/dataiku/dss_data/install.ini"

sed -i 's|backend.xmx = 8g|backend.xmx = 16g|g' "/opt/dataiku/dss_data/install.ini"

cat "/opt/dataiku/dss_data/install.ini"

su ec2-user -c "/opt/dataiku/dss_data/bin/dssadmin regenerate-config"

#-------------------------------------------------------------------------------
# Setting up DSS item exports to PDF or images
#-------------------------------------------------------------------------------

# su ec2-user -c "/opt/dataiku/dss_data/bin/dssadmin verify-installation-integrity"

#-------------------------------------------------------------------------------
# Access to the Dataiku Management Console
#-------------------------------------------------------------------------------
# Connect to Dataiku DSS by opening the following URL in a web browser:
#    http://${Public IP}:10000
# Initial credentials : username = "admin" / password = "admin"
#-------------------------------------------------------------------------------

# Startup of the dataiku service
if [ $(systemctl is-active dataiku) = "inactive" ]; then
	systemctl start dataiku
	sleep 3
	systemctl status -l dataiku
fi

#-------------------------------------------------------------------------------
# Reboot
#-------------------------------------------------------------------------------

# Instance Reboot
reboot
