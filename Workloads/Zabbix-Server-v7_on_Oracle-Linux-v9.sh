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

dnf install -y oraclelinux-release-el9 oracle-instantclient-release-23ai-el9 oracle-epel-release-el9 oracle-ocne-release-el9 oraclelinux-developer-release-el9
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
dnf --enablerepo="ol9_developer_EPEL" install -y aria2 atop bash-color-prompt byobu collectd collectd-utils colordiff dateutils fping glances htop iftop inotify-tools inxi ipv6calc jc lsb_release moreutils moreutils-parallel ncdu nload screen ssh-audit stressapptest unicornscan wdiff yamllint

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
#                   Building Zabbix Server (v7 LTS)                            #
################################################################################
################################################################################
# https://www.zabbix.com/download?zabbix=7.0&os_distribution=oracle_linux&os_version=9&components=server_frontend_agent&db=pgsql&ws=nginx
################################################################################

#-------------------------------------------------------------------------------
# Zabbix Server dependency configuration
# [Restrictions on installation of Zabbix packages via EPEL]
#-------------------------------------------------------------------------------
ls -l /etc/yum.repos.d/

if [ -f "/etc/yum.repos.d/oracle-epel-ol9.repo" ]; then
	cat "/etc/yum.repos.d/oracle-epel-ol9.repo"
	if [ -z "$(grep "excludepkgs" "/etc/yum.repos.d/oracle-epel-ol9.repo")" ]; then
		echo excludepkgs=zabbix\* >> "/etc/yum.repos.d/oracle-epel-ol9.repo"
		cat "/etc/yum.repos.d/oracle-epel-ol9.repo"
	fi
fi

#-------------------------------------------------------------------------------
# Zabbix Server dependency installation for Zabbix reporting [Google Chrome]
#-------------------------------------------------------------------------------
dnf install --nogpgcheck -y "https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm"
dnf --enablerepo="*" --verbose clean all

dnf repolist enabled

dnf makecache -y

dnf repository-packages -y "google-chrome" list

#-------------------------------------------------------------------------------
# Zabbix Server dependency installation [nginx v1.24]
#-------------------------------------------------------------------------------
dnf module list nginx
dnf module enable nginx:1.24 -y
dnf module install nginx:1.24 -y
dnf module list nginx
nginx -V

nginx -t

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
# Zabbix Server dependency installation [PHP v8.2]
#-------------------------------------------------------------------------------
dnf module list php
dnf module enable php:8.2 -y
dnf module install php:8.2 -y
dnf module list php
php -v

# PHP Configuration
# php -i
# php -m
# php --ini
# php --ri Core

#-------------------------------------------------------------------------------
# Zabbix Server dependency installation [PostgreSQL v16]
#-------------------------------------------------------------------------------

# Install the repository RPM:
dnf install --nogpgcheck -y "https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm"
dnf --enablerepo="*" --verbose clean all

dnf repolist enabled
dnf config-manager --set-disabled pgdg15
dnf config-manager --set-disabled pgdg14
dnf config-manager --set-disabled pgdg13
dnf config-manager --set-disabled pgdg12
dnf repolist enabled

dnf makecache -y

dnf repository-packages -y "pgdg-common" list
dnf repository-packages -y "pgdg16" list

# Disable the built-in PostgreSQL module:
dnf module list
dnf -qy module disable postgresql
dnf module list

# Install PostgreSQL:
dnf install -y postgresql16-server postgresql16-contrib postgresql16-docs

# Initial setup and automatic startup configuration of the postgresql service
/usr/pgsql-16/bin/postgresql-16-setup initdb

if [ $(systemctl is-enabled postgresql-16) = "disabled" ]; then
	systemctl enable postgresql-16 --now
	systemctl is-enabled postgresql-16
	systemctl status -l postgresql-16
fi

#-------------------------------------------------------------------------------
# Zabbix Server installation [Zabbix Server v7.0]
# https://repo.zabbix.com/zabbix/7.0/oracle/9/x86_64/
#-------------------------------------------------------------------------------
dnf install --nogpgcheck -y "https://repo.zabbix.com/zabbix/7.0/oracle/9/x86_64/zabbix-release-latest.el9.noarch.rpm"
dnf --enablerepo="*" --verbose clean all

dnf repolist enabled

dnf makecache -y

dnf repository-packages -y "zabbix" list
dnf repository-packages -y "zabbix-non-supported" list

# Zabbix Server (PostgreSQL), Zabbix Web (Nginx), Zabbix Agent
dnf install -y zabbix-server-pgsql zabbix-web-pgsql zabbix-nginx-conf zabbix-sql-scripts zabbix-agent2 zabbix-web-service

# Zabbix Server (PostgreSQL), Zabbix Web (Apache), Zabbix Agent
# dnf install -y zabbix-server-pgsql zabbix-web-pgsql zabbix-apache-conf zabbix-sql-scripts zabbix-agent2 zabbix-web-service

# Zabbix Server (Other)
dnf install -y zabbix-web-japanese zabbix-agent2-plugin-postgresql zabbix-selinux-policy zabbix-get fping

#-------------------------------------------------------------------------------
# Create initial database
#-------------------------------------------------------------------------------
cd /tmp

ZabbixPassword="$(cat /dev/urandom | tr -dc '[:alnum:]' | head -c 16 | tee -a /tmp/postgresql-zabbix.secrets)"

cat > /tmp/create_zabbix_user.sql << __EOF__
create user zabbix password 'PASSWORD';
__EOF__

sed -i "s|PASSWORD|$ZabbixPassword|g" "/tmp/create_zabbix_user.sql"

sudo -u postgres psql --file="/tmp/create_zabbix_user.sql"

sudo -u postgres createdb -O zabbix zabbix

zcat /usr/share/zabbix-sql-scripts/postgresql/server.sql.gz | sudo -u zabbix psql zabbix

# Moving the generated password information file
mv /tmp/postgresql-zabbix.secrets /root/
mv /tmp/create_zabbix_user.sql /root/

#-------------------------------------------------------------------------------
# Firewall configuration (Zabbix Server)
#-------------------------------------------------------------------------------
firewall-cmd --state
firewall-cmd --list-all

firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --permanent --zone=public --add-service=https
firewall-cmd --permanent --zone=public --add-port=10051/tcp

firewall-cmd --reload

firewall-cmd --list-all

#-------------------------------------------------------------------------------
# TimescaleDB installation
# https://docs.timescale.com/self-hosted/latest/install/installation-linux/
#-------------------------------------------------------------------------------

# Repository Configuration
cat > /etc/yum.repos.d/timescale_timescaledb.repo << __EOF__
[timescale_timescaledb]
name=timescale_timescaledb
baseurl=https://packagecloud.io/timescale/timescaledb/el/$(rpm -E %{rhel})/\$basearch
repo_gpgcheck=1
gpgcheck=0
enabled=1
gpgkey=https://packagecloud.io/timescale/timescaledb/gpgkey
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300
__EOF__

cat /etc/yum.repos.d/timescale_timescaledb.repo

# Cleanup repository information
dnf --enablerepo="*" --verbose clean all

dnf repolist enabled

dnf makecache -y

dnf repository-packages -y "timescale_timescaledb" list

# Install TimescaleDB:
dnf install -y timescaledb-2-postgresql-16 timescaledb-2-loader-postgresql-16 timescaledb-toolkit-postgresql-16

# Configure TimescaleDB:
timescaledb-tune --pg-config=/usr/pgsql-16/bin/pg_config --max-conns=125 -yes

# Restart PostgreSQL:
systemctl status -l postgresql-16

systemctl restart postgresql-16

systemctl status -l postgresql-16

# Create TimescaleDB extension:
echo "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;" | sudo -u postgres psql zabbix
cat /usr/share/zabbix-sql-scripts/postgresql/timescaledb/schema.sql | sudo -u zabbix psql zabbix

#-------------------------------------------------------------------------------
# Zabbix Server and Agent2 configuration
#-------------------------------------------------------------------------------

# Zabbix Server configuration
cat /etc/zabbix/zabbix_server.conf | grep -ie "DBPassword" -ie "StartReportWriters" -ie "WebServiceURL" -ie "AllowUnsupportedDBVersions"

sed -i "s|# DBPassword=|DBPassword=$ZabbixPassword|g" "/etc/zabbix/zabbix_server.conf"
sed -i 's|# StartReportWriters=0|StartReportWriters=1|g' "/etc/zabbix/zabbix_server.conf"
sed -i 's|# WebServiceURL=|WebServiceURL=http://localhost:10053/report|g' "/etc/zabbix/zabbix_server.conf"
# [Workaround]
sed -i 's|# AllowUnsupportedDBVersions=0|AllowUnsupportedDBVersions=1|g' "/etc/zabbix/zabbix_server.conf"

cat /etc/zabbix/zabbix_server.conf | grep -ie "DBPassword" -ie "StartReportWriters" -ie "WebServiceURL" -ie "AllowUnsupportedDBVersions"

# Zabbix Agent2 configuration
cat /etc/zabbix/zabbix_agent2.conf | grep -ie "Server=" -ie "ServerActive=" -ie "Hostname="

# Restart and automatic startup configuration of the Zabbix Server-related services
systemctl restart zabbix-server zabbix-web-service zabbix-agent2 nginx php-fpm
systemctl enable zabbix-server zabbix-web-service zabbix-agent2 nginx php-fpm

#-------------------------------------------------------------------------------
# Access to the Zabbix Management Console
#-------------------------------------------------------------------------------
# Connect to Zabbix Management Console by opening the following URL in a web browser:
#    http://${Public IP}
# Initial credentials : username = "Admin" / password = "zabbix"
#-------------------------------------------------------------------------------


#-------------------------------------------------------------------------------
# Zabbix Server optional installation [Grafana]
# https://grafana.com/docs/grafana/latest/setup-grafana/installation/redhat-rhel-fedora/
#-------------------------------------------------------------------------------

# Repository Configuration
cat > /etc/yum.repos.d/grafana.repo << __EOF__
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
__EOF__

# Cleanup repository information
dnf --enablerepo="*" --verbose clean all

dnf repolist enabled

dnf makecache -y

dnf repository-packages -y "grafana" list

# Install Grafana Enterprise:
# dnf --showduplicates list grafana-enterprise
# dnf install -y grafana-enterprise

# Install Grafana OSS:
dnf --showduplicates list grafana
dnf install -y grafana

# Initial setup and automatic startup configuration of the grafana-server service
if [ $(systemctl is-enabled grafana-server) = "disabled" ]; then
	systemctl enable grafana-server --now
	systemctl is-enabled grafana-server
	systemctl status -l grafana-server
fi

# Firewall configuration (Grafana Server)
firewall-cmd --state
firewall-cmd --list-all

firewall-cmd --permanent --zone=public --add-port=3000/tcp

firewall-cmd --reload

firewall-cmd --list-all


# Grafana configuration (plugin installation for Zabbix plugin for Grafana)
# https://grafana.com/docs/plugins/alexanderzobnin-zabbix-app/latest/installation/
grafana-cli plugins list-remote

grafana-cli plugins install alexanderzobnin-zabbix-app

systemctl restart grafana-server
systemctl status -l grafana-server

grafana-cli plugins ls

# Grafana configuration (plugin configuration for Zabbix plugin for Grafana)
# https://grafana.com/docs/plugins/alexanderzobnin-zabbix-app/latest/configuration/


# [Workaround]
# https://github.com/grafana/grafana-zabbix/issues/1834#issuecomment-2156000726

#-------------------------------------------------------------------------------
# Reboot
#-------------------------------------------------------------------------------

# Instance Reboot
reboot
