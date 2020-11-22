#!/bin/bash -v

set -e -x

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - RHEL v6
#    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/
#    https://access.redhat.com/support/policy/updates/extras
#    https://access.redhat.com/articles/1150793
#    https://access.redhat.com/solutions/3358
#
#    https://access.redhat.com/articles/3135121
#
#    https://aws.amazon.com/marketplace/pp/B00CFQWLS6
#
#    [How to synchronize repository on system registered to CDN via subscription-manager]
#    https://access.redhat.com/articles/1355053
#-------------------------------------------------------------------------------

# Logger
exec > >(tee /var/log/user-data_reposync.log || logger -t user-data -s 2> /dev/console) 2>&1

echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Preparing the execution environment for reposync : START"

#-------------------------------------------------------------------------------
# RHEL Default Package Update
#-------------------------------------------------------------------------------

# Red Hat Update Infrastructure Client Package Update
yum clean all
yum install -y yum yum-utils
yum update -y rh-amazon-rhui-client

# Checking repository information
yum repolist all

# Get Yum Repository List (Exclude Yum repository related to "beta, debug, source, test, epel")
repolist=$(yum repolist all | grep -ie "enabled" -ie "disabled" | grep -ve "Loaded plugins" -ve "beta" -ve "debug" -ve "source" -ve "test" -ve "epel" | awk '{print $1}' | awk '{ sub("/.*$",""); print $0; }' | sort)

# Enable Yum Repository Data from RHUI (Red Hat Update Infrastructure)
for repo in $repolist
do
	echo "[Target repository Name (Enable yum repository)] :" $repo
	yum-config-manager --enable ${repo}
	sleep 3
done

# Checking repository information
yum repolist all

# Red Hat Update Infrastructure Client Package Update
yum clean all
yum update -y rh-amazon-rhui-client

# Get Yum Repository List (Exclude Yum repository related to "beta, debug, source, test, epel")
repolist=$(yum repolist all | grep -ie "enabled" -ie "disabled" | grep -ve "Loaded plugins" -ve "beta" -ve "debug" -ve "source" -ve "test" -ve "epel" | awk '{print $1}' | awk '{ sub("/.*$",""); print $0; }' | sort)

# Enable Yum Repository Data from RHUI (Red Hat Update Infrastructure)
for repo in $repolist
do
	echo "[Target repository Name (Enable yum repository)] :" $repo
	yum-config-manager --enable ${repo}
	sleep 3
done

# RHEL/RHUI repository package [yum command]
for repo in $repolist
do
	echo "[Target repository Name (Collect yum repository package list)] :" $repo
	yum --disablerepo="*" --enablerepo=${repo} list available > /tmp/command-log_yum_repository-package-list_${repo}.txt
	sleep 3
done

# yum repository metadata Clean up
yum clean all

# Default Package Update
yum update -y

#-------------------------------------------------------------------------------
# Custom Package Installation [Python3]
#-------------------------------------------------------------------------------

# Package Install Python 3 Runtime (from Red Hat Official Repository)
yum install -y rh-python36 rh-python36-python-pip rh-python36-python-devel rh-python36-python-setuptools rh-python36-python-setuptools rh-python36-python-simplejson rh-python36-python-test rh-python36-python-tools rh-python36-python-virtualenv rh-python36-python-wheel
yum install -y rh-python36-PyYAML rh-python36-python-docutils rh-python36-python-six

# Version Information (Python3/RHSCL)
/opt/rh/rh-python36/root/usr/bin/python3 -V
/opt/rh/rh-python36/root/usr/bin/pip3 -V

# Configuration Python3 Runtime
alternatives --install "/usr/bin/python3" python3 "/opt/rh/rh-python36/root/usr/bin/python3" 1
alternatives --display python3

alternatives --install "/usr/bin/pip3" pip3 "/opt/rh/rh-python36/root/usr/bin/pip3" 1
alternatives --display pip3

#-------------------------------------------------------------------------------
# Custom Package Installation [EPEL]
#-------------------------------------------------------------------------------

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
# yum localinstall -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm

cat > /etc/yum.repos.d/epel-bootstrap.repo << __EOF__
[epel-bootstrap]
name=Bootstrap EPEL
mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-6&arch=\$basearch
failovermethod=priority
enabled=0
gpgcheck=0
__EOF__

yum clean all

yum --enablerepo=epel-bootstrap -y install epel-release

# Delete yum temporary data
rm -f /etc/yum.repos.d/epel-bootstrap.repo
rm -rf /var/cache/yum/x86_64/6Server/epel-bootstrap*

# Disable EPEL yum repository
egrep '^\[|enabled' /etc/yum.repos.d/epel*
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel-*.repo
egrep '^\[|enabled' /etc/yum.repos.d/epel*

# yum repository metadata Clean up
yum clean all

# EPEL repository package [yum command]
yum --disablerepo="*" --enablerepo="epel" list available > /tmp/command-log_yum_repository-package-list_epel.txt

#-------------------------------------------------------------------------------
# Installing packages required for repository synchronization
#-------------------------------------------------------------------------------

# Package Install Yum Repository Administration Tools (from Red Hat Official Repository)
yum install -y createrepo curl yum-utils

# Package Install RHEL System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y bash-completion jq repoview zstd

#-------------------------------------------------------------------------------
# Custom Package Uninstallation [EPEL]
#-------------------------------------------------------------------------------

# Package Uninstall EPEL(Extra Packages for Enterprise Linux) Repository Package
# yum remove -y epel-release

# Delete yum temporary data
# rm -f /etc/yum.repos.d/epel.repo.rpmsave
# rm -rf /var/cache/yum/x86_64/6Server/epel

# yum repository metadata Clean up
# yum clean all

#-------------------------------------------------------------------------------
# Get EC2 Instance MetaData
#-------------------------------------------------------------------------------

# Get EC2 Instance MetaData
AZ=$(curl -s "http://169.254.169.254/latest/meta-data/placement/availability-zone")
Region=$(echo $AZ | sed -e 's/.$//g')
InstanceId=$(curl -s "http://169.254.169.254/latest/meta-data/instance-id")
InstanceType=$(curl -s "http://169.254.169.254/latest/meta-data/instance-type")
PrivateIp=$(curl -s "http://169.254.169.254/latest/meta-data/local-ipv4")
AmiId=$(curl -s "http://169.254.169.254/latest/meta-data/ami-id")

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI/Python3]
# https://docs.aws.amazon.com/cli/latest/userguide/install-bundle.html
#-------------------------------------------------------------------------------

# Package download AWS-CLI v2 Tools (from Bundle Installer)
curl -sS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
unzip -q "/tmp/awscliv2.zip" -d /tmp/

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

# Setting AWS-CLI S3 Configuration
# https://docs.aws.amazon.com/cli/latest/topic/s3-config.html#cli-aws-help-s3-config
aws configure set default.s3.max_concurrent_requests 25
aws configure get default.s3.max_concurrent_requests
aws configure set default.s3.max_queue_size 25000
aws configure get default.s3.max_queue_size

# Getting AWS-CLI default Region & Output format
aws configure list
cat ~/.aws/config

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting SELinux permissive mode
getenforce
sestatus
cat /etc/selinux/config
sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
cat /etc/selinux/config
setenforce 0
getenforce

echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Preparing the execution environment for reposync : COMPLETE"

#-------------------------------------------------------------------------------
# Sync Yum Repository Data from RHUI / EPEL
#-------------------------------------------------------------------------------

echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Sync YUM Repository Data from RHUI / EPEL : START"

# Get Yum Repository List (Exclude Yum repository related to "beta, debug, source, test, epel")
repolist=$(yum repolist all | grep -ie "enabled" -ie "disabled" | grep -ve "Loaded plugins" -ve "beta" -ve "debug" -ve "source" -ve "test" | awk '{print $1}' | awk '{ sub("/.*$",""); print $0; }' | sort)

# Create working directory
Dir="/var/www/html"
mkdir -m 755 -p ${Dir}

# Sync Yum Repository Data from RHUI / EPEL
for repo in $repolist
do
	echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Sync YUM Repository Data from yum repository :" $repo "START"

	# reposync
	start_time=$(date +%s)
	reposync --gpgcheck -l --downloadcomps --download-metadata --newest-only --delete --repoid=${repo} --download_path=${Dir}/ > /tmp/exec-log_reposync_${repo}.log
	end_time=$(date +%s)
	exec_time=$((end_time - start_time))
	echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Sync YUM Repository Data :" $repo "- (execution time : " $exec_time "seconds)"

	echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Sync YUM Repository Data from yum repository :" $repo "COMPLETE"
	echo "#-------------------------------------------------------------------------------"

	sleep 3

	# Disk Information (File System)
	df -khT

	# Check Disk usage (Working Dirctory)
	du -m --max-depth=1 ${Dir}
done

echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Sync YUM Repository Data from RHUI / EPEL : COMPLETE"

#-------------------------------------------------------------------------------
# Create metadata for YUM repository
#-------------------------------------------------------------------------------

echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create metadata for YUM repository : START"

# Create metadata for YUM repository
for repo in $repolist
do
	echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create metadata for YUM repository :" $repo "START"

	# createrepo
	createrepo -s sha256 --checkts --update --workers=2 --groupfile=$Dir/$repo/comps.xml $Dir/$repo

	# modifyrepo (productid)
	if [ -f $Dir/$repo/productid ]; then
		modifyrepo $Dir/$repo/productid $Dir/$repo/repodata/
	fi

	# modifyrepo (updateinfo.xml)
	if [ $(find $Dir/$repo/ -name "*updateinfo.xml*" | grep gz) ]; then
		gunzip -c $(ls -t $Dir/$repo/*updateinfo.xml.gz) > $Dir/$repo/updateinfo.xml
		modifyrepo $Dir/$repo/updateinfo.xml $Dir/$repo/repodata/
	elif [ $(find $Dir/$repo/ -name "*updateinfo.xml*" | grep bz2) ]; then
		bzip2 -cd $(ls -t $Dir/$repo/*updateinfo.xml.bz2) > $Dir/$repo/updateinfo.xml
		modifyrepo $Dir/$repo/updateinfo.xml $Dir/$repo/repodata/
	else
		find $Dir/$repo/ -name "*updateinfo.xml*"
	fi

	echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create metadata for YUM repository :" $repo "COMPLETE"
	echo "#-------------------------------------------------------------------------------"

	sleep 3
done

echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create metadata for YUM repository : COMPLETE"

#-------------------------------------------------------------------------------
# Create Website Index page
#-------------------------------------------------------------------------------

echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create Website Index page : START"

# Create Website Index page
for repo in $repolist
do
	echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create Website Index page :" $repo "START"

	# repoview
	repoview $Dir/$repo/ > /tmp/exec-log_repoview_${repo}.log

	echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create Website Index page :" $repo "COMPLETE"
	echo "#-------------------------------------------------------------------------------"

	sleep 3
done

echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create Website Index page : COMPLETE"

#-------------------------------------------------------------------------------
# Create archive file of clone data of YUM repository
#-------------------------------------------------------------------------------

echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create archive file of clone data of YUM repository : START"

# Create archive directory
Arc="reposync_for_rhel-v6"
mkdir -m 755 -p /tmp/$Arc

# cd archive directory
cd /tmp/$Arc

# Create a copy of the file to be stored in the archive file
echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create a copy of the file to be stored in the archive file : START"
cp -prv $Dir $Arc
echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create a copy of the file to be stored in the archive file : COMPLETE"

# Create an archive file in TAR file format
echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create an archive file in TAR file format : START"
tar cvf $Arc.tar $Arc/
echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create an archive file in TAR file format : COMPLETE"

# Compress an archive file in ZTSD file format
echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Compress an archive file in ZTSD file format : START"
zstd $Arc.tar -o $Arc.zst -v -T0 --ultra
echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Compress an archive file in ZTSD file format : COMPLETE"

echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- [EXEC] Create archive file of clone data of YUM repository : COMPLETE"

#-------------------------------------------------------------------------------
# Upload Yum Repository Data to and S3 Bucket
#-------------------------------------------------------------------------------

# aws ssm get-parameters --names "reposync_for_rhel-v6_s3bucket-name" --output json --region ${Region} | jq  -r '.Parameters[].Value'
# aws ssm get-parameters --names "reposync_for_rhel-v6_s3bucket-name" --query "Parameters[*].{Name:Name,Value:Value}" --output json --region ${Region} | jq  -r '.[].Value'


# Upload to S3 bucket

# aws s3 cp --recursive --acl public-read pkg/ s3://rpm-repos/rhel/6/
# aws s3 sync ~/localrepo s3://yumrepobucket/remoterepo --delete

# Make Public Access

#-------------------------------------------------------------------------------
# Stop instance
#-------------------------------------------------------------------------------

# Shutdown
shutdown -h now
