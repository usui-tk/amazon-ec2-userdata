#!/bin/bash -v

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Network Driver(ena)]
#
# Target Linux Distribution
#  - Red Hat Enterprise Linux v6.x
#  - CentOS v6.x
#
# Reference
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/instance-types.html
#  https://github.com/amzn/amzn-drivers
#  https://github.com/amzn/amzn-drivers/releases
#  https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/rpm/README-rpm.txt
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Parameter definition [Amazon Network Driver(ena)]
#-------------------------------------------------------------------------------

# Source code acquisition URL and definition of file name and version information
SourceUrl="https://github.com/amzn/amzn-drivers/archive/ena_linux_2.2.11.tar.gz"
SourceFile=$(echo ${SourceUrl##*/})
SourceVersion=$(echo $SourceFile | sed -nre 's/^[^0-9]*(([0-9]+\.)*[0-9]+).*/\1/p')

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

# IAM Role Information
if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
	RoleArn=$(curl -s "http://169.254.169.254/latest/meta-data/iam/info" | jq -r '.InstanceProfileArn')
	RoleName=$(echo $RoleArn | cut -d '/' -f 2)
fi

#-------------------------------------------------------------------------------
# Install Kernel module and Configure Dynamic Kernel Module Support (DKMS)
#-------------------------------------------------------------------------------

# Operating system support status of AWS Nitro Hypervisor (Before - Install ENA Kernel module)
# https://github.com/awslabs/aws-support-tools/tree/master/EC2/NitroInstanceChecks

TestScriptUrl="https://raw.githubusercontent.com/awslabs/aws-support-tools/master/EC2/NitroInstanceChecks/nitro_check_script.sh"

Result=`curl -LI ${TestScriptUrl} -w '%{http_code}\n' -s -o /dev/null`
if [ "${Result}" = 200 ]; then
	echo "Successful file existence check :" ${TestScriptUrl}
	curl -fsSL ${TestScriptUrl} | bash
fi

# Package Install Kernel Module
eval $(grep ^DEFAULTKERNEL= /etc/sysconfig/kernel)
if [ -n "$DEFAULTKERNEL" ]; then
	echo "Linux Kernel Package Name :" $DEFAULTKERNEL
	yum install -y ${DEFAULTKERNEL}-devel-$(uname -r) ${DEFAULTKERNEL}-headers-$(uname -r)
else
	yum install -y kernel-devel-$(uname -r) kernel-headers-$(uname -r)
fi

# Package Install Build Tool
yum install -y gcc make rpm-build rpmdevtools
# yum groupinstall -y "Development tools"

# Package Install DKMS (from EPEL Repository)
yum --enablerepo=epel install -y dkms

# Set Grub2 Parameter for RHEL v7.x/CentOS v7.x
if [ $(command -v grub2-mkconfig) ]; then
	rpm -qa | grep -e '^systemd-[0-9]\+\|^udev-[0-9]\+'
	sed -i '/^GRUB_CMDLINE_LINUX/s/"$/ net.ifnames=0"/' /etc/default/grub
	grub2-mkconfig -o /boot/grub2/grub.cfg
fi

# Get Amazon ENA Driver source code
curl -LsS "${SourceUrl}" -o "/usr/src/${SourceFile}"

cd /usr/src
tar xzf ${SourceFile}
rm -fr ${SourceFile}

mv "amzn-drivers-ena_linux_${SourceVersion}" "amzn-drivers-${SourceVersion}"
cd "amzn-drivers-${SourceVersion}"

cat > dkms.conf << __EOF__
PACKAGE_NAME="ena"
PACKAGE_VERSION="TEMP-VERSION"
CLEAN="make -C kernel/linux/ena clean"
MAKE="make -C kernel/linux/ena/ BUILD_KERNEL=\${kernelver}"
BUILT_MODULE_NAME[0]="ena"
BUILT_MODULE_LOCATION="kernel/linux/ena"
DEST_MODULE_LOCATION[0]="/updates"
DEST_MODULE_NAME[0]="ena"
AUTOINSTALL="yes"
__EOF__

sed -i 's/TEMP-VERSION/'${SourceVersion}'/g' dkms.conf

# Make & Build & Install Amazon ENA Driver
date; dkms add -m amzn-drivers -v ${SourceVersion}; date

date; dkms build -m amzn-drivers -v ${SourceVersion}; date

date; dkms install -m amzn-drivers -v ${SourceVersion}; date

modinfo ena

# Operating system support status of AWS Nitro Hypervisor (After - Install ENA Kernel module)
# https://github.com/awslabs/aws-support-tools/tree/master/EC2/C5M5InstanceChecks

# TestScriptUrl="https://raw.githubusercontent.com/awslabs/aws-support-tools/master/EC2/NitroInstanceChecks/nitro_check_script.sh"

Result=`curl -LI ${TestScriptUrl} -w '%{http_code}\n' -s -o /dev/null`
if [ "${Result}" = 200 ]; then
	echo "Successful file existence check :" ${TestScriptUrl}
	curl -fsSL ${TestScriptUrl} | bash
fi

#-------------------------------------------------------------------------------
# Configure EC2 Instance Support for Amazon ENA Device
#-------------------------------------------------------------------------------

if [ -n "$RoleName" ]; then
	if [ $(command -v aws) ]; then
		# Get EC2 Instance Attribute(Elastic Network Adapter Status)
		aws ec2 describe-instances --instance-id ${InstanceId} --query "Reservations[].Instances[].EnaSupport" --output json --region ${Region}

		# Modify EC2 Instance Attribute(Elastic Network Adapter Status)
		# aws ec2 modify-instance-attribute --instance-id ${InstanceId} --ena-support

		# Get EC2 Instance Attribute(Elastic Network Adapter Status)
		# aws ec2 describe-instances --instance-id ${InstanceId} --query "Reservations[].Instances[].EnaSupport" --output json --region ${Region}
	fi
fi

#-------------------------------------------------------------------------------
# Remove Network Persistent Rules
#-------------------------------------------------------------------------------
# [Important]
# If your instance operating system contains an /etc/udev/rules.d/70-persistent-net.rules file, you must delete it before creating the AMI.
# This file contains the MAC address for the Ethernet adapter of the original instance.
# If another instance boots with this file, the operating system will be unable to find the device and eth0 might fail, causing boot issues.
# This file is regenerated at the next boot cycle, and any instances launched from the AMI create their own version of the file.
#-------------------------------------------------------------------------------

if [ -f /etc/udev/rules.d/70-persistent-net.rules ]; then
	rm -fr /etc/udev/rules.d/70-persistent-net.rules
fi

#-------------------------------------------------------------------------------
# For normal termination of SSM "Run Command"
#-------------------------------------------------------------------------------

exit 0

#-------------------------------------------------------------------------------
# End of File
#-------------------------------------------------------------------------------
