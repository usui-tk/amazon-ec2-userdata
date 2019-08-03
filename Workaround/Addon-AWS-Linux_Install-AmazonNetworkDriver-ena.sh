#!/bin/bash -v

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Network Driver(ena)]
#
# Target Linux Distribution
#  - Red Hat Enterprise Linux v6.x, v7.x
#  - CentOS v6.x, v7,x
#
# Reference
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/instance-types.html
#  https://github.com/amzn/amzn-drivers
#  https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/rpm/README-rpm.txt
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Parameter definition [Amazon Network Driver(ena)]
#-------------------------------------------------------------------------------

# Source code acquisition URL and definition of file name and version information
SourceUrl="https://github.com/amzn/amzn-drivers/archive/ena_linux_2.1.1.tar.gz"
SourceFile=$(echo ${SourceUrl##*/})
SourceVersion=$(echo $SourceFile | sed -nre 's/^[^0-9]*(([0-9]+\.)*[0-9]+).*/\1/p')

#-------------------------------------------------------------------------------
# Install Kernel module and Configure Dynamic Kernel Module Support (DKMS) 
#-------------------------------------------------------------------------------

# Package Install Kernel Module
yum install -y kernel-devel-$(uname -r) kernel-headers-$(uname -r)

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

mv "amzn-drivers-ena_linux_${SourceVersion}" "amzn-drivers-ena_linux-${SourceVersion}"
cd "amzn-drivers-ena_linux-${SourceVersion}"

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
dkms add -m amzn-drivers-ena_linux -v ${SourceVersion}
dkms build -m amzn-drivers-ena_linux -v ${SourceVersion}
dkms install -m amzn-drivers-ena_linux -v ${SourceVersion}

modinfo ena

#-------------------------------------------------------------------------------
# Configure EC2 Instance Support for Amazon ENA Device
#-------------------------------------------------------------------------------
if [ -n "$RoleName" ]; then

	# Get EC2 Instance Attribute(Elastic Network Adapter Status)
	aws ec2 describe-instances --instance-id ${InstanceId} --query "Reservations[].Instances[].EnaSupport" --output json --region ${Region}

	# Modify EC2 Instance Attribute(Elastic Network Adapter Status)
	# aws ec2 modify-instance-attribute --instance-id ${InstanceId} --ena-support

	# Get EC2 Instance Attribute(Elastic Network Adapter Status)
	aws ec2 describe-instances --instance-id ${InstanceId} --query "Reservations[].Instances[].EnaSupport" --output json --region ${Region}
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

