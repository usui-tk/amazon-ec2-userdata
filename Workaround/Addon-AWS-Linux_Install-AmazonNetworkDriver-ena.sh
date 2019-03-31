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
# Get Instance Information [AWS-CLI]
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

# Get EC2 Instance Information
if [ -n "$RoleName" ]; then
	echo "# Get EC2 Instance Information"
	aws ec2 describe-instances --instance-ids ${InstanceId} --output json --region ${Region}
fi

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
#
# - ENA (Elastic Network Adapter)
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
# - SR-IOV
#   http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/sriov-networking.html
#
if [ -n "$RoleName" ]; then
	if [[ "$InstanceType" =~ ^(c5.*|c5d.*|e3.*|f1.*|g3.*|h1.*|i3.*|i3p.*|m5.*|m5d.*|p2.*|p3.*|r4.*|x1.*|x1e.*|m4.16xlarge)$ ]]; then
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


#-------------------------------------------------------------------------------
# Install Kernel module and Configure Dynamic Kernel Module Support (DKMS) 
#-------------------------------------------------------------------------------

# Package Install Kernel Module
yum install -y kernel-devel kernel-headers

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

# Get Amazon ENA Driver source code at github
curl -LsS "https://github.com/amzn/amzn-drivers/archive/ena_linux_2.0.3.tar.gz" -o "/usr/src/ena_linux_2.0.3.tar.gz"

cd /usr/src
tar xzf ena_linux_2.0.3.tar.gz
rm -fr ena_linux_2.0.3.tar.gz

mv amzn-drivers-ena_linux_2.0.3 amzn-drivers-ena_linux-2.0.3
cd amzn-drivers-ena_linux-2.0.3

cat > dkms.conf << __EOF__
PACKAGE_NAME="ena"
PACKAGE_VERSION="2.0.3"
CLEAN="make -C kernel/linux/ena clean"
MAKE="make -C kernel/linux/ena/ BUILD_KERNEL=\${kernelver}"
BUILT_MODULE_NAME[0]="ena"
BUILT_MODULE_LOCATION="kernel/linux/ena"
DEST_MODULE_LOCATION[0]="/updates"
DEST_MODULE_NAME[0]="ena"
AUTOINSTALL="yes"
__EOF__

# Make & Build & Install Amazon ENA Driver
ethtool -i eth0

dkms add -m amzn-drivers-ena_linux -v 2.0.3
dkms build -m amzn-drivers-ena_linux -v 2.0.3
dkms install -m amzn-drivers-ena_linux -v 2.0.3

modinfo ena
ethtool -i eth0


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

