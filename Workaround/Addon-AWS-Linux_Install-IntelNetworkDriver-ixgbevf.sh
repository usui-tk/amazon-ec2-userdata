#!/bin/bash -v

#-------------------------------------------------------------------------------
# Custom Package Installation [Intel Network Driver(ixgbevf)]
#
# Target Linux Distribution
#  - Red Hat Enterprise Linux v6.x, v7.x
#  - CentOS v6.x, v7,x
#
# Reference
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/enhanced-networking.html
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/instance-types.html
#  http://blog.father.gedow.net/2016/03/15/enhanced-networking/
#  https://sourceforge.net/projects/e1000/files/ixgbevf%20stable/
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Parameter definition [Intel Network Driver(ixgbevf)]
#-------------------------------------------------------------------------------

# Source code acquisition URL and definition of file name and version information
SourceUrl="https://downloads.sourceforge.net/project/e1000/ixgbevf%20stable/4.6.1/ixgbevf-4.6.1.tar.gz"
SourceFile=$(echo ${SourceUrl##*/})
SourceVersion=$(echo $SourceFile | sed -nre 's/^[^0-9]*(([0-9]+\.)*[0-9]+).*/\1/p')

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

# Get Intel Ethernet Driver source code
curl -LsS "${SourceUrl}" -o "/usr/src/${SourceFile}"

cd /usr/src
tar xzf ${SourceFile}
rm -fr ${SourceFile}

cd "ixgbevf-${SourceVersion}"

cat > dkms.conf << __EOF__
PACKAGE_NAME="ixgbevf"
PACKAGE_VERSION="TEMP-VERSION"
CLEAN="cd src/; make clean"
MAKE="cd src/; make BUILD_KERNEL=\${kernelver}"
BUILT_MODULE_LOCATION[0]="src/"
BUILT_MODULE_NAME[0]="ixgbevf"
DEST_MODULE_LOCATION[0]="/updates"
DEST_MODULE_NAME[0]="ixgbevf"
AUTOINSTALL="yes"
__EOF__

sed -i 's/TEMP-VERSION/'${SourceVersion}'/g' dkms.conf

# Make & Build & Install ixgbevf
dkms add -m ixgbevf -v ${SourceVersion}
dkms build -m ixgbevf -v ${SourceVersion}
dkms install -m ixgbevf -v ${SourceVersion}

modinfo ixgbevf


#-------------------------------------------------------------------------------
# Configure EC2 Instance Support for Amazon ENA Device
#-------------------------------------------------------------------------------
if [ -n "$RoleName" ]; then

	# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
	aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}

	# Modify EC2 Instance Attribute(Elastic Network Adapter Status)
	# aws ec2 modify-instance-attribute --instance-id ${InstanceId} --sriov-net-support simple

	# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
	aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}
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

