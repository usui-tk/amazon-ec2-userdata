#!/bin/bash -v

#-------------------------------------------------------------------------------
# Custom Package Installation [Intel Network Driver(ixgbevf)]
#
# Target Linux Distribution
#  - Red Hat Enterprise Linux v7.3
#  - CentOS v7.3(1602)
#
# Target AWS EC2 Instance Type
#  - General Purpose   [m4]
#  - Compute Optimized [c3,c4]
#  - Memory Optimized  [r3]
#  - Storage Optimized [i2,d2]
#
# Reference
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/enhanced-networking.html
#  http://blog.father.gedow.net/2016/03/15/enhanced-networking/
#  https://sourceforge.net/projects/e1000/files/ixgbevf%20stable/
#-------------------------------------------------------------------------------

# Instance MetaData
AZ=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
Region=$(echo $AZ | sed -e 's/.$//g')
InstanceId=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
InstanceType=$(curl -s http://169.254.169.254/latest/meta-data/instance-type)
PrivateIp=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
if [[ "$InstanceType" =~ ^(x1.*)$ ]]; then
	# Get EC2 Instance Attribute(Elastic Network Adapter Status)
	echo "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
	aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute enaSupport --output json --region ${Region}
elif [[ "$InstanceType" =~ ^(c3.*|c4.*|d2.*|i2.*|m4.*|r3.*)$ ]]; then
	# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
	echo "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
	aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}
	modinfo ixgbevf
	ethtool -i eth0
else
	echo "Instance type of None [Network Interface Performance Attribute]"
fi

# Package Install DKMS (from EPEL Repository)
yum --enablerepo=epel install -y dkms wget

# Set Grub2 Parameter
sed -i '/^GRUB_CMDLINE_LINUX/s/"$/ net.ifnames=0"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

cd /usr/src
wget -O ixgbevf-3.3.2.tar.gz "https://downloads.sourceforge.net/project/e1000/ixgbevf%20stable/3.3.2/ixgbevf-3.3.2.tar.gz"
tar xzf ixgbevf-3.3.2.tar.gz
cd ixgbevf-3.3.2

cat > dkms.conf << "__EOF__"
PACKAGE_NAME="ixgbevf"
PACKAGE_VERSION="3.3.2"
CLEAN="cd src/; make clean"
MAKE="cd src/; make BUILD_KERNEL=${kernelver}"
BUILT_MODULE_LOCATION[0]="src/"
BUILT_MODULE_NAME[0]="ixgbevf"
DEST_MODULE_LOCATION[0]="/updates"
DEST_MODULE_NAME[0]="ixgbevf"
AUTOINSTALL="yes"
__EOF__

# Make & Build & Install ixgbevf
modinfo ixgbevf
ethtool -i eth0

dkms add -m ixgbevf -v 3.3.2
dkms build -m ixgbevf -v 3.3.2
dkms install -m ixgbevf -v 3.3.2

modinfo ixgbevf
ethtool -i eth0

