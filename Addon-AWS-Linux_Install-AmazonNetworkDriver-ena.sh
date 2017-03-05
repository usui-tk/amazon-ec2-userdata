#!/bin/bash -v

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Network Driver(ena)]
#
# Target Linux Distribution
#  - Red Hat Enterprise Linux v7.3
#  - CentOS v7.3(1602)
#
# Target AWS EC2 Instance Type
#  - General Purpose                           [m4.16xlarge]
#  - Memory Optimized                          [r4, x1]
#  - General Purpose GPU compute applications  [p2]
#
# Reference
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/instance-types.html
#  https://github.com/amzn/amzn-drivers
#  https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/rpm/README-rpm.txt
#-------------------------------------------------------------------------------

# Instance MetaData
AZ=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
Region=$(echo $AZ | sed -e 's/.$//g')
InstanceId=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
InstanceType=$(curl -s http://169.254.169.254/latest/meta-data/instance-type)
PrivateIp=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
AmiId=$(curl -s http://169.254.169.254/latest/meta-data/ami-id)

# Get EC2 Instance Attribute[Network Interface Performance Attribute]
if [[ "$InstanceType" =~ ^(i3.*|m4.16xlarge|p2.*|r4.*|x1.*)$ ]]; then
	# Get EC2 Instance Attribute(Elastic Network Adapter Status)
	echo "# Get EC2 Instance Attribute(Elastic Network Adapter Status)"
	aws ec2 describe-instances --instance-id ${InstanceId} --query Reservations[].Instances[].EnaSupport --output json --region ${Region}
	echo "# Get Linux Kernel Module(modinfo ena)"
	modinfo ena
	echo "# Get Linux Network Interface Driver(ethtool -i eth0)"
	ethtool -i eth0
elif [[ "$InstanceType" =~ ^(c3.*|c4.*|d2.*|i2.*|m4.*|r3.*)$ ]]; then
	# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)
	echo "# Get EC2 Instance Attribute(Single Root I/O Virtualization Status)"
	aws ec2 describe-instance-attribute --instance-id ${InstanceId} --attribute sriovNetSupport --output json --region ${Region}
	echo "# Get Linux Kernel Module(modinfo ixgbevf)"
	modinfo ixgbevf
	echo "# Get Linux Network Interface Driver(ethtool -i eth0)"
	ethtool -i eth0
else
	echo "# Get Linux Network Interface Driver(ethtool -i eth0)"
	ethtool -i eth0
fi

# Package Install DKMS (from EPEL Repository)
yum --enablerepo=epel install -y dkms wget gcc kernel-devel

# Set Grub2 Parameter
rpm -qa | grep -e '^systemd-[0-9]\+\|^udev-[0-9]\+'
sed -i '/^GRUB_CMDLINE_LINUX/s/"$/ net.ifnames=0"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

cd /usr/src
wget -O ena_linux_1.1.3.tar.gz "https://github.com/amzn/amzn-drivers/archive/ena_linux_1.1.3.tar.gz"
tar xzf ena_linux_1.1.3.tar.gz
rm -fr ena_linux_1.1.3.tar.gz

mv amzn-drivers-ena_linux_1.1.3 amzn-drivers-ena_linux-1.1.3
cd amzn-drivers-ena_linux-1.1.3

cat > dkms.conf << "__EOF__"
PACKAGE_NAME="ena"
PACKAGE_VERSION="1.1.3"
CLEAN="make -C kernel/linux/ena clean"
MAKE="make -C kernel/linux/ena/ BUILD_KERNEL=${kernelver}"
BUILT_MODULE_NAME[0]="ena"
BUILT_MODULE_LOCATION="kernel/linux/ena"
DEST_MODULE_LOCATION[0]="/updates"
DEST_MODULE_NAME[0]="ena"
AUTOINSTALL="yes"
__EOF__

# Make & Build & Install ixgbevf
ethtool -i eth0

dkms add -m amzn-drivers-ena_linux -v 1.1.3
dkms build -m amzn-drivers-ena_linux -v 1.1.3
dkms install -m amzn-drivers-ena_linux -v 1.1.3

modinfo ena
ethtool -i eth0
