#!/bin/bash -v

#-------------------------------------------------------------------------------
# Custom Package Installation [Intel Network Driver(ixgbevf)]
#
# Target Linux Distribution
#  - Red Hat Enterprise Linux v7.3, v6.9
#  - CentOS v7.3(1602), v6.9
#
# Reference
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/enhanced-networking.html
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/instance-types.html
#  http://blog.father.gedow.net/2016/03/15/enhanced-networking/
#  https://sourceforge.net/projects/e1000/files/ixgbevf%20stable/
#-------------------------------------------------------------------------------

# Package Install DKMS (from EPEL Repository)
yum --enablerepo=epel install -y dkms wget gcc kernel-devel kernel-headers

# Set Grub2 Parameter
rpm -qa | grep -e '^systemd-[0-9]\+\|^udev-[0-9]\+'
sed -i '/^GRUB_CMDLINE_LINUX/s/"$/ net.ifnames=0"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

cd /usr/src
wget -O ixgbevf-4.3.2.tar.gz "https://downloads.sourceforge.net/project/e1000/ixgbevf%20stable/4.3.2/ixgbevf-4.3.2.tar.gz"
tar xzf ixgbevf-4.3.2.tar.gz
rm -fr ixgbevf-4.3.2.tar.gz
cd ixgbevf-4.3.2

cat > dkms.conf << __EOF__
PACKAGE_NAME="ixgbevf"
PACKAGE_VERSION="4.3.2"
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

dkms add -m ixgbevf -v 4.3.2
dkms build -m ixgbevf -v 4.3.2
dkms install -m ixgbevf -v 4.3.2

modinfo ixgbevf
ethtool -i eth0

