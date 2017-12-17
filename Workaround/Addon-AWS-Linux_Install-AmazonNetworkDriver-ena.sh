#!/bin/bash -v

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Network Driver(ena)]
#
# Target Linux Distribution
#  - Red Hat Enterprise Linux v7.3
#  - CentOS v7.3(1602)
#
# Reference
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/enhanced-networking-ena.html
#  http://docs.aws.amazon.com/ja_jp/AWSEC2/latest/UserGuide/instance-types.html
#  https://github.com/amzn/amzn-drivers
#  https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/rpm/README-rpm.txt
#-------------------------------------------------------------------------------

# Package Install DKMS (from EPEL Repository)
yum --enablerepo=epel install -y dkms wget gcc kernel-devel kernel-headers

# Set Grub2 Parameter
rpm -qa | grep -e '^systemd-[0-9]\+\|^udev-[0-9]\+'
sed -i '/^GRUB_CMDLINE_LINUX/s/"$/ net.ifnames=0"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

cd /usr/src
wget -O ena_linux_1.5.0.tar.gz "https://github.com/amzn/amzn-drivers/archive/ena_linux_1.5.0.tar.gz"
tar xzf ena_linux_1.5.0.tar.gz
rm -fr ena_linux_1.5.0.tar.gz

mv amzn-drivers-ena_linux_1.5.0 amzn-drivers-ena_linux-1.5.0
cd amzn-drivers-ena_linux-1.5.0

cat > dkms.conf << __EOF__
PACKAGE_NAME="ena"
PACKAGE_VERSION="1.5.0"
CLEAN="make -C kernel/linux/ena clean"
MAKE="make -C kernel/linux/ena/ BUILD_KERNEL=${kernelver}"
BUILT_MODULE_NAME[0]="ena"
BUILT_MODULE_LOCATION="kernel/linux/ena"
DEST_MODULE_LOCATION[0]="/updates"
DEST_MODULE_NAME[0]="ena"
AUTOINSTALL="yes"
__EOF__

# Make & Build & Install ena
ethtool -i eth0

dkms add -m amzn-drivers-ena_linux -v 1.5.0
dkms build -m amzn-drivers-ena_linux -v 1.5.0
dkms install -m amzn-drivers-ena_linux -v 1.5.0

modinfo ena
ethtool -i eth0
