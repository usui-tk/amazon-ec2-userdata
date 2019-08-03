#!/bin/bash -v

# Remove the udev persistent rules file
rm -rf /etc/udev/rules.d/70-persistent-*

# Remove cloud-init status
rm -rf /var/lib/cloud/* 

# Remove /tmp files
rm -rf /tmp/* 

# Remove /var/log files
find /var/log/ -type f -name \* -exec cp -f /dev/null {} \;

# Remove /var/log/user-data_*.log files
rm -rf /var/log/user-data_*.log

# Remove SSH Host Key Pairs
shred -u /etc/ssh/*_key /etc/ssh/*_key.pub

# Remove SSH Authorized Keys (Root User) for All Linux Distribution
if [ -f /root/.ssh/authorized_keys ]; then
    shred -u /root/.ssh/authorized_keys
fi

# Remove SSH Authorized Keys (ec2-user User) for Amazon Linux, Red Hat Enterprise Linux (RHEL), SUSE Linux Enterprise Server (SLES)
if [ -f /home/ec2-user/.ssh/authorized_keys ]; then
    shred -u /home/ec2-user/.ssh/authorized_keys
fi

# Remove SSH Authorized Keys (ec2-user User) for CentOS
if [ -f /home/centos/.ssh/authorized_keys ]; then
    shred -u /home/centos/.ssh/authorized_keys
fi

# Remove SSH Authorized Keys (fedora User) for fedora
if [ -f /home/fedora/.ssh/authorized_keys ]; then
    shred -u /home/fedora/.ssh/authorized_keys
fi

# Remove SSH Authorized Keys (ubuntu User) for Ubuntu
if [ -f /home/ubuntu/.ssh/authorized_keys ]; then
    shred -u /home/ubuntu/.ssh/authorized_keys
fi

# Remove SSH Authorized Keys (admin User) for Debian
if [ -f /home/admin/.ssh/authorized_keys ]; then
    shred -u /admin/centos/.ssh/authorized_keys
fi

# Remove Bash History
unset HISTFILE
[ -f /root/.bash_history ] && rm -rf /root/.bash_history
[ -f /home/ec2-user/.bash_history ] && rm -rf /home/ec2-user/.bash_history
[ -f /home/centos/.bash_history ] && rm -rf /home/centos/.bash_history
[ -f /home/fedora/.bash_history ] && rm -rf /home/fedora/.bash_history
[ -f /home/ubuntu/.bash_history ] && rm -rf /home/ubuntu/.bash_history
[ -f /home/admin/.bash_history ] && rm -rf /home/admin/.bash_history

# Shutdown
shutdown -h now
