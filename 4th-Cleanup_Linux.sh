#!/bin/bash -v

# Remove the udev persistent rules file
rm -rf /etc/udev/rules.d/70-persistent-*

# Remove cloud-init status
rm -rf /var/lib/cloud/* 

# Remove Amazon System Manager (Agent) status
rm -rf /var/lib/amazon/ssm/* 

# Remove /tmp files
rm -rf /tmp/* 

# Remove /var/log files
find /var/log/ -type f -name \* -exec cp -f /dev/null {} \;

# Remove /var/log/user-data_*.log files
rm -rf /var/log/user-data_*.log

# Remove SSH Host Key Pairs
shred -u /etc/ssh/*_key /etc/ssh/*_key.pub

# Remove Bash History
unset HISTFILE
[ -f /root/.bash_history ] && rm -rf /root/.bash_history
[ -f /home/ec2-user/.bash_history ] && rm -rf /home/ec2-user/.bash_history

# Shutdown
shutdown -h now
