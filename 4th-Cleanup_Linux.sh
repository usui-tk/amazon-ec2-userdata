#!/bin/bash -v

#############################################################################################
#
# [Reference]
#  Security best practices for EC2 Image Builder
#   https://docs.aws.amazon.com/imagebuilder/latest/userguide/security-best-practices.html
#  Guidelines for shared Linux AMIs
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/building-shared-amis.html
#
#############################################################################################

set -e -x

#-------------------------------------------------------------------------------
# Parameter Settings
#-------------------------------------------------------------------------------

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
	lsb_release -a
else
	uname -a
fi

# Show Linux distribution release Information
if [ -f /etc/os-release ]; then
	cat "/etc/os-release"
fi

# Show Linux kernel package name Information
if [ $(command -v rpm) ]; then
	if [ $(command -v grubby) ]; then
		DEFAULTKERNEL=$(rpm -qf `grubby --default-kernel` | sed 's/\(.*\)-[0-9].*-.*/\1/')
		echo "Linux kernel package name :" $DEFAULTKERNEL
	else
		DEFAULTKERNEL=$(rpm -qa | grep -ie `uname -r` | grep -ie "kernel" | awk '{print length, $0}' | sort -n | head -n 1 | awk '{print $2}')
		echo "Linux kernel package name :" $DEFAULTKERNEL
	fi
fi

# Show Machine Boot Program Information
if [ -d /sys/firmware/efi ]; then
	BootProgram="UEFI"
	echo "Machine Boot Program :" $BootProgram
else
	BootProgram="BIOS"
	echo "Machine Boot Program :" $BootProgram
fi

#-------------------------------------------------------------------------------
# Cleanup process for old kernel Package (RPM package ecosystem)
#-------------------------------------------------------------------------------
if [ $(command -v rpm) ]; then

	echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Cleanup process for old kernel Package (RPM package ecosystem) START"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Linux distributions using DNF package manager)
	# --------------------------------------------------------------------------
	if [ $(command -v dnf) ]; then

		echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Removing old kernel packages (Linux distributions using DNF package manager) START"

		# Show Linux Distribution/Distro information
		if [ $(command -v lsb_release) ]; then
			lsb_release -a
		else
			uname -a
		fi

		# Package Installed Kernel Package
		if [ -n "$DEFAULTKERNEL" ]; then
			dnf --showduplicate list ${DEFAULTKERNEL}
		else
			rpm -qa | grep -ie "kernel" | sort
		fi

		# Removing old kernel packages
		dnf remove -y $(dnf repoquery --installonly --latest-limit=-1 -q)
		sleep 5

		# Package Installed Kernel Package
		if [ -n "$DEFAULTKERNEL" ]; then
			dnf --showduplicate list ${DEFAULTKERNEL}
		else
			rpm -qa | grep -ie "kernel" | sort
		fi

		# Reconfigure GRUB 2 config file
		if [ $(command -v grub2-mkconfig) ]; then
			if [ $BootProgram = "UEFI" ]; then
				grub2-mkconfig -o $(find /boot | grep -ie "efi" -ie "EFI" | grep -w grub.cfg)
			elif [ $BootProgram = "BIOS" ]; then
				grub2-mkconfig -o $(find /boot | grep -ve "efi" -ve "EFI" | grep -w grub.cfg)
			else
				grub2-mkconfig -o $(find /boot | grep -w grub.cfg)
			fi
		fi

		# Cleanup repository information
		dnf --enablerepo="*" --verbose clean all

		echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Removing old kernel packages (Linux distributions using DNF package manager) COMPLETE"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Linux distributions using YUM package manager)
	# --------------------------------------------------------------------------
	elif [ $(command -v yum) ]; then

		echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Removing old kernel packages (Linux distributions using YUM package manager) START"

		# Show Linux Distribution/Distro information
		if [ $(command -v lsb_release) ]; then
			lsb_release -a
		else
			uname -a
		fi

		# Package Installed Kernel Package
		if [ -n "$DEFAULTKERNEL" ]; then
			yum --showduplicate list ${DEFAULTKERNEL}
		else
			rpm -qa | grep -ie "kernel" | sort
		fi

		# Removing old kernel packages
		if [ $(command -v package-cleanup) ]; then
			package-cleanup --oldkernels --count="1" -y
			sleep 5
		fi

		# Package Installed Kernel Package
		if [ -n "$DEFAULTKERNEL" ]; then
			yum --showduplicate list ${DEFAULTKERNEL}
		else
			rpm -qa | grep -ie "kernel" | sort
		fi

		# Reconfigure GRUB 2 config file
		if [ $(command -v grub2-mkconfig) ]; then
			if [ $BootProgram = "UEFI" ]; then
				grub2-mkconfig -o $(find /boot | grep -ie "efi" -ie "EFI" | grep -w grub.cfg)
			elif [ $BootProgram = "BIOS" ]; then
				grub2-mkconfig -o $(find /boot | grep -ve "efi" -ve "EFI" | grep -w grub.cfg)
			else
				grub2-mkconfig -o $(find /boot | grep -w grub.cfg)
			fi
		fi

		# Cleanup repository information
		yum --enablerepo="*" --verbose clean all

		echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Removing old kernel packages (Linux distributions using YUM package manager) COMPLETE"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Linux distributions using ZYPPER package manager)
	# --------------------------------------------------------------------------
	elif [ $(command -v zypper) ]; then

		echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Removing old kernel packages (Linux distributions using ZYPPER package manager) START"

		# Show Linux Distribution/Distro information
		if [ $(command -v lsb_release) ]; then
			lsb_release -a
		else
			uname -a
		fi

		# Package Install Kernel Package
		rpm -qa | grep -ie "kernel-default" | sort

		# Removing old kernel packages
		cat /etc/zypp/zypp.conf | grep multiversion.kernels
		if [ $(command -v purge-kernels) ]; then
			purge-kernels
			sleep 5
		fi

		# Package Install Kernel Package
		rpm -qa | grep -ie "kernel-default" | sort

		# Reconfigure GRUB 2 config file
		if [ $(command -v grub2-mkconfig) ]; then
			if [ $BootProgram = "UEFI" ]; then
				grub2-mkconfig -o $(find /boot | grep -ie "efi" -ie "EFI" | grep -w grub.cfg)
			elif [ $BootProgram = "BIOS" ]; then
				grub2-mkconfig -o $(find /boot | grep -ve "efi" -ve "EFI" | grep -w grub.cfg)
			else
				grub2-mkconfig -o $(find /boot | grep -w grub.cfg)
			fi
		fi

		# Cleanup repository information
		zypper clean --all

		echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Removing old kernel packages (Linux distributions using ZYPPER package manager) COMPLETE"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Unsupported Linux distributions)
	# --------------------------------------------------------------------------
	else

		echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Removing old kernel packages (Unsupported Linux distributions)"

		# Show Linux Distribution/Distro information
		if [ $(command -v lsb_release) ]; then
			lsb_release -a
		else
			uname -a
		fi

		# Show Linux distribution release Information
		if [ -f /etc/os-release ]; then
			cat "/etc/os-release"
		fi
	fi

	echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Cleanup process for old kernel Package (RPM package ecosystem) COMPLETE"

fi

#-------------------------------------------------------------------------------
# Cleanup process for old kernel Package (DEB package ecosystem)
#-------------------------------------------------------------------------------
if [ $(command -v dpkg) ]; then

	echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Cleanup process for old kernel Package (DEB package ecosystem) START"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Linux distributions using APT package manager)
	# --------------------------------------------------------------------------
	if [ $(command -v apt) ]; then

		echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Removing old kernel packages (Linux distributions using APT package manager) START"

		# Show Linux Distribution/Distro information
		if [ $(command -v lsb_release) ]; then
			lsb_release -a
		else
			uname -a
		fi

		# Package Installed Kernel Package
		dpkg --get-selections | grep -ie "linux-image" | sort

		# Removing old kernel packages
		if [ $(command -v purge-old-kernels) ]; then
			purge-old-kernels
			sleep 5
		fi

		# Package Installed Kernel Package
		dpkg --get-selections | grep -ie "linux-image" | sort

		# Reconfigure GRUB 2 config file
		if [ $(command -v update-grub) ]; then
			update-grub
		fi

		# Clean up package
		apt autoremove -y -q

		# apt repository metadata Clean up
		apt clean -y -q

		echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Removing old kernel packages (Linux distributions using APT package manager) COMPLETE"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Unsupported Linux distributions)
	# --------------------------------------------------------------------------
	else

		echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Removing old kernel packages (Unsupported Linux distributions)"

		# Show Linux Distribution/Distro information
		if [ $(command -v lsb_release) ]; then
			lsb_release -a
		else
			uname -a
		fi

		# Show Linux distribution release Information
		if [ -f /etc/os-release ]; then
			cat "/etc/os-release"
		fi
	fi

	echo "["$(date "+%Y-%m-%d %H:%M:%S.%N")"]" "- Cleanup process for old kernel Package (DEB package ecosystem) COMPLETE"

fi

#-------------------------------------------------------------------------------
# Cleanup process for Configuration Files, and Log Files
# [Security best practices for EC2 Image Builder]
# https://docs.aws.amazon.com/imagebuilder/latest/userguide/security-best-practices.html
#-------------------------------------------------------------------------------

FILES=(
		# Secure removal of list of users
		"/etc/sudoers.d/90-cloud-init-users"

		# Secure removal of RSA encrypted SSH host keys.
		"/etc/ssh/ssh_host_rsa_key"
		"/etc/ssh/ssh_host_rsa_key.pub"

		# Secure removal of ECDSA encrypted SSH host keys.
		"/etc/ssh/ssh_host_ecdsa_key"
		"/etc/ssh/ssh_host_ecdsa_key.pub"

		# Secure removal of ED25519 encrypted SSH host keys.
		"/etc/ssh/ssh_host_ed25519_key"
		"/etc/ssh/ssh_host_ed25519_key.pub"

		# Secure removal of "root" user approved SSH keys list.
		"/root/.ssh/authorized_keys"

		# Secure removal of "ec2-user" user approved SSH keys list.
		"/home/ec2-user/.ssh/authorized_keys"

		# Secure removal of file which tracks system updates
		"/etc/.updated"
		"/var/.updated"

		# Secure removal of file with aliases for mailing lists
		"/etc/aliases.db"

		# Secure removal of file which contains the hostname of the system
		"/etc/hostname"

		# Secure removal of files with system-wide locale settings
		"/etc/locale.conf"

		# Secure removal of cached GPG signatures of yum repositories
		"/var/cache/yum/x86_64/2/.gpgkeyschecked.yum"

		# Secure removal of audit framework logs
		"/var/log/audit/audit.log"

		# Secure removal of boot logs
		"/var/log/boot.log"

		# Secure removal of kernel message logs
		"/var/log/dmesg"

		# Secure removal of cloud-init logs
		"/var/log/cloud-init.log"

		# Secure removal of cloud-init's output logs
		"/var/log/cloud-init-output.log"

		# Secure removal of cron logs
		"/var/log/cron"

		# Secure removal of aliases file for the Postfix mail transfer agent
		"/var/lib/misc/postfix.aliasesdb-stamp"

		# Secure removal of master lock for the Postfix mail transfer agent
		"/var/lib/postfix/master.lock"

		# Secure removal of spool data for the Postfix mail transfer agent
		"/var/spool/postfix/pid/master.pid"

		# Secure removal of history of Bash commands
		"/home/ec2-user/.bash_history"

)


for FILE in "${FILES[@]}"; do
	if [[ -f $FILE ]]; then
		echo "Deleting $FILE"
		shred -zuf $FILE
	fi

	if [[ -f $FILE ]]; then
		echo "Failed to delete '$FILE'. Failing."
	fi
done

#-------------------------------------------------------------------------------

# Secure removal of system activity reports/logs
if [[ $(find /var/log/sa/sa* -type f | wc -l) -gt 0 ]]; then
	echo "Deleting /var/log/sa/sa*"
	shred -zuf /var/log/sa/sa*
fi

if [[ $(find /var/log/sa/sa* -type f | wc -l) -gt 0 ]]; then
	echo "Failed to delete /var/log/sa/sa*"
fi

#-------------------------------------------------------------------------------

# Secure removal of SSM logs
if [[ $(find /var/log/amazon/ssm -type f | wc -l) -gt 0 ]]; then
	echo "Deleting files within /var/log/amazon/ssm/*"
	find /var/log/amazon/ssm -type f -exec shred -zuf {} \;
fi

if [[ $(find /var/log/amazon/ssm -type f | wc -l) -gt 0 ]]; then
	echo "Failed to delete /var/log/amazon/ssm"
fi


if [[ -d "/var/log/amazon/ssm" ]]; then
	echo "Deleting /var/log/amazon/ssm/*"
	rm -rf /var/log/amazon/ssm
fi

if [[ -d "/var/log/amazon/ssm" ]]; then
	echo "Failed to delete /var/log/amazon/ssm"
fi

#-------------------------------------------------------------------------------

# Secure removal of DHCP client leases that have been acquired
if [[ $(find /var/lib/dhclient/dhclient*.lease -type f | wc -l) -gt 0 ]]; then
	echo "Deleting /var/lib/dhclient/dhclient*.lease"
	shred -zuf /var/lib/dhclient/dhclient*.lease
fi

if [[ $(find /var/lib/dhclient/dhclient*.lease -type f | wc -l) -gt 0 ]]; then
	echo "Failed to delete /var/lib/dhclient/dhclient*.lease"
fi

#-------------------------------------------------------------------------------

# Secure removal of cloud-init files
if [[ $(find /var/lib/cloud -type f | wc -l) -gt 0 ]]; then
	echo "Deleting files within /var/lib/cloud/*"
	find /var/lib/cloud -type f -exec shred -zuf {} \;
fi

if [[ $(find /var/lib/cloud -type f | wc -l) -gt 0 ]]; then
	echo "Failed to delete /var/lib/cloud"
fi


if [[ $(ls /var/lib/cloud | wc -l) -gt 0 ]]; then
	echo "Deleting /var/lib/cloud/*"
	rm -rf /var/lib/cloud/*
fi
if [[ $(ls /var/lib/cloud | wc -l) -gt 0 ]]; then
	echo "Failed to delete /var/lib/cloud/*"
fi

#-------------------------------------------------------------------------------

# Secure removal of temporary files
if [[ $(find /var/tmp -type f | wc -l) -gt 0 ]]; then
	echo "Deleting files within /var/tmp/*"
	find /var/tmp -type f -exec shred -zuf {} \;
fi

if [[ $(find /var/tmp -type f | wc -l) -gt 0 ]]; then
	echo "Failed to delete /var/tmp"
fi

if [[ $( ls /var/tmp | wc -l ) -gt 0 ]]; then
	echo "Deleting /var/tmp/*"
	rm -rf /var/tmp/*
fi

#-------------------------------------------------------------------------------



#-------------------------------------------------------------------------------
# Shredding is not guaranteed to work well on rolling logs
# [Security best practices for EC2 Image Builder]
# https://docs.aws.amazon.com/imagebuilder/latest/userguide/security-best-practices.html
#-------------------------------------------------------------------------------

# Removal of system logs
if [[ -f "/var/lib/rsyslog/imjournal.state" ]]; then
	echo "Deleting /var/lib/rsyslog/imjournal.state"
	shred -zuf /var/lib/rsyslog/imjournal.state
	rm -f /var/lib/rsyslog/imjournal.state
fi

if [[ -f "/var/lib/rsyslog/imjournal.state" ]]; then
	echo "Failed to delete /var/lib/rsyslog/imjournal.state"
fi

# Removal of journal logs
if [[ $(ls /var/log/journal/ | wc -l) -gt 0 ]]; then
	echo "Deleting /var/log/journal/*"
	find /var/log/journal/ -type f -exec shred -zuf {} \;
	rm -rf /var/log/journal/*
fi

#-------------------------------------------------------------------------------



#-------------------------------------------------------------------------------
# Cleanup process for Configuration Files, and Log Files
#-------------------------------------------------------------------------------

# Remove the udev persistent rules file
rm -rf /etc/udev/rules.d/70-persistent-*

# Remove cloud-init status
rm -rf /var/lib/cloud/*

# Remove temporary files
rm -rf /tmp/*
rm -rf /var/tmp/*

# Remove /var/log files
find /var/log/ -type f -name \* -exec cp -f /dev/null {} \;

# Remove /var/log/user-data_*.log files
rm -rf /var/log/user-data_*.log

#-------------------------------------------------------------------------------
# Cleanup process for Machine ID
#-------------------------------------------------------------------------------

# Cleanup Machine information
if [ -f /etc/machine-id ]; then
	echo "[Cleanup Machine information] : /etc/machine-id"

	cat "/etc/machine-id"

	cat /dev/null > "/etc/machine-id"

	cat "/etc/machine-id"
fi

# Cleanup Machine ID for Yum package manager
if [ -f /var/lib/yum/uuid ]; then
	echo "[Cleanup Machine information] : /var/lib/yum/uuid"

	cat "/var/lib/yum/uuid"

	cat /dev/null > "/var/lib/yum/uuid"

	cat "/var/lib/yum/uuid"
fi

# Cleanup Machine ID for Zypper package manager
if [ -f /var/lib/zypp/AnonymousUniqueId ]; then
	echo "[Cleanup Machine information] : /var/lib/zypp/AnonymousUniqueId"

	cat "/var/lib/zypp/AnonymousUniqueId"

	cat /dev/null > "/var/lib/zypp/AnonymousUniqueId"

	cat "/var/lib/zypp/AnonymousUniqueId"
fi

#-------------------------------------------------------------------------------
# Cleanup process for SSH Host Key, SSH Public Key, SSH Authorized Keys
#-------------------------------------------------------------------------------

# Remove SSH Host Key
if [[ $(find /etc/ssh/ -name "*_key" | wc -l) -gt 0 ]]; then

	# SSH Host Key File List
	HostKeyList=$(find /etc/ssh/ -name "*_key")

	# Remove SSH Host Key
	for HostKey in $HostKeyList
	do
		echo "[Remove SSH Host Key] :" $HostKey
		shred -zuf $HostKey
		sleep 1
	done

fi


# Remove SSH Public Key
if [[ $(find /etc/ssh/ -name "*_key.pub" | wc -l) -gt 0 ]]; then

	# SSH Public Key File List
	PublicKeyList=$(find /etc/ssh/ -name "*_key.pub")

	# Remove SSH Public Key
	for PublicKey in $PublicKeyList
	do
		echo "[Remove SSH Public Key] :" $PublicKey
		shred -zuf $PublicKey
		sleep 1
	done

fi

# Remove SSH Authorized Keys (General user)
if [[ $(find /home -name "authorized_keys" | wc -l) -gt 0 ]]; then

	# SSH Authorized Keys File List
	SshKeyList=$(find /home -name "authorized_keys")

	# Remove SSH Authorized Keys (General user)
	for SshKey in $SshKeyList
	do
		echo "[Remove SSH Authorized Key] :" $SshKey
		shred -zuf $SshKey
		sleep 1
	done

fi


#-------------------------------------------------------------------------------
# Cleanup process for Bash History
#-------------------------------------------------------------------------------

# Remove Bash History
export HISTSIZE=0
unset HISTFILE

# Remove Bash History (Root User) for All Linux Distribution
if [ -f /root/.bash_history ]; then
	echo "[Remove Bash History] : rm -fv /root/.bash_history"
	shred -zuf "/root/.bash_history"
fi

# Remove Bash History (for AWS Systems Manager/OS Local User)
if [ -f /home/ssm-user/.bash_history ]; then
	echo "[Remove Bash History] : /home/ssm-user/.bash_history"
	shred -zuf "/home/ssm-user/.bash_history"
fi

# Remove Bash History (General user)
if [[ $(find /home -name ".bash_history" | wc -l) -gt 0 ]]; then

	# Bash History File List
	BashHistoryList=$(find /home -name ".bash_history")

	# Remove Bash History (General user)
	for BashHistory in $BashHistoryList
	do
		echo "[Remove Bash History] :" $BashHistory
		shred -zuf $BashHistory
		sleep 1
	done

fi


#-------------------------------------------------------------------------------
# Wait for cache data to be written to disk
#-------------------------------------------------------------------------------

# Make sure we wait until all the data is written to disk, otherwise script might quite too early before the large files are deleted
sync

# Waiting time
sleep 30

#-------------------------------------------------------------------------------
# Stop instance
#-------------------------------------------------------------------------------

# Shutdown
shutdown -h now

#-------------------------------------------------------------------------------
# For normal termination of SSM "Run Command"
#-------------------------------------------------------------------------------

# exit 0

#-------------------------------------------------------------------------------
# End of File
#-------------------------------------------------------------------------------
