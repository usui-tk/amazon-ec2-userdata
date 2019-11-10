#!/bin/bash -v

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
	cat /etc/os-release
fi

# Show Linux kernel package name Information
if [ -f /etc/sysconfig/kernel ]; then
	eval $(grep ^DEFAULTKERNEL= /etc/sysconfig/kernel)
	echo "Linux Kernel Package Name :" $DEFAULTKERNEL
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

	echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Cleanup process for old kernel Package (RPM package ecosystem) START"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Linux distributions using DNF package manager)
	# --------------------------------------------------------------------------
	if [ $(command -v dnf) ]; then

		echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Removing old kernel packages (Linux distributions using DNF package manager) START"

		# Show Linux Distribution/Distro information
		if [ $(command -v lsb_release) ]; then
			lsb_release -a
		else
			uname -a
		fi

		# Package Install Kernel Package
		if [ -n "$DEFAULTKERNEL" ]; then
			dnf --showduplicate list ${DEFAULTKERNEL}
		else
			rpm -qa | grep -ie "kernel" | sort
		fi

		# Removing old kernel packages
		dnf remove -y $(dnf repoquery --installonly --latest-limit=-1 -q)
		sleep 5

		# Package Install Kernel Package
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
		dnf clean all

		echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Removing old kernel packages (Linux distributions using DNF package manager) COMPLETE"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Linux distributions using YUM package manager)
	# --------------------------------------------------------------------------
	elif [ $(command -v yum) ]; then

		echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Removing old kernel packages (Linux distributions using YUM package manager) START"

		# Show Linux Distribution/Distro information
		if [ $(command -v lsb_release) ]; then
			lsb_release -a
		else
			uname -a
		fi

		# Package Install Kernel Package
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

		# Package Install Kernel Package
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
		yum clean all

		echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Removing old kernel packages (Linux distributions using YUM package manager) COMPLETE"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Linux distributions using ZYPPER package manager)
	# --------------------------------------------------------------------------
	elif [ $(command -v zypper) ]; then

		echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Removing old kernel packages (Linux distributions using ZYPPER package manager) START"

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

		# Cleanup Machine information
		if [ -f /var/lib/dbus/machine-id ]; then
			echo "[Cleanup Machine information] : rm -fv /var/lib/dbus/machine-id"
			rm -fv /var/lib/dbus/machine-id
		fi

		if [ -f /var/lib/zypp/AnonymousUniqueId ]; then
			echo "[Cleanup Machine information] : rm -fv /var/lib/zypp/AnonymousUniqueId"
			rm -fv /var/lib/zypp/AnonymousUniqueId
		fi

		echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Removing old kernel packages (Linux distributions using ZYPPER package manager) COMPLETE"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Unsupported Linux distributions)
	# --------------------------------------------------------------------------
	else

		echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Removing old kernel packages (Unsupported Linux distributions)"

		# Show Linux Distribution/Distro information
		if [ $(command -v lsb_release) ]; then
			lsb_release -a
		else
			uname -a
		fi

		# Show Linux distribution release Information
		if [ -f /etc/os-release ]; then
			cat /etc/os-release
		fi
	fi

	echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Cleanup process for old kernel Package (RPM package ecosystem) COMPLETE"

fi

#-------------------------------------------------------------------------------
# Cleanup process for old kernel Package (DEB package ecosystem)
#-------------------------------------------------------------------------------
if [ $(command -v dpkg) ]; then

	echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Cleanup process for old kernel Package (DEB package ecosystem) START"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Linux distributions using APT package manager)
	# --------------------------------------------------------------------------
	if [ $(command -v apt) ]; then

		echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Removing old kernel packages (Linux distributions using APT package manager) START"

		# Show Linux Distribution/Distro information
		if [ $(command -v lsb_release) ]; then
			lsb_release -a
		else
			uname -a
		fi

		# Package Install Kernel Package
		dpkg --get-selections | grep -ie "linux-image" | sort

		# Removing old kernel packages
		if [ $(command -v purge-old-kernels) ]; then
			purge-old-kernels
			sleep 5
		fi

		# Package Install Kernel Package
		dpkg --get-selections | grep -ie "linux-image" | sort

		# Reconfigure GRUB 2 config file
		if [ $(command -v update-grub) ]; then
			update-grub
		fi

		# apt repository metadata Clean up
		apt clean -y -q

		# Clean up package
		apt autoremove -y -q

		echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Removing old kernel packages (Linux distributions using APT package manager) COMPLETE"

	# --------------------------------------------------------------------------
	# Removing old kernel packages (Unsupported Linux distributions)
	# --------------------------------------------------------------------------
	else

		echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Removing old kernel packages (Unsupported Linux distributions)"

		# Show Linux Distribution/Distro information
		if [ $(command -v lsb_release) ]; then
			lsb_release -a
		else
			uname -a
		fi

		# Show Linux distribution release Information
		if [ -f /etc/os-release ]; then
			cat /etc/os-release
		fi
	fi

	echo $(date "+%Y-%m-%d %H:%M:%S.%N") "- Cleanup process for old kernel Package (DEB package ecosystem) COMPLETE"

fi

#-------------------------------------------------------------------------------
# Cleanup process for Configuration Files, and Log Files
#-------------------------------------------------------------------------------

# Remove the udev persistent rules file
rm -rf /etc/udev/rules.d/70-persistent-*

# Remove cloud-init status
rm -rf /var/lib/cloud/*

# Remove /tmp/, /var/tmp/ files
rm -rf /tmp/*
rm -rf /var/tmp/*

# Remove /var/log files
find /var/log/ -type f -name \* -exec cp -f /dev/null {} \;

# Remove /var/log/user-data_*.log files
rm -rf /var/log/user-data_*.log

#-------------------------------------------------------------------------------
# Cleanup process for SSH Host Key, SSH Public Key, SSH Authorized Keys
#-------------------------------------------------------------------------------

# Remove SSH Host Key
HostKeyFlag=$(find /etc/ssh/ -name "*_key" | wc -l)

if [ $HostKeyFlag -gt 0 ]; then
	# SSH Host Key File List
	HostKeyList=$(find /etc/ssh/ -name "*_key")

	# Remove SSH Host Key
	for HostKey in $HostKeyList
	do
		echo "[Remove SSH Host Key] :" $HostKey
		shred -u --force $HostKey
		sleep 1
	done
fi

# Remove SSH Public Key
PublicKeyFlag=$(find /etc/ssh/ -name "*_key.pub" | wc -l)

if [ $PublicKeyFlag -gt 0 ]; then
	# SSH Public Key File List
	PublicKeyList=$(find /etc/ssh/ -name "*_key.pub")

	# Remove SSH Public Key
	for PublicKey in $PublicKeyList
	do
		echo "[Remove SSH Public Key] :" $PublicKey
		shred -u --force $PublicKey
		sleep 1
	done
fi

# Remove SSH Authorized Keys (Root User) for All Linux Distribution
if [ -f /root/.ssh/authorized_keys ]; then
	shred -u --force /root/.ssh/authorized_keys
fi

# Remove SSH Authorized Keys (General user)
SshKeyFlag=$(find /home -name "authorized_keys" | wc -l)

if [ $SshKeyFlag -gt 0 ]; then
	# SSH Authorized Keys File List
	SshKeyList=$(find /home -name "authorized_keys")

	# Remove SSH Authorized Keys (General user)
	for SshKey in $SshKeyList
	do
		echo "[Remove SSH Authorized Key] :" $SshKey
		shred -u --force $SshKey
		sleep 1
	done
fi

#-------------------------------------------------------------------------------
# Cleanup process for Bash History
#-------------------------------------------------------------------------------

# Remove Bash History
unset HISTFILE

# Remove Bash History (Root User) for All Linux Distribution
if [ -f /root/.bash_history ]; then
	echo "[Remove Bash History] : rm -fv /root/.bash_history"
	rm -fv /root/.bash_history
fi

# Remove Bash History (for AWS Systems Manager/OS Local User)
if [ -f /home/ssm-user/.bash_history ]; then
	echo "[Remove Bash History] : /home/ssm-user/.bash_history"
	rm -fv /home/ssm-user/.bash_history
fi

# Remove Bash History (General user)
BashHistoryFlag=$(find /home -name ".bash_history" | wc -l)

if [ $BashHistoryFlag -gt 0 ]; then
	# Bash History File List
	BashHistoryList=$(find /home -name ".bash_history")

	# Remove Bash History (General user)
	for BashHistory in $BashHistoryList
	do
		echo "[Remove Bash History] :" $BashHistory
		rm -fv $BashHistory
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
