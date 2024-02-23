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
		grubby --info=ALL
	else
		DEFAULTKERNEL=$(rpm -qa | grep -ie `uname -r` | grep -ie "kernel-" | awk '{print length, $0}' | sort -n | head -n 1 | awk '{print $2}')
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

		# Show Linux Boot Program information
		if [ $(command -v grubby) ]; then
			grubby --info=ALL
		fi

		# Removing old kernel packages
		dnf remove -y $(dnf repoquery --installonly --latest-limit=-1 -q)
		sleep 5

		# Show Linux Boot Program information
		if [ $(command -v grubby) ]; then
			grubby --info=ALL
		fi

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

		# Show Linux Boot Program information
		if [ $(command -v grubby) ]; then
			grubby --info=ALL
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

# [Creation of execution flags]
touch /perform_cleanup

if [[ ! -f {{workingDirectory}}/perform_cleanup ]]; then
    echo "Skipping cleanup"
    exit 0
else
    sudo rm -f {{workingDirectory}}/perform_cleanup
fi

function cleanup() {
    FILES=("$@")
    for FILE in "${FILES[@]}"; do
        if [[ -f "$FILE" ]]; then
            echo "Deleting $FILE";
            sudo shred -zuf $FILE;
        fi;
        if [[ -f $FILE ]]; then
            echo "Failed to delete '$FILE'. Failing."
            exit 1
        fi;
    done
};


# Clean up for cloud-init files
CLOUD_INIT_FILES=(
    "/etc/sudoers.d/90-cloud-init-users"
    "/etc/locale.conf"
    "/var/log/cloud-init.log"
    "/var/log/cloud-init-output.log"
)
if [[ -f {{workingDirectory}}/skip_cleanup_cloudinit_files ]]; then
    echo "Skipping cleanup of cloud init files"
else
    echo "Cleaning up cloud init files"
    cleanup "${CLOUD_INIT_FILES[@]}"
    if [[ $( sudo find /var/lib/cloud -type f | sudo wc -l ) -gt 0 ]]; then
        echo "Deleting files within /var/lib/cloud/*"
        sudo find /var/lib/cloud -type f -exec shred -zuf {} \;
    fi;

    if [[ $( sudo ls /var/lib/cloud | sudo wc -l ) -gt 0 ]]; then
        echo "Deleting /var/lib/cloud/*"
        sudo rm -rf /var/lib/cloud/* || true
    fi;
fi;


# Clean up for temporary instance files
INSTANCE_FILES=(
    "/etc/.updated"
    "/etc/aliases.db"
    "/etc/hostname"
    "/var/lib/misc/postfix.aliasesdb-stamp"
    "/var/lib/postfix/master.lock"
    "/var/spool/postfix/pid/master.pid"
    "/var/.updated"
    "/var/cache/yum/x86_64/2/.gpgkeyschecked.yum"
)
if [[ -f {{workingDirectory}}/skip_cleanup_instance_files ]]; then
    echo "Skipping cleanup of instance files"
else
    echo "Cleaning up instance files"
    cleanup "${INSTANCE_FILES[@]}"
fi;


# Clean up for ssh files
SSH_FILES=(
    "/etc/ssh/ssh_host_rsa_key"
    "/etc/ssh/ssh_host_rsa_key.pub"
    "/etc/ssh/ssh_host_ecdsa_key"
    "/etc/ssh/ssh_host_ecdsa_key.pub"
    "/etc/ssh/ssh_host_ed25519_key"
    "/etc/ssh/ssh_host_ed25519_key.pub"
    "/root/.ssh/authorized_keys"
)
if [[ -f {{workingDirectory}}/skip_cleanup_ssh_files ]]; then
    echo "Skipping cleanup of ssh files"
else
    echo "Cleaning up ssh files"
    cleanup "${SSH_FILES[@]}"
    USERS=$(ls /home/)
    for user in $USERS; do
        echo Deleting /home/"$user"/.ssh/authorized_keys;
        sudo find /home/"$user"/.ssh/authorized_keys -type f -exec shred -zuf {} \;
    done
    for user in $USERS; do
        if [[ -f /home/"$user"/.ssh/authorized_keys ]]; then
            echo Failed to delete /home/"$user"/.ssh/authorized_keys;
            exit 1
        fi;
    done;
fi;


# Clean up for instance log files
INSTANCE_LOG_FILES=(
    "/var/log/audit/audit.log"
    "/var/log/boot.log"
    "/var/log/dmesg"
    "/var/log/cron"
)
if [[ -f {{workingDirectory}}/skip_cleanup_instance_log_files ]]; then
    echo "Skipping cleanup of instance log files"
else
    echo "Cleaning up instance log files"
    cleanup "${INSTANCE_LOG_FILES[@]}"
fi;

# Clean up for TOE files
if [[ -f {{workingDirectory}}/skip_cleanup_toe_files ]]; then
    echo "Skipping cleanup of TOE files"
else
    echo "Cleaning TOE files"
    if [[ $( sudo find {{workingDirectory}}/TOE_* -type f | sudo wc -l) -gt 0 ]]; then
        echo "Deleting files within {{workingDirectory}}/TOE_*"
        sudo find {{workingDirectory}}/TOE_* -type f -exec shred -zuf {} \;
    fi
    if [[ $( sudo find {{workingDirectory}}/TOE_* -type f | sudo wc -l) -gt 0 ]]; then
        echo "Failed to delete {{workingDirectory}}/TOE_*"
        exit 1
    fi
    if [[ $( sudo find {{workingDirectory}}/TOE_* -type d | sudo wc -l) -gt 0 ]]; then
        echo "Deleting {{workingDirectory}}/TOE_*"
        sudo rm -rf {{workingDirectory}}/TOE_*
    fi
    if [[ $( sudo find {{workingDirectory}}/TOE_* -type d | sudo wc -l) -gt 0 ]]; then
        echo "Failed to delete {{workingDirectory}}/TOE_*"
        exit 1
    fi
fi

# Clean up for ssm log files
if [[ -f {{workingDirectory}}/skip_cleanup_ssm_log_files ]]; then
    echo "Skipping cleanup of ssm log files"
else
    echo "Cleaning up ssm log files"
    if [[ $( sudo find /var/log/amazon/ssm -type f | sudo wc -l) -gt 0 ]]; then
        echo "Deleting files within /var/log/amazon/ssm/*"
        sudo find /var/log/amazon/ssm -type f -exec shred -zuf {} \;
    fi
    if [[ $( sudo find /var/log/amazon/ssm -type f | sudo wc -l) -gt 0 ]]; then
        echo "Failed to delete /var/log/amazon/ssm"
        exit 1
    fi
    if [[ -d "/var/log/amazon/ssm" ]]; then
        echo "Deleting /var/log/amazon/ssm/*"
        sudo rm -rf /var/log/amazon/ssm
    fi
    if [[ -d "/var/log/amazon/ssm" ]]; then
        echo "Failed to delete /var/log/amazon/ssm"
        exit 1
    fi
fi


if [[ $( sudo find /var/log/sa/sa* -type f | sudo wc -l ) -gt 0 ]]; then
    echo "Deleting /var/log/sa/sa*"
    sudo shred -zuf /var/log/sa/sa*
fi
if [[ $( sudo find /var/log/sa/sa* -type f | sudo wc -l ) -gt 0 ]]; then
    echo "Failed to delete /var/log/sa/sa*"
    exit 1
fi

if [[ $( sudo find /var/lib/dhclient/dhclient*.lease -type f | sudo wc -l ) -gt 0 ]]; then
        echo "Deleting /var/lib/dhclient/dhclient*.lease"
        sudo shred -zuf /var/lib/dhclient/dhclient*.lease
fi
if [[ $( sudo find /var/lib/dhclient/dhclient*.lease -type f | sudo wc -l ) -gt 0 ]]; then
        echo "Failed to delete /var/lib/dhclient/dhclient*.lease"
        exit 1
fi

if [[ $( sudo find /var/tmp -type f | sudo wc -l) -gt 0 ]]; then
        echo "Deleting files within /var/tmp/*"
        sudo find /var/tmp -type f -exec shred -zuf {} \;
fi
if [[ $( sudo find /var/tmp -type f | sudo wc -l) -gt 0 ]]; then
        echo "Failed to delete /var/tmp"
        exit 1
fi
if [[ $( sudo ls /var/tmp | sudo wc -l ) -gt 0 ]]; then
        echo "Deleting /var/tmp/*"
        sudo rm -rf /var/tmp/*
fi

# Shredding is not guaranteed to work well on rolling logs

if [[ -f "/var/lib/rsyslog/imjournal.state" ]]; then
        echo "Deleting /var/lib/rsyslog/imjournal.state"
        sudo shred -zuf /var/lib/rsyslog/imjournal.state
        sudo rm -f /var/lib/rsyslog/imjournal.state
fi

if [[ $( sudo ls /var/log/journal/ | sudo wc -l ) -gt 0 ]]; then
        echo "Deleting /var/log/journal/*"
        sudo find /var/log/journal/ -type f -exec shred -zuf {} \;
        sudo rm -rf /var/log/journal/*
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
# Cleanup process for Configuration Files, and Log Files
#-------------------------------------------------------------------------------

# Remove temporary files
rm -rf /tmp/*
rm -rf /var/tmp/*

# Remove /var/log files
find /var/log/ -type f -name \* -exec cp -f /dev/null {} \;

# Remove /var/log/user-data_*.log and txt files
rm -rf /var/log/user-data_*.log
rm -rf /var/log/user-data_*.txt

#-------------------------------------------------------------------------------
# Cleanup process for Machine ID
#-------------------------------------------------------------------------------

# Cleanup Machine information
if [ -f /etc/machine-id ]; then
	echo "[Cleanup Machine information] : /etc/machine-id"

	cat "/etc/machine-id"

	if [ $(command -v systemd-machine-id-setup) ]; then

		# [Reference]
		# https://access.redhat.com/solutions/3600401
		systemd-machine-id-setup --print
		systemd-machine-id-setup

		# [Workaround]
		cat /dev/null > "/etc/machine-id"
	else
		cat /dev/null > "/etc/machine-id"
	fi

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
