#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data_2nd-decision.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Parameter Settings
#-------------------------------------------------------------------------------

if [ $(uname -m) = "x86_64" ]; then

   # [For x86_64] Parameter Settings (BootstrapScript - Script dependent on operating system version)
   ScriptForAmazonLinux2="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_AmazonLinux-2-LTS-HVM.sh"
   ScriptForAmazonLinux1="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_AmazonLinux-1-HVM.sh"
   ScriptForRHELv8="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_RHEL-v8-HVM.sh"
   ScriptForRHELv7="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_RHEL-v7-HVM.sh"
   ScriptForRHELv6="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_RHEL-v6-HVM.sh"
   ScriptForRockyLinuxv8="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_RockyLinux-v8-HVM.sh"
   ScriptForAlmaLinuxv8="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_AlmaLinux-v8-HVM.sh"
   ScriptForCentOSv8="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_CentOS-v8-HVM.sh"
   ScriptForCentOSv7="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_CentOS-v7-HVM.sh"
   ScriptForCentOSv6="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_CentOS-v6-HVM.sh"
   ScriptForOracleLinuxv8="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_OracleLinux-v8-HVM.sh"
   ScriptForOracleLinuxv7="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_OracleLinux-v7-HVM.sh"
   ScriptForOracleLinuxv6="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_OracleLinux-v6-HVM.sh"
   ScriptForUbuntu2004="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Ubuntu-20.04-LTS-HVM.sh"
   ScriptForUbuntu1804="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Ubuntu-18.04-LTS-HVM.sh"
   ScriptForUbuntu1604="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Ubuntu-16.04-LTS-HVM.sh"
   ScriptForSLESv15="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_SLES-v15-HVM.sh"
   ScriptForSLESv12="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_SLES-v12-HVM.sh"
   ScriptForDebian11="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Debian-11-HVM.sh"
   ScriptForDebian10="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Debian-10-HVM.sh"
   ScriptForDebian9="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Debian-9-HVM.sh"
   ScriptForPhotonOS3="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Photon-3-HVM.sh"

   # [For x86_64] Parameter Settings (BootstrapScript - Script independent of operating system version [operation check requires a specific version or higher])
   ScriptForFedora="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Fedora-HVM.sh"
   ScriptForOpenSUSE="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_OpenSUSE-HVM.sh"
   ScriptForKaliLinux="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Kali-Linux-HVM.sh"

# elif [ $(uname -m) = "aarch64" ]; then
#    echo "To Be Update for aarch64"
#    exit 0
   # [For aarch64] Parameter Settings (BootstrapScript - Script dependent on operating system version)
   # ScriptForAmazonLinux2="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_AmazonLinux-2-LTS-HVM.sh"
   # ScriptForRHELv8="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_RHEL-v8-HVM.sh"
   # ScriptForAlmaLinuxv8="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_AlmaLinux-v8-HVM.sh"
   # ScriptForOracleLinuxv8="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_OracleLinux-v8-HVM.sh"
   # ScriptForUbuntu2004="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Ubuntu-20.04-LTS-HVM.sh"
   # ScriptForSLESv15="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_SLES-v15-HVM.sh"
   # ScriptForDebian10="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Debian-10-HVM.sh"

# else
#    echo "None"
#    exit 0

fi

#-------------------------------------------------------------------------------
# Define Function
#-------------------------------------------------------------------------------

function lowercase(){
   echo "$1" | sed "y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/"
}

function uppercase(){
   echo "$1" | sed "y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/"
}

function get_os_info () {
   OS=`lowercase \`uname\``
   KERNEL=`uname -r`
   MACH=`uname -m`
   KERNEL_GROUP=$(echo $KERNEL | cut -f1-2 -d'.')

   if [ "${OS}" = "linux" ] ; then
      if [ -f /etc/os-release ]; then
         source /etc/os-release
         DIST_TYPE=$ID
         DIST=$NAME
         REV=$VERSION_ID
      elif [ -f /etc/rocky-release ]; then
         DIST_TYPE='Rocky Linux'
         DIST=`cat /etc/rocky-release | sed s/\ release.*//`
         REV=`cat /etc/rocky-release | sed s/.*release\ // | sed s/\ .*//`
      elif [ -f /etc/almalinux-release ]; then
         DIST_TYPE='AlmaLinux'
         DIST=`cat /etc/almalinux-release | sed s/\ release.*//`
         REV=`cat /etc/almalinux-release | sed s/.*release\ // | sed s/\ .*//`
      elif [ -f /etc/oracle-release ]; then
         DIST_TYPE='Oracle'
         DIST=`cat /etc/oracle-release | sed s/\ release.*//`
         REV=`cat /etc/oracle-release | sed s/.*release\ // | sed s/\ .*//`
      elif [ -f /etc/centos-release ]; then
         DIST_TYPE='CentOS'
         DIST=`cat /etc/centos-release | sed s/\ release.*//`
         REV=`cat /etc/centos-release | sed s/.*release\ // | sed s/\ .*//`
      elif [ -f /etc/fedora-release ]; then
         DIST_TYPE='Fedora'
         DIST=`cat /etc/fedora-release | sed s/\ release.*//`
         REV=`cat /etc/fedora-release | sed s/.*release\ // | sed s/\ .*//`
      elif [ -f /etc/redhat-release ]; then
         DIST_TYPE='RHEL'
         DIST=`cat /etc/redhat-release | sed s/\ release.*//`
         REV=`cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//`
      elif [ -f /etc/system-release ]; then
         if grep "Amazon Linux" /etc/system-release; then
            DIST_TYPE='Amazon'
         fi
         DIST=`cat /etc/system-release | sed s/\ release.*//`
         REV=`cat /etc/system-release | sed s/.*release\ // | sed s/\ .*//`
      else
         DIST_TYPE=""
         DIST=""
         REV=""
      fi
    fi

    if [[ -z "${DIST}" || -z "${DIST_TYPE}" ]]; then
      echo "Unsupported distribution: ${DIST} and distribution type: ${DIST_TYPE}"
      exit 1
    fi

   LOWERCASE_DIST_TYPE=`lowercase $DIST_TYPE`
   UNIQ_OS_ID="${LOWERCASE_DIST_TYPE}-${KERNEL}-${MACH}"
   UNIQ_PLATFORM_ID="${LOWERCASE_DIST_TYPE}-${KERNEL_GROUP}."
}

function get_bootstrap_script () {
   # Select a Bootstrap script
   if [ "${DIST}" = "Amazon Linux AMI" ] || [ "${DIST}" = "Amazon Linux" ] || [ "${DIST_TYPE}" = "amzn" ]; then
         if [ "${REV}" = "2" ]; then
            # Bootstrap Script for Amazon Linux 2.x [Caution - Workaround]
            BootstrapScript=${ScriptForAmazonLinux2}
         elif [ $(echo ${REV} | grep -e '201') ]; then
            # Bootstrap Script for Amazon Linux 1.x (2011.09 - 2017.09)
            BootstrapScript=${ScriptForAmazonLinux1}
         else
            BootstrapScript=""
         fi
   elif [ "${DIST}" = "RHEL" ] || [ "${DIST}" = "Red Hat Enterprise Linux Server" ] || [ "${DIST_TYPE}" = "rhel" ]; then
         if [ $(echo ${REV} | grep -e '8.') ]; then
            # Bootstrap Script for Red Hat Enterprise Linux v8.x
            BootstrapScript=${ScriptForRHELv8}
         elif [ $(echo ${REV} | grep -e '7.') ]; then
            # Bootstrap Script for Red Hat Enterprise Linux v7.x
            BootstrapScript=${ScriptForRHELv7}
         elif [ $(echo ${REV} | grep -e '6.') ]; then
            # Bootstrap Script for Red Hat Enterprise Linux v6.x
            BootstrapScript=${ScriptForRHELv6}
         else
            BootstrapScript=""
         fi
   elif [ "${DIST}" = "Rocky Linux" ] || [ "${DIST_TYPE}" = "rocky" ]; then
         if [ $(echo ${REV} | grep -e '8.') ]; then
            # Bootstrap Script for Rocky Linux v8.x
            BootstrapScript=${ScriptForRockyLinuxv8}
         else
            BootstrapScript=""
         fi
   elif [ "${DIST}" = "AlmaLinux" ] || [ "${DIST_TYPE}" = "almalinux" ]; then
         if [ $(echo ${REV} | grep -e '8.') ]; then
            # Bootstrap Script for AlmaLinux v8.x
            BootstrapScript=${ScriptForAlmaLinuxv8}
         else
            BootstrapScript=""
         fi
   elif [ "${DIST}" = "CentOS" ] || [ "${DIST_TYPE}" = "centos" ]; then
         if [ "${REV}" = "8" ]; then
            # Bootstrap Script for CentOS v8.x
            BootstrapScript=${ScriptForCentOSv8}
         elif [ "${REV}" = "7" ]; then
            # Bootstrap Script for CentOS v7.x
            BootstrapScript=${ScriptForCentOSv7}
         elif [ $(echo ${REV} | grep -e '6.') ]; then
            # Bootstrap Script for CentOS v6.x
            BootstrapScript=${ScriptForCentOSv6}
         else
            BootstrapScript=""
         fi
   elif [ "${DIST}" = "Oracle Linux Server" ] || [ "${DIST_TYPE}" = "ol" ]; then
         if [ $(echo ${REV} | grep -e '8.') ]; then
            # Bootstrap Script for Oracle Linux v8.x
            BootstrapScript=${ScriptForOracleLinuxv8}
         elif [ $(echo ${REV} | grep -e '7.') ]; then
            # Bootstrap Script for Oracle Linux v7.x
            BootstrapScript=${ScriptForOracleLinuxv7}
         elif [ $(echo ${REV} | grep -e '6.') ]; then
            # Bootstrap Script for Oracle Linux v6.x
            BootstrapScript=${ScriptForOracleLinuxv6}
         else
            BootstrapScript=""
         fi
   elif [ "${DIST}" = "Ubuntu" ] || [ "${DIST_TYPE}" = "ubuntu" ]; then
         if [ $(echo ${REV} | grep -e '20.04') ]; then
            # Bootstrap Script for Ubuntu 20.04 LTS (Focal Fossa)
            BootstrapScript=${ScriptForUbuntu2004}
         elif [ $(echo ${REV} | grep -e '18.04') ]; then
            # Bootstrap Script for Ubuntu 18.04 LTS (Bionic Beaver)
            BootstrapScript=${ScriptForUbuntu1804}
         elif [ $(echo ${REV} | grep -e '16.04') ]; then
            # Bootstrap Script for Ubuntu 16.04 LTS (Xenial Xerus)
            BootstrapScript=${ScriptForUbuntu1604}
         else
            BootstrapScript=""
         fi
   elif [ "${DIST}" = "SLES" ] || [ "${DIST_TYPE}" = "sles" ]; then
         if [ $(echo ${REV} | grep -e '15') ]; then
            # Bootstrap Script for SUSE Linux Enterprise Server 15
            BootstrapScript=${ScriptForSLESv15}
         elif [ $(echo ${REV} | grep -e '12.') ]; then
            # Bootstrap Script for SUSE Linux Enterprise Server 12
            BootstrapScript=${ScriptForSLESv12}
         else
            BootstrapScript=""
         fi
   elif [ "${DIST}" = "Debian GNU/Linux" ] || [ "${DIST_TYPE}" = "debian" ]; then
         if [ $(echo ${REV} | grep -e '11') ]; then
            # Bootstrap Script for Debian GNU/Linux 11 (Bullseye)
            BootstrapScript=${ScriptForDebian11}
         elif [ $(echo ${REV} | grep -e '10') ]; then
            # Bootstrap Script for Debian GNU/Linux 10 (Buster)
            BootstrapScript=${ScriptForDebian10}
         elif [ $(echo ${REV} | grep -e '9') ]; then
            # Bootstrap Script for Debian GNU/Linux 9 (Stretch)
            BootstrapScript=${ScriptForDebian9}
         else
            BootstrapScript=""
         fi
   elif [ "${DIST}" = "VMware Photon OS" ] || [ "${DIST_TYPE}" = "photon" ]; then
         if [ $(echo ${REV} | grep -e '3.') ]; then
            # Bootstrap Script for VMware Photon OS 3.x
            BootstrapScript=${ScriptForPhotonOS3}
         else
            BootstrapScript=""
         fi
   elif [ "${DIST}" = "Fedora" ] || [ "${DIST_TYPE}" = "fedora" ]; then
      # Bootstrap Script for Fedora
      BootstrapScript=${ScriptForFedora}
   elif [ "${DIST}" = "openSUSE Leap" ] || [ "${DIST_TYPE}" = "opensuse-leap" ]; then
      # Bootstrap Script for openSUSE Leap 15
      BootstrapScript=${ScriptForOpenSUSE}
   elif [ "${DIST}" = "Kali GNU/Linux" ] || [ "${DIST_TYPE}" = "kali" ]; then
      # Bootstrap Script for Kali Linux 2020.x
      BootstrapScript=${ScriptForKaliLinux}
   else
      BootstrapScript=""
   fi

   # Bootstrap script determination
   if [ -z "${BootstrapScript}" ]; then
      echo "Unsupported Bootstrap Script Linux distribution"
      exit 1
   fi

}

#-------------------------------------------------------------------------------
# Main Routine
#-------------------------------------------------------------------------------

# call the os info function to get details
get_os_info

# call the bootstrap script function to get details
get_bootstrap_script

# Information Linux Distribution
KERNEL_VERSION=$(uname -r )
KERNEL_GROUP=$(echo "${KERNEL_VERSION}" | cut -f 1-2 -d'.')
KERNEL_VERSION_WO_ARCH=$(basename ${KERNEL_VERSION} .x86_64)

echo "Distribution of the machine is ${DIST}."
echo "Distribution type of the machine is ${DIST_TYPE}."
echo "Revision of the distro is ${REV}."
echo "Kernel version of the machine is ${KERNEL_VERSION}."

echo "BootstrapScript URL is ${BootstrapScript}"

# Install curl/wget Command
if [ $(compgen -ac | sort | uniq | grep -x curl) ] || [ $(compgen -ac | sort | uniq | grep -x wget) ]; then
   echo "Preinstalled curl/wget command - Linux distribution: ${DIST} and distribution type: ${DIST_TYPE}"
else
   if [ $(command -v dnf) ]; then
      # Package Install curl/wget Tools (Red Hat Enterprise Linux, AlmaLinux, CentOS, Oracle Linux)
      dnf clean all
      dnf install -y curl wget
   elif [ $(command -v yum) ]; then
      # Package Install curl/wget Tools (Amazon Linux, Red Hat Enterprise Linux, AlmaLinux, CentOS, Oracle Linux)
      yum clean all
      yum install -y curl wget
   elif [ $(command -v apt-get) ]; then
      # Package Install curl/wget Tools (Debian, Ubuntu)
      export DEBIAN_FRONTEND=noninteractive
      apt clean -y
      apt install -y curl wget
   elif [ $(command -v zypper) ]; then
      # Package Install curl/wget Tools (SUSE Linux Enterprise Server)
      zypper clean --all
      zypper --quiet --non-interactive install curl wget
   elif [ $(command -v tdnf) ]; then
      # Package Install curl/wget Tools (VMware Photon OS)
      tdnf clean all
      tdnf install -y curl wget
   else
      echo "Unsupported curl/wget command - Linux distribution: ${DIST} and distribution type: ${DIST_TYPE}"
      exit 1
   fi
fi

#-------------------------------------------------------------------------------
# Bootstrap Script Executite
#-------------------------------------------------------------------------------

if [ -n "${BootstrapScript}" ]; then
   # Script execution method #1 : Use curl command
   if [ $(compgen -ac | sort | uniq | grep -x curl) ]; then
      echo "Bootstrap Script Executite - ${BootstrapScript}"
      bash -vc "$(curl -L ${BootstrapScript})"
   # Script execution method #2 : Use wget command
   elif [ $(compgen -ac | sort | uniq | grep -x wget) ]; then
      echo "Bootstrap Script Executite - ${BootstrapScript}"
      cd /tmp
      wget --tries=5 --no-check-certificate --output-document=BootstrapScript.sh ${BootstrapScript}
      chmod 700 BootstrapScript.sh
      bash -x BootstrapScript.sh
   fi
fi

#-------------------------------------------------------------------------------
# End of File
#-------------------------------------------------------------------------------
