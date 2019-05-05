#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data_2nd-decision.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Parameter Settings
#-------------------------------------------------------------------------------

# Parameter Settings(BootstrapScript)
ScriptForAmazonLinux1="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_AmazonLinux-1-HVM.sh"
ScriptForAmazonLinux2="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_AmazonLinux-2-LTS-HVM.sh"
ScriptForRHELv7="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_RHEL-v7-HVM.sh"
ScriptForRHELv6="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_RHEL-v6-HVM.sh"
ScriptForCentOSv7="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_CentOS-v7-HVM.sh"
ScriptForCentOSv6="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_CentOS-v6-HVM.sh"
ScriptForOracleLinuxv7="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_OracleLinux-v7-HVM.sh"
ScriptForOracleLinuxv6="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_OracleLinux-v6-HVM.sh"
ScriptForUbuntu1804="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Ubuntu-18.04-LTS-HVM.sh"
ScriptForUbuntu1604="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Ubuntu-16.04-LTS-HVM.sh"
ScriptForSLESv15="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_SLES-v15-HVM.sh"
ScriptForSLESv12="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_SLES-v12-HVM.sh"
ScriptForDebian9="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Debian-9-HVM.sh"

ScriptForFedora="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Fedora-HVM.sh"
ScriptForKaliLinux="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/3rd-Bootstrap_Kali-Linux-HVM.sh"

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
      elif [ -f /etc/centos-release ]; then
          DIST_TYPE='CentOS'
          DIST=`cat /etc/centos-release | sed s/\ release.*//`
          REV=`cat /etc/centos-release | sed s/.*release\ // | sed s/\ .*//`
      elif [ -f /etc/oracle-release ]; then
          DIST_TYPE='Oracle'
          DIST=`cat /etc/oracle-release | sed s/\ release.*//`
          REV=`cat /etc/oracle-release | sed s/.*release\ // | sed s/\ .*//`
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
        if [ $(echo ${REV} | grep -e '7.') ]; then
           # Bootstrap Script for Red Hat Enterprise Linux v7.x
           BootstrapScript=${ScriptForRHELv7}
        elif [ $(echo ${REV} | grep -e '6.') ]; then
           # Bootstrap Script for Red Hat Enterprise Linux v6.x
           BootstrapScript=${ScriptForRHELv6}
        else
           BootstrapScript=""
        fi
    elif [ "${DIST}" = "CentOS" ] || [ "${DIST_TYPE}" = "centos" ]; then
        if [ "${REV}" = "7" ]; then
           # Bootstrap Script for CentOS v7.x
           BootstrapScript=${ScriptForCentOSv7}
        elif [ $(echo ${REV} | grep -e '6.') ]; then
           # Bootstrap Script for CentOS v6.x
           BootstrapScript=${ScriptForCentOSv6}
        else
           BootstrapScript=""
        fi
    elif [ "${DIST}" = "Oracle Linux Server" ] || [ "${DIST_TYPE}" = "ol" ]; then
        if [ $(echo ${REV} | grep -e '7.') ]; then
           # Bootstrap Script for Oracle Linux v7.x
           BootstrapScript=${ScriptForOracleLinuxv7}
        elif [ $(echo ${REV} | grep -e '6.') ]; then
           # Bootstrap Script for Oracle Linux v6.x
           BootstrapScript=${ScriptForOracleLinuxv6}
        else
           BootstrapScript=""
        fi
    elif [ "${DIST}" = "Ubuntu" ] || [ "${DIST_TYPE}" = "ubuntu" ]; then
        if [ $(echo ${REV} | grep -e '18.04') ]; then
           # Bootstrap Script for Ubuntu 18.04 LTS
           BootstrapScript=${ScriptForUbuntu1804}
        elif [ $(echo ${REV} | grep -e '16.04') ]; then
           # Bootstrap Script for Ubuntu 16.04 LTS
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
    elif [ "${DIST}" = "Fedora" ] || [ "${DIST_TYPE}" = "fedora" ]; then
        if [ $(echo ${REV} | grep -e '30') ]; then
           # Bootstrap Script for Fedora 30
           BootstrapScript=${ScriptForFedora}
        elif [ $(echo ${REV} | grep -e '29') ]; then
           # Bootstrap Script for Fedora 29
           BootstrapScript=${ScriptForFedora}
        elif [ $(echo ${REV} | grep -e '28') ]; then
           # Bootstrap Script for Fedora 28
           BootstrapScript=${ScriptForFedora}
        elif [ $(echo ${REV} | grep -e '27') ]; then
           # Bootstrap Script for Fedora 27
           BootstrapScript=${ScriptForFedora}
        else
           BootstrapScript=""
        fi    
    elif [ "${DIST}" = "Debian GNU/Linux" ] || [ "${DIST_TYPE}" = "debian" ]; then
        if [ $(echo ${REV} | grep -e '9') ]; then
           # Bootstrap Script for Debian GNU/Linux 9 (Stretch)
           BootstrapScript=${ScriptForDebian9}
        else
           BootstrapScript=""
        fi    
    elif [ "${DIST}" = "Kali GNU/Linux" ] || [ "${DIST_TYPE}" = "kali" ]; then
        if [ $(echo ${REV} | grep -e '2018.') ]; then
           # Bootstrap Script for Kali Linux 2018.x
           BootstrapScript=${ScriptForKaliLinux}
        elif [ $(echo ${REV} | grep -e '2017.') ]; then
           # Bootstrap Script for Kali Linux 2017.x
           BootstrapScript=${ScriptForKaliLinux}
        else
           BootstrapScript=""
        fi    
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

echo "BootstrapScript of the distro is ${BootstrapScript}."

# Install curl Command
if [ $(command -v curl) ]; then
    echo "Preinstalled curl command - Linux distribution: ${DIST} and distribution type: ${DIST_TYPE}"
else 
    if [ $(command -v yum) ]; then
        # Package Install curl Tools (Amazon Linux, Red Hat Enterprise Linux, CentOS, Oracle Linux)
        yum clean all
        yum install -y curl
    elif [ $(command -v apt-get) ]; then
        # Package Install curl Tools (Debian, Ubuntu)
        apt install -y curl
    elif [ $(command -v zypper) ]; then
        # Package Install curl Tools (SUSE Linux Enterprise Server)
        zypper --non-interactive install curl
    else
        echo "Unsupported distribution: ${DIST} and distribution type: ${DIST_TYPE}"
        exit 1
    fi
fi

#-------------------------------------------------------------------------------
# Bootstrap Script Executite
#-------------------------------------------------------------------------------

bash -vc "$(curl -L ${BootstrapScript})"
