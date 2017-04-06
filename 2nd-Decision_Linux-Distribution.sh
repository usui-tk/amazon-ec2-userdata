#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data_2nd-decision.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Parameter Settings
#-------------------------------------------------------------------------------

# Parameter Settings(BootstrapScript)
ScriptForAmazonLinux='https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/3rd-Bootstrap_AmazonLinux-HVM.sh'
ScriptForRHELv7="https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/3rd-Bootstrap_RHEL-v7-HVM.sh"
ScriptForRHELv6="https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/3rd-Bootstrap_RHEL-v6-HVM.sh"
ScriptForCentOSv7="https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/3rd-Bootstrap_CentOS-v7-HVM.sh"
ScriptForCentOSv6="https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/3rd-Bootstrap_CentOS-v6-HVM.sh"
ScriptForUbuntu1604="https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/3rd-Bootstrap_Ubuntu-16.04-LTS-HVM.sh"

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
      elif [ -f /etc/redhat-release ]; then
          DIST_TYPE='RHEL'
          DIST=`cat /etc/redhat-release | sed s/\ release.*//`
          REV=`cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//`
      elif [ -f /etc/system-release ]; then
          if grep "Amazon Linux AMI" /etc/system-release; then
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
    if [ "${DIST_TYPE}" = "Amazon" ] || [ "${DIST_TYPE}" = "amzn" ]; then
        # Bootstrap Script for Amazon Linux
        BootstrapScript=${ScriptForAmazonLinux}
    elif [ "${DIST_TYPE}" = "RHEL" ] || [ "${DIST_TYPE}" = "rhel" ]; then
        if [ $(echo ${REV} | grep -e '7.') ]; then
           # Bootstrap Script for Red Hat Enterprise Linux v7.x
           BootstrapScript=${ScriptForRHELv7}
        elif [ $(echo ${REV} | grep -e '6.') ]; then
           # Bootstrap Script for Red Hat Enterprise Linux v6.x
           BootstrapScript=${ScriptForRHELv6}
        else
           BootstrapScript=""
        fi
    elif [ "${DIST_TYPE}" = "CentOS" ] || [ "${DIST_TYPE}" = "centos" ]; then
        if [ $(echo ${REV} | grep -e '7.') ]; then
           # Bootstrap Script for CentOS v7.x
           BootstrapScript=${ScriptForCentOSv7}
        elif [ $(echo ${REV} | grep -e '6.') ]; then
           # Bootstrap Script for CentOS v6.x
           BootstrapScript=${ScriptForCentOSv6}
        else
           BootstrapScript=""
        fi
    elif [ "${DIST_TYPE}" = "Ubuntu" ] || [ "${DIST_TYPE}" = "ubuntu" ]; then
        if [ "${REV}" = "16.04" ]; then
           # Bootstrap Script for Ubuntu 16.04 LTS
           BootstrapScript=${ScriptForUbuntu1604}
        else
           BootstrapScript=""
        fi    
    else
        BootstrapScript=""
    fi

    if [ -z "${BootstrapScript}" ]; then
       echo "Unsupported Bootstrap Script Linux distribution"
       exit 1
    fi
}


#-------------------------------------------------------------------------------
# Main Routine
#-------------------------------------------------------------------------------

# Install curl Command
if [ $(command -v yum) ]; then
    # Package Install curl Tools (Amazon Linux, Red Hat Enterprise Linux, CentOS)
    yum clean all
    yum install -y curl
elif [ $(command -v apt-get) ]; then
    # Package Install curl Tools (Debian, Ubuntu)
    apt-get install -y curl
else
    echo "Unsupported distribution: ${DIST} and distribution type: ${DIST_TYPE}"
    exit 1
fi

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

#-------------------------------------------------------------------------------
# Bootstrap Script Executite
#-------------------------------------------------------------------------------

bash -vc "$(curl -L ${BootstrapScript})"
