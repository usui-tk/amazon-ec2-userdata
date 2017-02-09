#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data.log || logger -t user-data -s 2> /dev/console) 2>&1

echo "#########################################################################"
echo " This script name is `basename $0`"
echo "#########################################################################"

#-------------------------------------------------------------------------------
# Parameter Settings
#-------------------------------------------------------------------------------

# Parameter Settings(SetupMode)
echo $SetupMode

# Parameter Settings(BootstrapScript)
BootstrapAmazonLinux='https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/VPC-IPv4/2nd-Bootstrap_AmazonLinux-2016.09.1-HVM.sh'
BootstrapRHELv7="https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/VPC-IPv4/2nd-Bootstrap_RHEL-v7-HVM.sh"
BootstrapRHELv6="https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/VPC-IPv4/2nd-Bootstrap_RHEL-v6-HVM.sh"
BootstrapCentOSv7="https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/VPC-IPv4/2nd-Bootstrap_CentOS-v7-HVM.sh"



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
      fi
    fi

    LOWERCASE_DIST_TYPE=`lowercase $DIST_TYPE`
    UNIQ_OS_ID="${LOWERCASE_DIST_TYPE}-${KERNEL}-${MACH}"
    UNIQ_PLATFORM_ID="${LOWERCASE_DIST_TYPE}-${KERNEL_GROUP}."

    if [ "${DIST_TYPE}" = "Amazon" ] || [ "${DIST_TYPE}" = "amzn" ]; then
          BootstrapScript=${BootstrapAmazonLinux}
    elif [ "${DIST_TYPE}" = "RHEL" ] || [ "${DIST_TYPE}" = "RedHat" ]; then
        if [ "${REV}" = "7" ]; then
           BootstrapScript=${BootstrapRHELv7}
        elif [ "${REV}" = "6" ]; then
           BootstrapScript=${BootstrapRHELv6}
        else
           BootstrapScript=""
    elif [ "${DIST_TYPE}" = "CentOS" ] || [ "${DIST_TYPE}" = "centos" ]; then
        if [ "${REV}" = "7" ]; then
           BootstrapScript=${BootstrapCentOSv7}
        else
           BootstrapScript=""
    else
        BootstrapScript=""
    fi

    if [[ -z "${DIST}" || -z "${DIST_TYPE}" ]]; then
       echo "Unsupported distribution: ${DIST} and distribution type: ${DIST_TYPE}"
       # exit 1
    fi
}



#-------------------------------------------------------------------------------
# Main Routine
#-------------------------------------------------------------------------------

# yum repository metadata Clean up
yum clean all

# Package Install curl Tools
yum install -y curl

# Instance MetaData
AZ=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
Region=$(echo $AZ | sed -e 's/.$//g')
InstanceId=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
InstanceType=$(curl -s http://169.254.169.254/latest/meta-data/instance-type)
PrivateIp=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
AmiId=$(curl -s http://169.254.169.254/latest/meta-data/ami-id)

# call the os info function to get details
get_os_info

# Information Linux Distribution
KERNEL_VERSION=$(uname -r )
KERNEL_GROUP=$(echo "${KERNEL_VERSION}" | cut -f 1-2 -d'.')
KERNEL_VERSION_WO_ARCH=$(basename ${KERNEL_VERSION} .x86_64)

echo "Distribution of the machine is ${DIST}." 
echo "Distribution type of the machine is ${DIST_TYPE}."
echo "Revision of the distro is ${REV}."
echo "Kernel version of the machine is ${KERNEL_VERSION}."

echo "Bootstrap Script of the distro is ${BootstrapScript}."


#-------------------------------------------------------------------------------
# Bootstrap Script Executite
#-------------------------------------------------------------------------------

SetupMode=$SetupMode bash -vc "$(curl -L ${BootstrapScript})"
