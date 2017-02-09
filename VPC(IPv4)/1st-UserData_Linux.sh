#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data.log || logger -t user-data -s 2> /dev/console) 2>&1

echo "#########################################################################"
echo " This script name is `basename $0`"
echo "#########################################################################"

#-------------------------------------------------------------------------------
# Parameter Settings
#-------------------------------------------------------------------------------

# Parameter Settings(Script)
SelectScript="https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/VPC(IPv4)/2nd-Select_Linux.sh"

# Parameter Settings(SetupMode)
SetupMode="Japanese"

#-------------------------------------------------------------------------------
# Select Script Execute
#-------------------------------------------------------------------------------

cd /tmp

# Download SelectScript
if [ $(command -v curl) ]; then
    curl --retry 5 --output SelectScript.sh ${SelectScript} 
else
    wget --tries=5 --no-check-certificate --output-document=SelectScript.sh ${SelectScript} 
fi

# Execute SelectScript
chmod 700 SelectScript.sh

SetupMode=$SetupMode bash -x SelectScript.sh
