#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data_1st-userdata.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Parameter Settings
#-------------------------------------------------------------------------------

# Parameter Settings(Script)
SelectScript="https://raw.githubusercontent.com/usui-tk/AWS-CloudInit_BootstrapScript/master/2nd-Select_Linux.sh"

# Parameter file Settings
cat > /tmp/userdata-parameter << __EOF__
# Language [ja_JP.UTF-8],[en_US.UTF-8]
Language="ja_JP.UTF-8"

# Timezone [Asia/Tokyo],[UTC]
Timezone="Asia/Tokyo"

# VPC Network [IPv4],[IPv6]
VpcNetwork="IPv4"
__EOF__

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

bash -x SelectScript.sh
