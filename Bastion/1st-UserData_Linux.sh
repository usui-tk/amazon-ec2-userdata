#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data_1st-userdata.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Parameter Settings
#-------------------------------------------------------------------------------

# Parameter Settings(Script)
DecisionScript="https://raw.githubusercontent.com/usui-tk/amazon-ec2-userdata/master/Bastion/2nd-Decision_Linux-Distribution.sh"

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

# Download Decision_Linux-Distribution.sh
if [ $(command -v curl) ]; then
    curl --retry 5 --output Decision_Linux-Distribution.sh ${DecisionScript} 
else
    wget --tries=5 --no-check-certificate --output-document=Decision_Linux-Distribution.sh ${DecisionScript} 
fi

# Execute Decision_Linux-Distribution.sh
chmod 700 Decision_Linux-Distribution.sh

bash -x Decision_Linux-Distribution.sh
