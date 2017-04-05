#!/bin/bash -v

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Systems Manager (SM) agent]
#-------------------------------------------------------------------------------
# yum localinstall -y https://amazon-ssm-ap-northeast-1.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm

yum localinstall -y https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm


#-------------------------------------------------------------------------------
# Custom Package Installation [AWS CloudWatchLogs Agent]
#-------------------------------------------------------------------------------
# yum --enablerepo=epel install -y python-pip
# pip install --upgrade pip

curl https://s3.amazonaws.com/aws-cloudwatch/downloads/latest/awslogs-agent-setup.py -o /tmp/awslogs-agent-setup.py

cat > /tmp/awslogs.conf << __EOF__
[general]
state_file = /var/awslogs/state/agent-state
use_gzip_http_content_encoding = true

[SYSTEM-sample-Linux-OS-var-log-messages]
log_group_name = SYSTEM-sample-Linux-OS-var-log-messages
log_stream_name = {instance_id}
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/messages
initial_position = start_of_file
encoding = utf-8
buffer_duration = 5000

[SYSTEM-sample-Linux-OS-var-log-secure]
log_group_name = SYSTEM-sample-Linux-OS-var-log-secure
log_stream_name = {instance_id}
datetime_format = %b %d %H:%M:%S
time_zone = LOCAL
file = /var/log/secure
initial_position = start_of_file
encoding = utf-8
buffer_duration = 5000

[SYSTEM-sample-Linux-SSM-Agent-Logs]
log_group_name = SYSTEM-sample-Linux-SSM-Agent-Logs
log_stream_name = {instance_id}
datetime_format = %Y-%m-%d %H:%M:%S
time_zone = LOCAL
file = /var/log/amazon/ssm/amazon-ssm-agent.log
initial_position = start_of_file
encoding = ascii
buffer_duration = 5000

__EOF__

python /tmp/awslogs-agent-setup.py --region ${Region} --configfile /tmp/awslogs.conf --non-interactive

service awslogs status
chkconfig --list awslogs
chkconfig awslogs on
chkconfig --list awslogs
service awslogs restart
service awslogs status



#-------------------------------------------------------------------------------
# Custom Package Installation [AWS CodeDeploy Agent]
#-------------------------------------------------------------------------------
yum install -y ruby

# curl https://aws-codedeploy-ap-southeast-1.s3.amazonaws.com/latest/install -o /tmp/Install-AWS-CodeDeploy-Agent
# curl https://aws-codedeploy-${Region}.s3.amazonaws.com/latest/install -o /tmp/Install-AWS-CodeDeploy-Agent

curl https://aws-codedeploy-${Region}.s3.amazonaws.com/latest/install -o /tmp/Install-AWS-CodeDeploy-Agent

chmod 744 /tmp/Install-AWS-CodeDeploy-Agent

ruby /tmp/Install-AWS-CodeDeploy-Agent auto

cat /opt/codedeploy-agent/.version

chmod 644 /usr/lib/systemd/system/codedeploy-agent.service

systemctl status codedeploy-agent
systemctl enable codedeploy-agent
systemctl is-enabled codedeploy-agent

systemctl restart codedeploy-agent
systemctl status codedeploy-agent



#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Inspector Agent]
#-------------------------------------------------------------------------------
curl https://d1wk0tztpsntt1.cloudfront.net/linux/latest/install -o /tmp/Install-Amazon-Inspector-Agent

chmod 744 /tmp/Install-Amazon-Inspector-Agent
bash /tmp/Install-Amazon-Inspector-Agent

systemctl status awsagent
systemctl enable awsagent
systemctl is-enabled awsagent

systemctl restart awsagent
systemctl status awsagent

/opt/aws/awsagent/bin/awsagent status












#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Monitoring Service Agent)
#-----------------------------------------------------------------------------------------------------------------------

# Log Separator
Write-LogSeparator "Custom Package Download (Monitoring Service Agent)"

# Package Download Monitoring Service Agent (Zabbix Agent)
# http://www.zabbix.com/download



# Package Download Monitoring Service Agent (Datadog Agent)
# http://docs.datadoghq.com/ja/guides/basic_agent_usage/amazonlinux/
# http://docs.datadoghq.com/ja/guides/basic_agent_usage/centos/
# http://docs.datadoghq.com/ja/guides/basic_agent_usage/redhat/
# http://docs.datadoghq.com/ja/guides/basic_agent_usage/ubuntu/


# Package Download Monitoring Service Agent (New Relic Infrastructure Agent)
# https://docs.newrelic.com/docs/infrastructure/new-relic-infrastructure/installation/install-infrastructure-linux



#-----------------------------------------------------------------------------------------------------------------------
# Custom Package Download (Security Service Agent)
#-----------------------------------------------------------------------------------------------------------------------


# Package Download Security Service Agent (Deep Security Agent)
# http://esupport.trendmicro.com/ja-jp/enterprise/dsaas/top.aspx
# https://help.deepsecurity.trendmicro.com/Get-Started/Install/install-dsa.html
# 


# Package Download Security Service Agent (Alert Logic Universal Agent)
# https://docs.alertlogic.com/requirements/system-requirements.htm#reqsAgent
# https://scc.alertlogic.net/software/al-agent-LATEST-1.x86_64.rpm






