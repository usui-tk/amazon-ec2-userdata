# Amazon WorkSpaces, Amazon AppStream 2.0 Information

## Overview

- Amazon WorkSpaces documentation
- (https://aws.amazon.com/documentation/workspaces/)

- Amazon Appstream 2.0 documentation
- (https://aws.amazon.com/documentation/appstream/)

## Technical Information (Amazon WorkSpaces)

- [Amazon WorkSpaces Bundle base on EC2 Instance]
- (https://aws.amazon.com/jp/workspaces/details/#Amazon_WorkSpaces_Bundles)


| Bundle Type | EC2 Instance Type |
|:-----------|------------:|
| Value Bundle | t2.small |
| Standard Bundle | t2.medium |
| Performance Bundle | m3.large -> t2.large |
| Power Bundle | t2.xlarge |
| Graphics Bundle | g2.2xlarge |

Amazon WorkSpaces is enabled at T2 Unlimited

- [Amazon WorkSpaces Management Interface IP Ranges (AWS Managed VPC)]
- (http://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-port-requirements.html#network-interfaces)


| Region | Code | AWS Managed VPC CIDR |
|:-----------|------------:|:------------:|
| US East (N. Virginia) | us-east-1 | 172.31.0.0/16, 192.168.0.0/16, and 198.19.0.0/16 |
| US West (Oregon) | us-west-2 | 172.31.0.0/16 and 192.168.0.0/16 |
| EU (Ireland) | eu-west-1 | 172.31.0.0/16 and 192.168.0.0/16 |
| EU (Frankfurt) | eu-central-1 | 198.19.0.0/16 |
| EU (London) | eu-west-2 | 198.19.0.0/16 |
| Asia Pacific (Sydney) | ap-southeast-2 | 172.31.0.0/16 and 192.168.0.0/16 |
| Asia Pacific (Tokyo) | ap-northeast-1 | 198.19.0.0/16 |
| Asia Pacific (Singapore) | ap-southeast-1 | 198.19.0.0/16 |


## Technical Information (Amazon AppStream 2.0)

- [Amazon AppStream 2.0 Instance Families base on EC2 Instance]
- (http://docs.aws.amazon.com/appstream2/latest/developerguide/instance-types.html)

| Instance Family | Instance Code-Types | EC2 instance-type Family |
|:-----------|------------:|:------------:|
| General Purpose | stream.standard | T2 Instance |
| Memory Optimized | stream.memory | R3 Instance |
| Compute Optimized | stream.compute | C4 Instance |
| Graphics Design | stream.graphics-design | E3 Instance |
| Graphics Desktop | stream.graphics-desktop | G2 Instance |
| Graphics Pro | stream.graphics-pro | G3 Instance |

- [Amazon  AppStream 2.0 Management Interface IP Ranges (AWS Managed VPC)]

| Region | Code | AWS Managed VPC CIDR |
|:-----------|------------:|:------------:|
| US East (N. Virginia) | us-east-1 | 198.19.0.0/16 |
| US West (Oregon) | us-west-2 |  |
| EU (Ireland) | eu-west-1 |  |
| Asia Pacific (Tokyo) | ap-northeast-1 | 198.19.0.0/16 |

- [Amazon AppStream 2.0 IAM Profile Information]

| Bundle Type | IAM Profile Name | Meta-Data URL |
|:-----------|------------:|:------------:|
| Image Builder | PhotonImageBuilderInstance | http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonImageBuilderInstance |
