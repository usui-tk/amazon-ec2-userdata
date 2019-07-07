# amazon-ec2-userdata
Publish the UserData script used when creating EC2 instance of Amazon EC2.
Mainly, optimize operating system settings and introduce AWS environment utilities.
In order to avoid the data size (16KB) which is one of the big limitation of UserData, it is made the implementation which minimizes 1st step script.

[1st]
Provide bootstrap script for operating system (Windows, Linux).

[2nd]
Identify the type of operating system (distribution and version).

[3rd]
Provide a script that describes the processing content that you want to execute in the actual UserData.

[4th]
Implement cleanup before creating AMI. (In the case of Windows, including generalization by Sysprep)
