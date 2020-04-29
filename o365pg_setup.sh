#!/bin/bash

adduser phishhunter
# setting the default password here.  Please change it later
#echo "phishhunter:okmijnokm1" | chpasswd
mkdir /home/phishhunter/phish_script
mkdir /home/phishhunter/logs
#chmod 600 /home/phishhunter/phish_script
# echo 'umask 377' >> /home/phishhunter/.bashrc
# change creds here
echo 'export CLIENT_ID=xxxxx' >> /home/phishhunter/.bashrc
echo 'export CLIENT_SECRET=xxxxx' >> /home/phishhunter/.bashrc
echo 'export TENANT=xxxxx' >> /home/phishhunter/.bashrc
echo 'export USER_NAME=xxxxx' >> /home/phishhunter/.bashrc
echo `date --utc +%FT%TZ` > /home/phishhunter/phish_script/timestamp.txt
chown -R phishhunter:phishhunter /home/phishhunter