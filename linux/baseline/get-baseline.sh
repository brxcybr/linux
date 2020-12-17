#!/bin/bash

# Author: brx
# Created: 25 October 2019
# Updated: 7 July 2020
#
# This tool:
# - Deploys the baseline.sh script to remote host
# - Executes script on remote host
# - Returns script to a local directory 
# - Removes artifacts from remote host 
#
# Note : For this to work, ensure that you have 
# the correct IP in the field below, and ensure
# that baseline.sh is in your current working 
# directory. If the device is not integrated 
# into LDAP, you will have to change the $ip 
# variable to <username>@ip for it to work. 
# Works best when shared ssh keys are utilized.
#
# Usage:
# $ chmod +x get-baseline.sh
# $ ./get-baseline.sh
# 

# Help menu
if [ "$1" = "-h" ] || [ "$1" = "--help" ] ; then	
  echo "usage: get-baseline.sh [-h]"
  echo ""
  echo 'Collects baseline data for remote Linux Hosts via the baseline.sh script. The script "baseline.sh" must be in the current working directory in order for this script to deploy it correctly. May require modification depending on the deployment environment.'
  echo ""
  echo "optional arguments:"
  echo "  -h, --help  show this help message and exit" 
  exit 0
fi

# Creates results folder if it does not exist
if [ ! -d "./results" ] ; then
  mkdir ./results
fi

# Script body 

# Uncomment or comment this line to run the script as another user 
username=$USER

# Note: Place IP of target(s) after 'for ip in <ip1> <ip2> <ip3>'
for ip in 10.225.2.80; do scp ./baseline.sh $username@$ip:/tmp && ssh -t $username@$ip "sudo chmod +x /tmp/baseline.sh && sudo /tmp/baseline.sh" && ssh -t $username@$ip "sudo chown $username ./$ip* || sudo chown $username ./_*Z.txt" && scp $username@$ip:./$ip* ./results || scp $username@$ip:./_*Z.txt ./results && ssh -t $username@$ip "sudo rm /tmp/baseline.sh $ip* || sudo rm ./_*Z.txt"; done

