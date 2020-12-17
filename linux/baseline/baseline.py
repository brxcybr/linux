#!/usr/bin/python3 

# Author: brx
# Created: 24 October 2019
# Updated: 21 February 2020
#
# This tool:
# - Collects baseline data for Linux Hosts
# - Checks for common indicators of compromise
# - Requires manual analysis
# 
# Note: Some of the commands run in this script
# will only resolve in certain flavors of Linux.
# Recommend commenting out any lines that are 
# irrelevant, cause issues or do not resolve.
#
# Usage:
# $ chmod +x baseline.py
# $ sudo ./baseline.py
# 
# Output:
# ./<hostname>_YYYYMMSSDD_HHMMSSZ.txt
 
import os
import platform
import sys
import socket
import datetime
import time
import subprocess
import argparse

help_content = "Collects baseline data for Linux Hosts "
help_content += "and checks for common indicators of compromise. "
help_content += "Requires manual analysis of output file, which is "
help_content += "placed in the current directory as "
help_content += "<hostname>_YYYYMMSSDD_HHMMSSZ.txt. "
help_content += "Must be executed as root user."

parser = argparse.ArgumentParser(description=help_content)
parser.parse_args()

def execute_commands(): 
    cmd_lists = [["/bin/hostname","/bin/uname -a", "/bin/cat /etc/*release*", "/bin/df -h"],["/usr/bin/whoami", "/usr/bin/id", "/bin/cat ~/.bash_history", "/bin/domainname", "/usr/bin/env", "/bin/echo $PATH", "/bin/cat /etc/passwd", "/bin/cat /etc/group"],["/usr/bin/w", "/usr/bin/lastlog", "/usr/bin/last -f /var/log/wtmp", "/usr/bin/last -f /var/log/btmp", "/usr/bin/last -f /var/run/utmp", "/bin/cat ~/.ssh/known_hosts", "/bin/cat ~/.ssh/authorized_keys"],["/bin/cat ~/.bash_profile", "/bin/cat ~/.bashrc", "/bin/cat /etc/rc.local", "/bin/ls -latR /etc/cron*", "/bin/cat /etc/crontab", "/bin/ls -latr /etc/init.d", "/usr/bin/find / -perm -0002 -type d -print"],["/sbin/ip a", "/usr/sbin/arp -a", "/sbin/route -n", "/bin/netstat -auntp", "/usr/bin/lsof -Pni", "/bin/ss -punt","/bin/cat /etc/hosts"],["/bin/ps -aux", "/bin/systemctl status *.service", "/bin/systemctl list-units --type=service -all", "/bin/cat /etc/services", "/sbin/lsmod", "/usr/bin/find /bin /usr/{bin,sbin} /usr/local/{bin,sbin} -maxdepth 1 -mtime 1"],["/bin/ls -latR /usr/bin/local", "/bin/ls -latR /tmp", "/sbin/iptables -L"]]
    section_headers = ["************HOST INFO**************\n","***********LOGON INFO**************\n","********PERSISTENCE INFO***********\n","*********NETWORK INFO**************\n","*********NETWORK INFO**************\n","***PACKAGE SERVICE SOFTWARE INFO***\n","***********MISC INFO***************\n"]
    f = open(get_file_name(), "w+")
    f.write("**********UBUNTU BASELINE**********\n")
    header_count = 0
    for cmd_list in cmd_lists:
        f.write(section_headers[header_count])
        for cmd in cmd_list:
            f.write("\n$ {0}\n".format(cmd))
            try:
                f.write(subprocess.check_output(cmd, shell=True).decode())    
            except:
                f.write("Output Error\n")
            f.write('\n===================================\n')
        header_count = header_count + 1
    f.close()

def get_file_name():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    date_string = datetime.date.today().strftime("%Y%m%d")
    time_string = time.strftime("%H:%M:%S", time.gmtime())
    filename = hostname + "_" + date_string + "_" + time_string + "Z.txt"
    return filename

def main():
    os_type = platform.system()
    if os_type == "Linux":
        if os.geteuid() == 0:
            execute_commands()
        else:
            print("WARNING: Must execute as root\n")
            sys.exit(1)
    else:
        print("Unsupported operating system")
        sys.exit(1)
    sys.exit(0)

main()
