#!/bin/bash

# Linux Baseline v2.0.2
# Author: brx
# Created: 24 October 2019
# Updated: 12 January 2021
#
# This tool:
# - Collects baseline data for Linux Hosts
# - Checks for common indicators of compromise
# - Produces an output file which can be parsed with parse-baseline.sh script
# 
# Note: Some of the commands run in this script
# will only resolve in certain flavors of Linux.
# Recommend commenting out any lines that are 
# irrelevant, cause issues or do not resolve.
# It is recommened that you use the get-baseline.sh
#
# Updates:
# - No longer required to edit interface name
# - Redirects both STDOUT and STDERR to file
# - Outputs location of results file when complete
# - Removed redundant commands 
# - Removed deprecated commands (i.e. arp)
# - Collects uptime, system environment variables
# - *FUTURE* Multiplatform support 
#
# Usage:
# $ chmod +x baseline.sh
# $ sudo ./baseline.sh
# 
# Output:
# ./<ip address>_YYYYMMSSDD_HHMMSSZ.txt
# 

# Help menu
if [ "$1" = "-h" ] || [ "$1" = "--help" ] ; then	
  echo "usage: baseline.sh [-h]"
  echo ""
  echo 'Collects baseline data for Linux Hosts and checks for common indicators of compromise. Requires manual analysis of output file, which is placed in the current directory as <ip_address>_YYYYMMSSDD_HHMMSSZ.txt. Must be executed as root user.'
  echo ""
  echo "optional arguments:"
  echo "  -h, --help  show this help message and exit" 
  exit 0
fi

if [ "$EUID" -ne 0 ]
  then echo "WARNING: Must execute as root"; echo ""
  exit 1
fi

# Create the file name
# Retrieve device IP address(es) to use as filename
ips=($(ip a | grep "inet\b" | awk '{print $2}' | cut -d/ -f1 | grep -v 127.0.0.1))

# If there is only one IP, set that as default
# If more than one IP, ask user which they would like to use
len_ips=${#ips[@]}
if [ "$len_ips" = 1 ]; then
	ip=$ips
elif [ "$len_ips" > 1 ]; then
	echo "Select which IP you would like to use (required for filename):"
	for (( i=0; i<${len_ips}; i++ )); do echo "$i) ${ips[$i]}"; done
	read index
    if [[ "${!ips[@]}" =~ "${index}" ]]; then
      ip=${ips[$index]}
    else
        echo -e "Invalid selection.\nExiting..."
        exit 1;
	fi
else
	echo -e "No valid IP address(es) found.\Exiting..."
	exit 1
fi

timestamp=`(date -u +%Y%m%d_%TZ)`
file=$ip"_"$timestamp".txt"

echo "Gathering data... "
echo "**********LINUX BASELINE**********" >> $file
echo >> $file

# Basic information about the host and Operating system.
echo "************HOST INFO**************" >> $file
echo "\$ hostnamectl" >> $file && hostnamectl >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ uname -a" >> $file && uname -a >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/*release*" >> $file && cat /etc/*release* >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ domainname" >> $file && domainname >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ timedatectl" >> $file && timedatectl >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ntpstat" >> $file && ntpstat >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ who -a" >> $file && who -a >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ uptime" >> $file && uptime >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ free -h" >> $file && free -h >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lsblk -a" >> $file && lsblk -a >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /proc/partitions" >> $file && cat /proc/partitions >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ iostat" >> $file && iostat >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ findmnt --all" >> $file && findmnt --all >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/fstab" >> $file && cat /etc/fstab >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Retrieve hardware info from DMI Table
echo "\$ dmidecode" >> $file && dmidecode >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Do not use DMI Table to pull harware information (DMI table can be inaccurate)
echo "\$ lshw -disable dmi" >> $file && lshw -disable dmi >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lsscsi -v" >> $file && lsscsi -v >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lspci -v" >> $file && lspci -v >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lsusb -v" >> $file && lsusb -v >> $file 2>&1
echo >> $file

# Checks for environmental contextual and user information
echo "************USER INFO**************" >> $file
users=$(cat /etc/passwd | grep 'sh$' | cut -d':' -f1)
echo "\$ whoami" >> $file && whoami >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ id" >> $file && id >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /root/.bash_history" >> $file && cat /root/.bash_history >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Bash history for all users who have the ability to login
# Commented out by default
# echo "\$ for u in $users; do cat /home/$u/.bash_history; done" >> $file && for u in $users; do cat /home/$u/.bash_history; done >> $file 2>&1
# echo >> $file && echo "===================================" >> $file
echo "\$ printenv" >> $file && printenv >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ set" >> $file && set >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/passwd" >> $file && cat /etc/passwd >> $file 2>&1
echo >> $file && echo "===================================" &>> $file
echo "\$ cat /etc/group" >> $file && cat /etc/group >> $file 2>&1
echo >> $file && echo "===================================" &>> $file
# Admins
echo "\$ getent group sudo root wheel adm admin" >> $file && getent group sudo root wheel adm admin >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Password status for each user
echo "\$ cut -d':' -f1 < /etc/passwd | xargs -I {} passwd -S {}" >> $file && cut -d':' -f1 < /etc/passwd | xargs -I {} passwd -S {} >> $file 2>&1
echo >> $file

# Check for suspicious logins or SSH keys
echo "************LOGON INFO**************" >> $file
echo "\$ w" >> $file && w >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ tty" >> $file && tty >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lastlog | sort" >> $file && lastlog | sort >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ last -f /var/log/wtmp" >> $file && last -f /var/log/wtmp >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ last -f /var/log/btmp" >> $file && last -f /var/log/btmp >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ last -f /var/run/utmp" >> $file && last -f /var/run/utmp >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /root/.ssh/known_hosts" >> $file && cat /root/.ssh/known_hosts >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Pull ssh known hosts for all accounts that can login
echo '$ for u in $users; do echo "# cat /home/$u/.ssh/known_hosts" && cat /home/$u/.ssh/known_hosts && echo; done' >> $file && for u in $users; do echo "# cat /home/$u/.ssh/known_hosts" && cat /home/$u/.ssh/known_hosts && echo; done >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /root/.ssh/authorized_keys" >> $file && cat /root/.ssh/authorized_keys >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Pull authorized ssh keys for all accounts that can login
echo '$ for u in $users; do echo "# cat /home/$u/.ssh/authorized_keys" && cat /home/$u/.ssh/authorized_keys && echo; done' >> $file && for u in $users; do echo "# cat /home/$u/.ssh/authorized_keys" && cat /home/$u/.ssh/authorized_keys && echo; done >> $file 2>&1

# echo >> $file && echo "===================================" >> $file
# Below line lists systemwide known_hosts on certain RHEL instances
# echo "\$ cat /var/lib/sss/pubconf/known_hosts" >> $file && cat /var/lib/sss/pubconf/known_hosts >> $file 2>&1
echo >> $file

# Checks for Common methods of persistence
echo "************PERSISTENCE INFO**************" >> $file
echo "\$ cat /etc/passwd | grep 'sh$'" >> $file && cat /etc/passwd | grep 'sh$' >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /root/.bash_profile" >> $file && cat /root/.bash_profile >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /root/.bash_login" >> $file && cat /root/.bash_login >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /root/.profile" >> $file && cat /root/.profile >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /root/.bashrc" >> $file && cat /root/.bashrc >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /root/.bash_logout" >> $file && cat /root/.bash_logout >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# The following lines compare user directories to defaults found in /etc/skel
files=$(ls -A /etc/skel)
# Root user
echo '$ for f in $files; do echo "# /root/$f" && diff -y --suppress-common-lines /etc/skel/$f ~/$f && echo || echo; done' >> $file && for f in $files; do echo "# /root/$f" && diff -y --suppress-common-lines /etc/skel/$f ~/$f && echo || echo; done >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# All users 
echo '$ for u in $users; do for f in $files; do echo "# /home/$u/$f" && diff -y --suppress-common-lines /etc/skel/$f /home/$u/$f && echo || echo; done; done' >> $file && for u in $users; do for f in $files; do echo "# /home/$u/$f" && diff -y --suppress-common-lines /etc/skel/$f /home/$u/$f && echo || echo; done; done >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/rc.local" >> $file && cat /etc/rc.local >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ atq" >> $file && atq >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/crontab" >> $file && cat /etc/crontab >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ls -latR /etc/cron.*" >> $file && ls -latR /etc/cron* >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ls -latR /var/spool/cron" >> $file && ls -latR /var/spool/cron >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ls -latR /etc/init.d" >> $file && ls -latR /etc/init.d >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ls -latR /etc/init/*" >> $file && ls -latR /etc/init/* >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ls -latR /etc/rc.d" >> $file && ls -latR /etc/rc.d >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ls -latR /etc/systemd/system" >> $file && ls -latR /etc/systemd/system >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Below line shows any user binaries created with within the past 180 days (edit range as needed)
echo "\$ find /bin /sbin /usr/{bin,sbin} /usr/local/{bin,sbin} -maxdepth 1 -mtime 180 | xargs -r ls -l" >> $file && find /bin /sbin /usr/{bin,sbin} /usr/local/{bin,sbin} -maxdepth 1 -mtime 180 | xargs -r ls -l >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Find orphaned files 
echo "\$ find / -nouser | xargs -r ls -l" >> $file && find / -nouser | xargs -r ls -l >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# World writable directories and files
echo "\$ find / -perm -0002 -type d -print | xargs -r ls -ld" >> $file && find / -perm -0002 -type d -print | xargs -r ls -ld >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Below line edited to remove excessive results from /proc and /sys, remove if desired
echo "\$ find / -perm -0002 -type f -print | grep -v '/proc/' | grep -v '/sys/' | xargs -r ls -l" >> $file && find / -perm -0002 -type f -print | grep -v '/proc/' | grep -v '/sys/' | xargs -r ls -l >> $file 2>&1
#echo "\$ find / -perm -0002 -type f -print | xargs r ls -l" >> $file && find / -perm -0002 -type f -print | xargs -r ls -l >> $file
echo >> $file

# Network and Firewall Situational Awareness
# Results will vary based on distribution
echo "************NETWORK INFO**************" >> $file
echo "\$ nmcli" >> $file && nmcli >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ip a" >> $file && ip a >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/resolv.conf" >> $file && cat /etc/resolv.conf >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ip neigh" >> $file && ip neigh >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ route -n" >> $file && route -n >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ netstat -autpel --numeric-hosts --numeric-ports | sort" >> $file && netstat -autpel --numeric-hosts --numeric-ports | sort >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lsof -Pni" >> $file && lsof -Pni >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ss -punt" >> $file && ss -punt >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/hosts" >> $file && cat /etc/hosts >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ rpcinfo -p" >> $file && rpcinfo -p >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ smbclient -L 127.0.0.1 -U%" >> $file && smbclient -L 127.0.0.1 -U% >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ showmount -e 127.0.0.1" >> $file && showmount -e 127.0.0.1 >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ iptables -L -n -v" >> $file && iptables -L -n -v >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ iptables -S" >> $file && iptables -S >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ firewall-cmd --list-all-zones" >> $file && firewall-cmd --list-all-zones >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ufw status verbose" >> $file && ufw status verbose >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ufw app list" >> $file && ufw app list >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ufw show raw" >> $file && ufw show raw >> $file 2>&1
echo >> $file

# Note: The output of the following few commands is significant. 
echo "*******PROCESS SERVICE SOFTWARE INFO*********" >> $file
echo "\$ ps -elf --sort pid" >> $file && ps -elf --sort pid >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ pstree" >> $file && pstree >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ systemctl list-units -all --full" >> $file && systemctl list-units -all --full >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# echo "\$ systemctl status *.service" >> $file && systemctl status *.service >> $file 2>&1
# echo >> $file && echo "===================================" >> $file
echo "\$ rpm -q --all | sort" >> $file && rpm -q --all | sort >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ dpkg -l | sort" >> $file && dpkg -l | sort >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lsmod | sort" >> $file && lsmod | sort >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Verbose for all Loaded Kernel Modules (Drivers)
# Makes a list of all of the modules and then pipes them to modinfo
mods=`lsmod | sort | cut -d " " -f1`
mods=`echo $mods | cut -d " " -f 2-`
echo '$ for m in $mods; do echo -e "# modinfo $m" && modinfo $m && echo ""; done' >> $file && for m in $mods; do echo -e "# modinfo $m" && modinfo $m && echo ""; done >> $file 2>&1
#echo "\$ ls -latR ~" >> $file && ls -latR ~ >> $file 2>&1
#echo >> $file && echo "===================================" >> $file
#echo "\$ ls -latR /tmp" >> $file && ls -latR /tmp >> $file 2>&1
#echo >> $file && echo "===================================" >> $file
echo >> $file

# This section pulls security policies and system monitoring information
echo "***********SECURITY POLICY CHECKS************" >> $file
# Auditd configuration
echo >> $file && echo "===================================" >> $file
echo "\$ auditctl -s" >> $file && auditctl -s >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ auditctl -l" >> $file && auditctl -l >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Logging configuration
echo "\$ cat /etc/rsyslog.conf" >> $file && cat /etc/rsyslog.conf >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/systemd/journald.conf" >> $file && cat /etc/systemd/journald.conf >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Security Context 
echo "\$ sestatus" >> $file && sestatus >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ getsebool -a" >> $file && getsebool -a >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ps -eo pid,user,comm,label --sort pid | grep -v unconfined" >> $file && ps -eo pid,user,comm,label --sort pid | grep -v unconfined >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ netstat -auntpelZ | grep -v unconfined | sort" >> $file && netstat -auntpelZ | grep -v unconfined | sort >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ aa-status" >> $file && aa-status >> $file 2>&1
echo >> $file && echo "===================================" >> $file
# Password policies
echo "\$ cat /etc/pam.d/password-auth" >> $file && cat /etc/pam.d/password-auth >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/pam.d/common-password" >> $file && cat /etc/pam.d/common-password >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/login.defs" >> $file && cat /etc/login.defs >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/default/useradd" >> $file && cat /etc/default/useradd >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/adduser.conf" >> $file && cat /etc/adduser.conf >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/bash.bashrc" >> $file && cat /etc/bash.bashrc >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/hosts.allow" >> $file && cat /etc/hosts.allow >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/hosts.deny" >> $file && cat /etc/hosts.deny >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/cron.allow" >> $file && cat /etc/cron.allow >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/cron.deny" >> $file && cat /etc/cron.deny >> $file 2>&1
echo >> $file

echo -e "Done!\n\nResults located at $(realpath $file)\n"