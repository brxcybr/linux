#!/bin/bash

# Linux Baseline v2.0.2
# Author: brx
# Created: 24 October 2019
# Updated: 05 February 2026
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
# For remote collection, use: ./baseline.sh --remote ...
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

# Notes on non-interactive use:
# - By default this script will automatically select an IP address for the output filename.
# - Use --ip-mode prompt to restore the original "pick an IP" behavior.
# - Use --outdir /tmp when deploying remotely to avoid leaving artifacts in $HOME.
#
# Output format contract (for downstream parsers):
# - Each command begins with a line that starts with "$ " (literal dollar + space).
# - The command output follows until the next "$ " line.
# - Section headers are delimited with asterisks.

# Defaults (can be overridden via args)
MODE="local"          # local | remote
IP_MODE="auto"        # auto | prompt | first | ip:<addr> | iface:<ifname>
OUTDIR="."
FIND_TIMEOUT_SECS="120"

# Find hardening:
# - We constrain filesystem scope (-xdev) to avoid huge mounts (NFS, overlay, etc.)
# - We prune known high-noise / high-cost trees (containers, pseudo-filesystems)
# - We optionally use `timeout` if available to avoid long hangs
FIND_PRUNE_ARGS=(
  \( -path /proc -o -path /proc/* \
     -o -path /sys -o -path /sys/* \
     -o -path /run -o -path /run/* \
     -o -path /var/lib/docker -o -path /var/lib/docker/* \
     -o -path /var/lib/containers -o -path /var/lib/containers/* \
     -o -path /snap -o -path /snap/* \
  \) -prune -o
)

usage() {
  echo "usage:"
  echo "  baseline.sh [-h] [--ip-mode auto|prompt|first|ip:<addr>|iface:<ifname>] [--outdir <dir>]"
  echo "  baseline.sh -r|--remote [--hosts-file FILE] [--user USER] [--identity KEYFILE] [--results-dir DIR] [--ip-mode MODE] [--ask-ssh-pass] [--ask-sudo-pass] [--ssh-pass PASS] [--sudo-pass PASS] [host1 host2 ...]"
  echo ""
  echo "Collects baseline data for Linux hosts and checks for common indicators of compromise."
  echo "Local mode must be executed as root (directly or via sudo)."
  echo "Remote mode orchestrates baselines over SSH and retrieves results."
  echo ""
  echo "options:"
  echo "  -h, --help      show this help message and exit"
  echo "  -r, --remote    run in remote mode (collect baselines from other hosts)"
  echo "  --ip-mode       filename IP selection mode (default: auto)"
  echo "  --outdir        output directory for the results file (default: .)"
  echo ""
  echo "remote options:"
  echo "  --hosts-file    file containing one host per line (IP/hostname/FQDN)"
  echo "  --user          remote username (default: current user)"
  echo "  --identity      SSH private key path (passed to ssh/scp -i)"
  echo "  --results-dir   local folder to store results (default: ./results)"
  echo "  --ask-ssh-pass  prompt for SSH password (uses sshpass if available)"
  echo "  --ask-sudo-pass prompt for sudo password (best-effort via sudo -S)"
  echo "  --ssh-pass      SSH password (NOT recommended: may be visible in process list)"
  echo "  --sudo-pass     sudo password (NOT recommended: may be visible in process list)"
}

# Remote defaults (only used when MODE=remote)
REMOTE_USER="$USER"
REMOTE_IDENTITY=""
REMOTE_HOSTS_FILE=""
REMOTE_RESULTS_DIR="./results"
REMOTE_SSH_PASS=""
REMOTE_SUDO_PASS=""
ASK_SSH_PASS="0"
ASK_SUDO_PASS="0"
REMOTE_HOSTS=()

# Parse args (minimal, non-getopts). Unknown args are ignored for backwards compatibility.
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -r|--remote)
      MODE="remote"
      shift 1
      ;;
    --ip-mode)
      IP_MODE="$2"
      shift 2
      ;;
    --outdir)
      OUTDIR="$2"
      shift 2
      ;;
    --hosts-file)
      REMOTE_HOSTS_FILE="$2"
      shift 2
      ;;
    --user)
      REMOTE_USER="$2"
      shift 2
      ;;
    --identity|-i)
      REMOTE_IDENTITY="$2"
      shift 2
      ;;
    --results-dir)
      REMOTE_RESULTS_DIR="$2"
      # Also set OUTDIR for local mode (allow --results-dir to work in both modes)
      OUTDIR="$2"
      shift 2
      ;;
    --ask-ssh-pass)
      ASK_SSH_PASS="1"
      shift 1
      ;;
    --ask-sudo-pass)
      ASK_SUDO_PASS="1"
      shift 1
      ;;
    --ssh-pass)
      REMOTE_SSH_PASS="$2"
      shift 2
      ;;
    --sudo-pass)
      REMOTE_SUDO_PASS="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      # ignore unknown options
      shift 1
      ;;
    *)
      # positional host
      REMOTE_HOSTS+=("$1")
      shift 1
      ;;
  esac
done

if [ $# -gt 0 ]; then
  # leftover positional hosts after --
  for h in "$@"; do REMOTE_HOSTS+=("$h"); done
fi

if [ "$MODE" = "remote" ]; then
  if [ "$ASK_SSH_PASS" = "1" ] && [ -z "$REMOTE_SSH_PASS" ]; then
    read -s -p "SSH password (leave blank to use keys/agent): " REMOTE_SSH_PASS
    echo ""
  fi
  if [ "$ASK_SUDO_PASS" = "1" ] && [ -z "$REMOTE_SUDO_PASS" ]; then
    read -s -p "sudo password (required for remote execution): " REMOTE_SUDO_PASS
    echo ""
    if [ -z "$REMOTE_SUDO_PASS" ]; then
      echo "Warning: No sudo password provided. Remote execution may fail if sudo requires a password." >&2
    fi
  fi
else
  # local mode: require root, but optionally support sudo -S if a sudo password was provided
  if [ "$EUID" -ne 0 ]; then
    if [ -n "$REMOTE_SUDO_PASS" ] && [ -z "$BASELINE_AS_ROOT" ]; then
      export BASELINE_AS_ROOT="1"
      # Re-run as root, preserving local args only
      echo "$REMOTE_SUDO_PASS" | sudo -S -p '' "$0" --ip-mode "$IP_MODE" --outdir "$OUTDIR"
      exit $?
    fi
    echo "WARNING: Must execute as root (run with sudo)."
    echo ""
    exit 1
  fi
fi

remote_run() {
  # Build up host list from file if provided
  if [ -n "$REMOTE_HOSTS_FILE" ]; then
    if [ ! -f "$REMOTE_HOSTS_FILE" ]; then
      echo "Hosts file not found: $REMOTE_HOSTS_FILE"
      exit 1
    fi
    while IFS= read -r line; do
      line="${line%%#*}"
      line="$(echo "$line" | xargs)"
      if [ -n "$line" ]; then
        REMOTE_HOSTS+=("$line")
      fi
    done < "$REMOTE_HOSTS_FILE"
  fi

  if [ ${#REMOTE_HOSTS[@]} -eq 0 ]; then
    echo "No hosts provided. Use --hosts-file or pass hosts as arguments."
    exit 1
  fi

  if [ ! -d "$REMOTE_RESULTS_DIR" ]; then
    mkdir -p "$REMOTE_RESULTS_DIR" 2>/dev/null || true
  fi

  local ssh_opts=()
  local scp_opts=()

  # Reuse SSH connections to reduce repeated auth prompts
  local control_path="/tmp/baseline-%r@%h:%p"
  ssh_opts+=(-o ControlMaster=auto -o ControlPersist=5m -o ControlPath="$control_path")
  scp_opts+=(-o ControlMaster=auto -o ControlPersist=5m -o ControlPath="$control_path")

  if [ -n "$REMOTE_IDENTITY" ]; then
    ssh_opts+=(-i "$REMOTE_IDENTITY")
    scp_opts+=(-i "$REMOTE_IDENTITY")
  fi

  # If an SSH password is supplied, we can use sshpass (best-effort).
  local use_sshpass="0"
  if [ -n "$REMOTE_SSH_PASS" ]; then
    if command -v sshpass >/dev/null 2>&1; then
      use_sshpass="1"
      export SSHPASS="$REMOTE_SSH_PASS"
      ssh_opts=(sshpass -e ssh "${ssh_opts[@]}")
      scp_opts=(sshpass -e scp "${scp_opts[@]}")
    else
      echo "SSH password provided, but sshpass is not installed. Install sshpass or use key-based auth."
      exit 1
    fi
  else
    ssh_opts=(ssh "${ssh_opts[@]}")
    scp_opts=(scp "${scp_opts[@]}")
  fi

  # We deploy THIS script to the remote host and execute it in local mode there.
  local self_path="$0"
  if [ ! -f "$self_path" ]; then
    echo "Could not locate script path: $self_path"
    exit 1
  fi

  for host in "${REMOTE_HOSTS[@]}"; do
    echo "=== Collecting baseline from $host ==="

    local remote="${REMOTE_USER}@${host}"
    local remote_script="/tmp/baseline.sh.$$"

    # Copy script
    "${scp_opts[@]}" "$self_path" "${remote}:${remote_script}" || { echo "scp failed for $host"; continue; }

    # Execute baseline and write output to /tmp on remote
    local ssh_out=""
    if [ -n "$REMOTE_SUDO_PASS" ]; then
      # Feed password to sudo -S. Pass it as argument to avoid read hanging.
      # Use -n to prevent SSH from reading stdin, which can cause hangs
      ssh_out=$(printf '%s\n' "$REMOTE_SUDO_PASS" | "${ssh_opts[@]}" -n -tt "$remote" "echo \"\$0\" | sudo -S -p \"\" bash -c \"chmod +x '\''${remote_script}'\''; '\''${remote_script}'\'' --ip-mode '\''${IP_MODE}'\'' --outdir /tmp\"" "$REMOTE_SUDO_PASS" 2>&1)
    else
      # Without password, try interactive sudo (may fail if no TTY or requiretty is set)
      # Warn user they should use --ask-sudo-pass
      echo "Warning: No sudo password provided. Attempting interactive sudo (may fail)." >&2
      echo "Tip: Use --ask-sudo-pass to provide password non-interactively." >&2
      ssh_out=$("${ssh_opts[@]}" -n -tt "$remote" "sudo chmod +x '${remote_script}' && sudo '${remote_script}' --ip-mode '${IP_MODE}' --outdir /tmp" 2>&1)
    fi
    echo "$ssh_out"

    # Extract results path from output
    local result_path
    result_path=$(echo "$ssh_out" | sed -n 's/^Results located at //p' | tail -n 1)
    if [ -z "$result_path" ]; then
      echo "Could not determine result file path for $host"
      "${ssh_opts[@]}" -n -T "$remote" "sudo rm -f '${remote_script}'" >/dev/null 2>&1 || true
      # Close SSH connection before continuing
      "${ssh_opts[@]}" -O exit "$remote" >/dev/null 2>&1 || true
      continue
    fi

    # Chown results file to remote user so scp can retrieve it
    # The file was created as root, but we need it owned by REMOTE_USER for scp
    # Use -n to prevent SSH from reading stdin, and -T to disable TTY (not needed for chown)
    if [ -n "$REMOTE_SUDO_PASS" ]; then
      printf '%s\n' "$REMOTE_SUDO_PASS" | "${ssh_opts[@]}" -n -T "$remote" "echo \"\$0\" | sudo -S -p \"\" chown \"${REMOTE_USER}:${REMOTE_USER}\" \"${result_path}\"" "$REMOTE_SUDO_PASS" >/dev/null 2>&1 || true
    else
      "${ssh_opts[@]}" -n -T "$remote" "sudo chown \"${REMOTE_USER}:${REMOTE_USER}\" \"${result_path}\"" >/dev/null 2>&1 || true
    fi

    # Copy results back
    local result_name
    result_name=$(basename "$result_path")
    "${scp_opts[@]}" "${remote}:${result_path}" "${REMOTE_RESULTS_DIR}/${result_name}" || echo "scp of results failed for $host"

    # Cleanup: remove script and results file (both may be root-owned, so use sudo)
    # Use -n to prevent SSH from reading stdin, and -T to disable TTY (not needed for rm)
    if [ -n "$REMOTE_SUDO_PASS" ]; then
      printf '%s\n' "$REMOTE_SUDO_PASS" | "${ssh_opts[@]}" -n -T "$remote" "echo \"\$0\" | sudo -S -p \"\" rm -f '${remote_script}' '${result_path}'" "$REMOTE_SUDO_PASS" >/dev/null 2>&1 || true
    else
      "${ssh_opts[@]}" -n -T "$remote" "sudo rm -f '${remote_script}' '${result_path}'" >/dev/null 2>&1 || true
    fi
    
    # Explicitly close SSH ControlMaster connection for this host to prevent hangs
    "${ssh_opts[@]}" -O exit "$remote" >/dev/null 2>&1 || true
  done
}

if [ "$MODE" = "remote" ]; then
  remote_run
  exit 0
fi

# Create the file name
# Retrieve device IP address(es) to use as filename
ips=($(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1))
len_ips=${#ips[@]}

select_ip_auto() {
  # Prefer the interface with the default route (common "primary" interface)
  local def_if
  def_if=$(ip route show default 0.0.0.0/0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
  if [ -n "$def_if" ]; then
    ip -o -4 addr show dev "$def_if" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1
    return
  fi
  # Fallback: first global IPv4
  if [ "$len_ips" -ge 1 ]; then
    echo "${ips[0]}"
    return
  fi
  echo ""
}

select_ip_prompt() {
  if [ "$len_ips" -lt 1 ]; then
    echo ""
    return
  fi
  if [ "$len_ips" = 1 ]; then
    echo "${ips[0]}"
    return
  fi
  echo "Select which IP you would like to use (required for filename):"
  for (( i=0; i<${len_ips}; i++ )); do echo "$i) ${ips[$i]}"; done
  read index
  if [[ "${!ips[@]}" =~ "${index}" ]]; then
    echo "${ips[$index]}"
  else
    echo ""
  fi
}

case "$IP_MODE" in
  prompt)
    ip=$(select_ip_prompt)
    ;;
  first)
    ip="${ips[0]}"
    ;;
  ip:*)
    ip="${IP_MODE#ip:}"
    ;;
  iface:*)
    ifname="${IP_MODE#iface:}"
    ip=$(ip -o -4 addr show dev "$ifname" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1)
    ;;
  *)
    ip=$(select_ip_auto)
    ;;
esac

if [ -z "$ip" ]; then
  echo -e "No valid IP address(es) found.\nExiting..."
  exit 1
fi

if [ ! -d "$OUTDIR" ] ; then
  mkdir -p "$OUTDIR" 2>/dev/null || true
fi

timestamp=`(date -u +%Y%m%d_%TZ)`
file="$OUTDIR/${ip}_${timestamp}.txt"

echo "Gathering data... "
echo "**********LINUX BASELINE**********" >> $file
echo >> $file
echo "# Selected filename IP: $ip" >> $file
echo "# IP selection mode: $IP_MODE" >> $file
echo >> $file

#
# Recommended execution order:
# - identity/platform first (fast + foundational)
# - access posture next (sshd/sudo)
# - network exposure next (interfaces/sockets/firewall)
# - persistence + filesystem hardening next (potentially expensive)
# - logs last (bounded, but still potentially noisy)
#

echo "************EXECUTION CONTEXT**************" >> $file
echo "\$ whoami" >> $file && whoami >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ id" >> $file && id >> $file 2>&1
echo >> $file

echo "************HOST INFO**************" >> $file
echo "\$ hostnamectl" >> $file && hostnamectl >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/*release*" >> $file && cat /etc/*release* >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ uname -a" >> $file && uname -a >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /proc/cmdline" >> $file && cat /proc/cmdline >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ domainname" >> $file && domainname >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ timedatectl" >> $file && timedatectl >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ntpstat" >> $file && ntpstat >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/ntp.conf" >> $file && cat /etc/ntp.conf >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/chrony.conf" >> $file && cat /etc/chrony.conf >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/chrony/chrony.conf" >> $file && cat /etc/chrony/chrony.conf >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/systemd/timesyncd.conf" >> $file && cat /etc/systemd/timesyncd.conf >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ who -a" >> $file && who -a >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ uptime" >> $file && uptime >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ free -h" >> $file && free -h >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lsblk -a" >> $file && lsblk -a >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ df -B1" >> $file && df -B1 >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /proc/partitions" >> $file && cat /proc/partitions >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ iostat" >> $file && iostat >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ findmnt --all" >> $file && findmnt --all >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/fstab" >> $file && cat /etc/fstab >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ dmidecode" >> $file && dmidecode >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lshw -disable dmi" >> $file && lshw -disable dmi >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lsscsi -v" >> $file && lsscsi -v >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lspci -v" >> $file && lspci -v >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lsusb -v" >> $file && lsusb -v >> $file 2>&1
echo >> $file

echo "************HARDENING INFO**************" >> $file
echo "\$ sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6" >> $file && sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ mokutil --sb-state" >> $file && mokutil --sb-state >> $file 2>&1
echo >> $file

echo "************ACCOUNTS & ENV**************" >> $file
users=$(cat /etc/passwd | grep 'sh$' | cut -d':' -f1)
echo "\$ cat /etc/passwd" >> $file && cat /etc/passwd >> $file 2>&1
echo >> $file && echo "===================================" &>> $file
echo "\$ cat /etc/group" >> $file && cat /etc/group >> $file 2>&1
echo >> $file && echo "===================================" &>> $file
echo "\$ getent group sudo root wheel adm admin" >> $file && getent group sudo root wheel adm admin >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cut -d':' -f1 < /etc/passwd | xargs -I {} passwd -S {}" >> $file && cut -d':' -f1 < /etc/passwd | xargs -I {} passwd -S {} >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /root/.bash_history" >> $file && cat /root/.bash_history >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ printenv" >> $file && printenv >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ set" >> $file && set >> $file 2>&1
echo >> $file

echo "************SSH & SUDO POSTURE**************" >> $file
echo "\$ sshd -T" >> $file && sshd -T >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/ssh/sshd_config" >> $file && cat /etc/ssh/sshd_config >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ls -la /etc/ssh/sshd_config.d" >> $file && ls -la /etc/ssh/sshd_config.d >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/ssh/sshd_config.d/*" >> $file && cat /etc/ssh/sshd_config.d/* >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub" >> $file && ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /root/.ssh/known_hosts" >> $file && cat /root/.ssh/known_hosts >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo '$ for u in $users; do echo "# cat /home/$u/.ssh/known_hosts" && cat /home/$u/.ssh/known_hosts && echo; done' >> $file && for u in $users; do echo "# cat /home/$u/.ssh/known_hosts" && cat /home/$u/.ssh/known_hosts && echo; done >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /root/.ssh/authorized_keys" >> $file && cat /root/.ssh/authorized_keys >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo '$ for u in $users; do echo "# cat /home/$u/.ssh/authorized_keys" && cat /home/$u/.ssh/authorized_keys && echo; done' >> $file && for u in $users; do echo "# cat /home/$u/.ssh/authorized_keys" && cat /home/$u/.ssh/authorized_keys && echo; done >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/sudoers" >> $file && cat /etc/sudoers >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ls -la /etc/sudoers.d" >> $file && ls -la /etc/sudoers.d >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/sudoers.d/*" >> $file && cat /etc/sudoers.d/* >> $file 2>&1
echo >> $file

echo "************SECURITY POLICY CHECKS**************" >> $file
echo "\$ auditctl -s" >> $file && auditctl -s >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ auditctl -l" >> $file && auditctl -l >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/rsyslog.conf" >> $file && cat /etc/rsyslog.conf >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/systemd/journald.conf" >> $file && cat /etc/systemd/journald.conf >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ sestatus" >> $file && sestatus >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ getsebool -a" >> $file && getsebool -a >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ aa-status" >> $file && aa-status >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ ps -eo pid,user,comm,label --sort pid | grep -v unconfined" >> $file && ps -eo pid,user,comm,label --sort pid | grep -v unconfined >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ netstat -auntpelZ | grep -v unconfined | sort" >> $file && netstat -auntpelZ | grep -v unconfined | sort >> $file 2>&1
echo >> $file && echo "===================================" >> $file
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

echo "************NETWORK & FIREWALL**************" >> $file
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
echo "\$ ss -punt" >> $file && ss -punt >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ netstat -autpel --numeric-hosts --numeric-ports | sort" >> $file && netstat -autpel --numeric-hosts --numeric-ports | sort >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lsof -Pni" >> $file && lsof -Pni >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/hosts" >> $file && cat /etc/hosts >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ rpcinfo -p" >> $file && rpcinfo -p >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ smbclient -L 127.0.0.1 -U%" >> $file && smbclient -L 127.0.0.1 -U% >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ showmount -e 127.0.0.1" >> $file && showmount -e 127.0.0.1 >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ nft list ruleset" >> $file && { command -v nft >/dev/null 2>&1 && { command -v timeout >/dev/null 2>&1 && timeout 20s nft list ruleset || nft list ruleset; } || echo "nft not installed"; } >> $file 2>&1
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

echo "************SERVICES & SCHEDULED**************" >> $file
echo "\$ systemctl list-units -all --full" >> $file && systemctl list-units -all --full >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ systemctl list-timers --all" >> $file && systemctl list-timers --all >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ systemctl list-unit-files --state=enabled" >> $file && systemctl list-unit-files --state=enabled >> $file 2>&1
echo >> $file

echo "************PROCESS / SOFTWARE / KERNEL**************" >> $file
echo "\$ ps -elf --sort pid" >> $file && ps -elf --sort pid >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ pstree" >> $file && pstree >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ rpm -q --all | sort" >> $file && rpm -q --all | sort >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ dpkg -l | sort" >> $file && dpkg -l | sort >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ lsmod | sort" >> $file && lsmod | sort >> $file 2>&1
echo >> $file && echo "===================================" >> $file
mods=`lsmod | sort | cut -d " " -f1`
mods=`echo $mods | cut -d " " -f 2-`
echo '$ for m in $mods; do echo -e "# modinfo $m" && modinfo $m && echo ""; done' >> $file && for m in $mods; do echo -e "# modinfo $m" && modinfo $m && echo ""; done >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ docker ps -a" >> $file && { command -v docker >/dev/null 2>&1 && { command -v timeout >/dev/null 2>&1 && timeout 20s docker ps -a || docker ps -a; } || echo "docker not installed"; } >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ docker info" >> $file && { command -v docker >/dev/null 2>&1 && { command -v timeout >/dev/null 2>&1 && timeout 20s docker info || docker info; } || echo "docker not installed"; } >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ podman ps -a" >> $file && { command -v podman >/dev/null 2>&1 && { command -v timeout >/dev/null 2>&1 && timeout 20s podman ps -a || podman ps -a; } || echo "podman not installed"; } >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ podman info" >> $file && { command -v podman >/dev/null 2>&1 && { command -v timeout >/dev/null 2>&1 && timeout 20s podman info || podman info; } || echo "podman not installed"; } >> $file 2>&1
echo >> $file

echo "************PERSISTENCE & FILESYSTEM**************" >> $file
echo "\$ cat /etc/passwd | grep 'sh$'" >> $file && cat /etc/passwd | grep 'sh$' >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ cat /etc/ld.so.preload" >> $file && cat /etc/ld.so.preload >> $file 2>&1
echo >> $file && echo "===================================" >> $file
files=$(ls -A /etc/skel)
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
echo '$ for f in $files; do echo "# /root/$f" && diff -y --suppress-common-lines /etc/skel/$f ~/$f && echo || echo; done' >> $file && for f in $files; do echo "# /root/$f" && diff -y --suppress-common-lines /etc/skel/$f ~/$f && echo || echo; done >> $file 2>&1
echo >> $file && echo "===================================" >> $file
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
echo "\$ find /bin /sbin /usr/{bin,sbin} /usr/local/{bin,sbin} -maxdepth 1 -mtime 180 -exec ls -l {} +" >> $file && find /bin /sbin /usr/{bin,sbin} /usr/local/{bin,sbin} -maxdepth 1 -mtime 180 -exec ls -l {} + >> $file 2>&1
echo >> $file && echo "===================================" >> $file
if command -v timeout >/dev/null 2>&1; then
  echo "\$ timeout ${FIND_TIMEOUT_SECS}s find / -xdev (pruned) \\( -nouser -o -nogroup \\) -type f -exec ls -l {} +" >> $file
  timeout "${FIND_TIMEOUT_SECS}s" find / -xdev "${FIND_PRUNE_ARGS[@]}" \( -nouser -o -nogroup \) -type f -exec ls -l {} + >> $file 2>/dev/null
else
  echo "\$ find / -xdev (pruned) \\( -nouser -o -nogroup \\) -type f -exec ls -l {} +" >> $file
  find / -xdev "${FIND_PRUNE_ARGS[@]}" \( -nouser -o -nogroup \) -type f -exec ls -l {} + >> $file 2>/dev/null
fi
echo >> $file && echo "===================================" >> $file
if command -v timeout >/dev/null 2>&1; then
  echo "\$ timeout ${FIND_TIMEOUT_SECS}s find / -xdev (pruned) -type d -perm -0002 -exec ls -ld {} +" >> $file
  timeout "${FIND_TIMEOUT_SECS}s" find / -xdev "${FIND_PRUNE_ARGS[@]}" -type d -perm -0002 -exec ls -ld {} + >> $file 2>/dev/null
else
  echo "\$ find / -xdev (pruned) -type d -perm -0002 -exec ls -ld {} +" >> $file
  find / -xdev "${FIND_PRUNE_ARGS[@]}" -type d -perm -0002 -exec ls -ld {} + >> $file 2>/dev/null
fi
echo >> $file && echo "===================================" >> $file
if command -v timeout >/dev/null 2>&1; then
  echo "\$ timeout ${FIND_TIMEOUT_SECS}s find / -xdev (pruned) -type f -perm -0002 -exec ls -l {} +" >> $file
  timeout "${FIND_TIMEOUT_SECS}s" find / -xdev "${FIND_PRUNE_ARGS[@]}" -type f -perm -0002 -exec ls -l {} + >> $file 2>/dev/null
else
  echo "\$ find / -xdev (pruned) -type f -perm -0002 -exec ls -l {} +" >> $file
  find / -xdev "${FIND_PRUNE_ARGS[@]}" -type f -perm -0002 -exec ls -l {} + >> $file 2>/dev/null
fi
echo >> $file && echo "===================================" >> $file
if command -v timeout >/dev/null 2>&1; then
  echo "\$ timeout ${FIND_TIMEOUT_SECS}s find / -xdev (pruned) -type f -perm -4000 -exec ls -l {} +" >> $file
  timeout "${FIND_TIMEOUT_SECS}s" find / -xdev "${FIND_PRUNE_ARGS[@]}" -type f -perm -4000 -exec ls -l {} + >> $file 2>/dev/null
  echo >> $file && echo "===================================" >> $file
  echo "\$ timeout ${FIND_TIMEOUT_SECS}s find / -xdev (pruned) -type f -perm -2000 -exec ls -l {} +" >> $file
  timeout "${FIND_TIMEOUT_SECS}s" find / -xdev "${FIND_PRUNE_ARGS[@]}" -type f -perm -2000 -exec ls -l {} + >> $file 2>/dev/null
else
  echo "\$ find / -xdev (pruned) -type f -perm -4000 -exec ls -l {} +" >> $file
  find / -xdev "${FIND_PRUNE_ARGS[@]}" -type f -perm -4000 -exec ls -l {} + >> $file 2>/dev/null
  echo >> $file && echo "===================================" >> $file
  echo "\$ find / -xdev (pruned) -type f -perm -2000 -exec ls -l {} +" >> $file
  find / -xdev "${FIND_PRUNE_ARGS[@]}" -type f -perm -2000 -exec ls -l {} + >> $file 2>/dev/null
fi
echo >> $file && echo "===================================" >> $file
# getcap -r / can hang on network mounts, containers, /proc, /sys, etc.
# Instead, scan important system paths individually to avoid hangs
if command -v getcap >/dev/null 2>&1; then
  echo "\$ getcap -r /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt 2>/dev/null" >> $file
  if command -v timeout >/dev/null 2>&1; then
    timeout "${FIND_TIMEOUT_SECS}s" getcap -r /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt 2>/dev/null >> $file 2>&1 || true
  else
    getcap -r /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt 2>/dev/null >> $file 2>&1 || true
  fi
  # Also check /etc and /root for any capability-enabled files
  echo "\$ getcap -r /etc /root 2>/dev/null" >> $file
  if command -v timeout >/dev/null 2>&1; then
    timeout 30s getcap -r /etc /root 2>/dev/null >> $file 2>&1 || true
  else
    getcap -r /etc /root 2>/dev/null >> $file 2>&1 || true
  fi
else
  echo "\$ getcap -r /" >> $file
  echo "getcap not installed" >> $file
fi
echo >> $file

echo "************LOGON HISTORY & AUTH LOGS**************" >> $file
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
echo "\$ journalctl -u ssh -u sshd --since \"7 days ago\" --no-pager" >> $file && { command -v journalctl >/dev/null 2>&1 && { command -v timeout >/dev/null 2>&1 && timeout 20s journalctl -u ssh -u sshd --since "7 days ago" --no-pager || journalctl -u ssh -u sshd --since "7 days ago" --no-pager; } || echo "journalctl not installed"; } >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ tail -n 200 /var/log/auth.log" >> $file && tail -n 200 /var/log/auth.log >> $file 2>&1
echo >> $file && echo "===================================" >> $file
echo "\$ tail -n 200 /var/log/secure" >> $file && tail -n 200 /var/log/secure >> $file 2>&1
echo >> $file

# If executed via sudo, try to return ownership to the invoking user so deployment can scp cleanly.
# Try multiple methods to get the original user
ORIG_USER=""
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
  ORIG_USER="$SUDO_USER"
elif [ -n "$SUDO_UID" ]; then
  # Fallback: get username from UID
  ORIG_USER=$(getent passwd "$SUDO_UID" 2>/dev/null | cut -d: -f1)
fi
# If still no user, try logname (works if TTY is available)
if [ -z "$ORIG_USER" ] || [ "$ORIG_USER" = "root" ]; then
  ORIG_USER=$(logname 2>/dev/null || true)
fi
# For SSH sessions, try to get user from SSH_CLIENT or who command
if [ -z "$ORIG_USER" ] || [ "$ORIG_USER" = "root" ]; then
  # Try to get the user who owns the SSH session
  ORIG_USER=$(who am i 2>/dev/null | awk '{print $1}' || true)
fi
# Last resort: try to get the first non-root user from who
if [ -z "$ORIG_USER" ] || [ "$ORIG_USER" = "root" ]; then
  ORIG_USER=$(who 2>/dev/null | awk 'NR==1 {print $1}' | grep -v root || true)
fi

if [ -n "$ORIG_USER" ] && [ "$ORIG_USER" != "root" ] && [ "$(id -u)" = "0" ]; then
  chown "$ORIG_USER":"$ORIG_USER" "$file" 2>/dev/null || true
fi

echo -e "Done!\n\nResults located at $(realpath $file)\n"