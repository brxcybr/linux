
### Linux Baseline Script
The purpose of this tool is to quickly gather and analyze Linux endpoint data to assess its security posture and check for evidence of malicious activity or compromise.

## Inside the bundle
This Linux baseline capability consists of three separate tools:
- _**baseline.sh**_ - Standalone baseline script, written in BASH
- _**get-baseline.sh**_ - Deployment script (uses SSH)
- _**parse-baseline.sh**_ - Parsing/Comparison script that lets you compare output files

## Linux Baseline Script (baseline.sh):
- Collects baseline data for Linux Hosts (supports ALL major flavors of Linux)
- Checks for common indicators of compromise
- Produces an output file which can be parsed with parse-baseline.sh script
- Some of the commands run in this script will only resolve in certain flavors of Linux
- Recommend commenting out any lines that are irrelevant, cause issues or do not resolve.
- _Note_: Should be executed with root privileges in order to gather all of the required data 


# Updates in v2.0.2:
- No longer required to edit interface name
- Redirects both STDOUT and STDERR to file
- Outputs location of results file when complete
- Removed redundant commands
- Removed deprecated commands (i.e. arp)
- Collects uptime, system environment variables

# Usage:
```
$ chmod +x baseline.sh
$ sudo ./baseline.sh
```
 
# Output:
`./<ip address>_YYYYMMSSDD_HHMMSSZ.txt` 

 
## Deployment Script (_get-baseline.sh_)
- Deploys the baseline.sh script to remote host
- Executes script on remote host
- Returns script to a local directory
- Removes artifacts from remote host
- Works best when shared SSH keys are utilized
- _Note_ : For this to work, ensure that you have the correct IP in the field below, and ensure that baseline.sh is in your current working directory. If the device is not integrated into LDAP, you will have to change the $ip variable to <username>@ip for it to work.

# Usage:
`$ chmod +x get-baseline.sh`

# Modify this file and set the IP(s) you want to pull from
```
$ vim get-baseline.sh
$ ./get-baseline.sh
```
 
## Parsing/Analysis Script (_parse-baseline.sh_)
- Splits files created by 'baseline.sh' script by command
- If a second filename is supplied, compares two files
- Reduces analytical time by allowing you to quickly identify changes over time

# Usage:
```
$ chmod +x parse-baseline.sh
$ parse-baseline.sh file1
$ parse-baseline.sh file1 file2
```

# Output:
```
./<ip address>/<date>/
./<ip address>/parse_baseline_YYYYMMDD_HHMMSSZ.txt
./<ip address>/parse_summary_YYYYMMDD_HHMMSSZ.txt
```
