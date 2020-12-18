#!/bin/bash

# Author: brx
# Created: 8 December 2020
# Updated: 9 December 2020
#
# This tool:
# - Splits files created by 'baseline.sh' script by command
# - If a second filename is supplied, compares two files
# - Reduces analytical time
#
# Usage:
# $ chmod +x parse-baseline.sh
# $ parse-baseline.sh file1
# $ parse-baseline.sh file1 file2
# 
# Output:
# ./<ip address>/<date>/
# ./<ip address>/parse_baseline_YYYYMMDD_HHMMSSZ.txt
# ./<ip address>/parse_summary_YYYYMMDD_HHMMSSZ.txt 

# Help menu
if [ "$1" = "-h" ] || [ "$1" = "--help" ] ; then	
  echo "usage: parse-baseline.sh [-h] file1 [file2]"
  echo ""
  echo 'Splits files created by "baseline.sh" script to reduce amount of time it takes to manually analyze files. This program accepts up to two filenames as parameters, separated by a space. If one filename is provided, splits the file and puts it in a folder with the name of the target IP address. If two filenames are provided, splits a second file and compares the results.'
  echo ""
  echo "optional arguments:"
  echo "  -h, --help  show this help message and exit" 
  exit 0
fi

# File 1
# Verify that filename was provided as a parameter and sets metadata (ip, date, time) to variable
if [ ! -z "$1" ] ; then
  echo -e "$# filename(s) provided.\nParsing first file..."
  file1="$1"
  ip1=$(echo ${file1##*/} | cut -d "_" -f1)
  dtg1=$(echo ${file1##*/} | cut -d "_" -f2)
  hms1=$(echo ${file1##*/} | cut -d "_" -f3 | cut -d "." -f1)

  # Create output folder if it does not already exist
  outdir1="./"$ip1"/"$dtg1"/"$hms1
  if [ ! -d $outdir1 ] ; then
    mkdir -p $outdir1
  fi
  
  # Split files 
  csplit --silent --prefix=$outdir1"/" --suffix-format="%02d.txt" $file1 '/^$ /' '{*}'
  
  # Give error if no filename is provided
else
  echo "No filename(s) provided."
  exit 1
fi
 
# File 2
# Verify that filename was provided as a parameter and sets metadata (ip, date, time) to variable
if [ ! -z "$2" ] ; then
  echo "Parsing second file..."
  file2="$2"
  ip2=$(echo ${file2##*/} | cut -d "_" -f1)
  dtg2=$(echo ${file2##*/} | cut -d "_" -f2)
  hms2=$(echo ${file2##*/} | cut -d "_" -f3 | cut -d "." -f1)

  # Creates folder if it does not already exist
  outdir2="./"$ip2"/"$dtg2"/"$hms2
  if [ ! -d $outdir2 ] ; then
    mkdir -p $outdir2
  fi

  # Split files
  csplit --silent --prefix=$outdir2"/" --suffix-format="%02d.txt" $file2 '/^$ /' '{*}'
  
  # Print notice if IP addresses are different and ask user if they would like to proceed
  if [ $ip1 != $ip2 ]; then
    read -p "You are requesting to compare results for two different IP addresses. Would you like to proceed? " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]] ; then
      exit 1
    else 
      echo "Results will go in ./$ip2/ folder."
    fi
  fi

  # Compare files and output differences to output filename
  timestamp=`(date -u +%Y%m%d_%TZ)`
  
  outfile="./"$ip2"/parse_baseline_"$timestamp".txt"
  summary="./"$ip2"/parse_summary_"$timestamp".txt"
  files=`ls -A $outdir1"/"`
  f1_size=$(ls -lah $file1 | awk -F " " {'print $5'})
  f2_size=$(ls -lah $file2 | awk -F " " {'print $5'})
  
  # Setup summary file 
  echo "BASELINE CHANGE SUMMARY" >> $summary
  echo "=======================" >> $summary
  echo "Date created: $timestamp" >> $summary
  echo "" >> $summary
  echo -e "First file:  $(realpath $file1)" >> $summary
  echo -e "Second file: $(realpath $file2)" >> $summary
  echo "" >> $summary
  echo -e "File: 1\t\t\t\t\tFile: 2" >> $summary
  echo -e "Host: $ip1\t\t\tHost: $ip2" >> $summary
  echo -e "Date: $dtg1\t\t\t\tDate: $dtg2" >> $summary
  echo -e "Time: $hms1\t\t\t\tDate: $hms2" >> $summary
  echo -e "Size: $f1_size\t\t\t\tSize: $f2_size" >> $summary
  echo -e "MD5 : $(md5sum $file1 | cut -d " " -f1)\tMD5 : $(md5sum $file2 | cut -d " " -f1)" >> $summary
  echo "" >> $summary
  echo "The output of the following commands have changed:" >> $summary

  # Generate output
  for f in $files
    do
      if [[ $(diff $outdir1"/"$f $outdir2"/"$f) ]] ; then 
	echo "" >> $outfile
	echo "===================================" >> $outfile
	head -1 $outdir1"/"$f >> $outfile
	cmd=$(head -1 $outdir1"/"$f)
	echo -e "$f\t${cmd#??}" >> $summary
        diff -y --suppress-common-lines $outdir1"/"$f $outdir2"/"$f >> $outfile
      fi;
    done
fi

echo "Done!"
exit 0
