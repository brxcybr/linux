#!/bin/bash

# Author: brx
# Created: 8 December 2020
# Updated: 12 January 2021
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

# --- helpers (portable) ---

msg() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

parse_meta_from_path() {
  # outputs: ip dtg hms
  local path="$1"
  local base="${path##*/}"

  local ip dtg hms_part hms
  ip="${base%%_*}"
  dtg="${base#*_}"; dtg="${dtg%%_*}"
  hms_part="${base#*_*_}"
  hms="${hms_part%%.*}"

  [ -n "$ip" ]  || die "Could not parse ip from filename: $base"
  [ -n "$dtg" ] || die "Could not parse dtg from filename: $base"
  [ -n "$hms" ] || die "Could not parse hms from filename: $base"

  printf '%s %s %s\n' "$ip" "$dtg" "$hms"
}

abs_path() {
  local p="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$p"
  else
    local d b
    d="$(cd "$(dirname "$p")" && pwd -P)" || return 1
    b="$(basename "$p")"
    printf '%s/%s\n' "$d" "$b"
  fi
}

md5_file() {
  # portable: GNU coreutils (md5sum) or macOS (md5)
  local f="$1"
  if command -v md5sum >/dev/null 2>&1; then
    md5sum "$f" | awk '{print $1}'
  else
    md5 -q "$f"
  fi
}

timestamp_utc() {
  date -u +%Y%m%d_%H%M%SZ
}

# Split by "$ " command header lines; preserve section headers for context
split_by_command_headers() {
  local infile="$1"
  local outdir="$2"

  [ -f "$infile" ] || die "Input file not found: $infile"
  mkdir -p "$outdir" || die "Failed to create output dir: $outdir"
  rm -f "$outdir"/*.txt 2>/dev/null || true

  awk -v outdir="$outdir" '
    function newfile() {
      i++
      fn = sprintf("%s/%02d.txt", outdir, i)
      if (section != "") {
        print section >> fn
      }
    }

    BEGIN {
      i = -1
      fn = ""
      section = ""
    }

    # Capture section headers like ************HOST INFO**************
    /^\*{5,}/ {
      section = $0
      next
    }

    # New command starts at a line beginning with "$ "
    /^\$ / {
      newfile()
      print $0 >> fn
      next
    }

    # Write all other lines only after we have started first command chunk
    {
      if (i >= 0) {
        print $0 >> fn
      }
    }
  ' "$infile"
}

cmd_from_chunk() {
  # First "$ ..." line in the chunk
  sed -n 's/^\$ //p' "$1" | head -n 1
}

# --- File 1 required ---
[ -n "${1:-}" ] || die "No filename(s) provided."
file1="$1"
read -r ip1 dtg1 hms1 < <(parse_meta_from_path "$file1")
outdir1="./${ip1}/${dtg1}/${hms1}"
msg "$# filename(s) provided."
msg "Parsing first file..."
split_by_command_headers "$file1" "$outdir1"

# --- File 2 optional ---
if [ -n "${2:-}" ]; then
  file2="$2"
  read -r ip2 dtg2 hms2 < <(parse_meta_from_path "$file2")
  outdir2="./${ip2}/${dtg2}/${hms2}"
  msg "Parsing second file..."
  split_by_command_headers "$file2" "$outdir2"

  if [ "$ip1" != "$ip2" ]; then
    printf "Comparing two different IPs (%s vs %s). Proceed? [y/N] " "$ip1" "$ip2"
    read -r reply
    case "$reply" in
      [Yy]*) msg "OK — results will go in ./${ip2}/" ;;
      *) die "Aborted by user." ;;
    esac
  fi

  ts="$(timestamp_utc)"
  outfile="./${ip2}/parse_baseline_${ts}.txt"
  summary="./${ip2}/parse_summary_${ts}.txt"
  mkdir -p "./${ip2}" || true

  f1_size="$(ls -lah "$file1" | awk '{print $5}')"
  f2_size="$(ls -lah "$file2" | awk '{print $5}')"

  {
    echo "BASELINE CHANGE SUMMARY"
    echo "======================="
    echo "Date created: $ts"
    echo
    printf "First file:  %s\n" "$(abs_path "$file1")"
    printf "Second file: %s\n" "$(abs_path "$file2")"
    echo
    printf "File: 1\t\t\t\t\tFile: 2\n"
    printf "Host: %s\t\t\tHost: %s\n" "$ip1" "$ip2"
    printf "Date: %s\t\t\t\tDate: %s\n" "$dtg1" "$dtg2"
    printf "Time: %s\t\t\t\tTime: %s\n" "$hms1" "$hms2"
    printf "Size: %s\t\t\t\tSize: %s\n" "$f1_size" "$f2_size"
    printf "MD5 : %s\tMD5 : %s\n" "$(md5_file "$file1")" "$(md5_file "$file2")"
    echo
    echo "Commands with changed output:"
  } > "$summary"

  : > "$outfile"

  # Compare chunk-by-chunk (by filename index 00.txt, 01.txt, ...)
  for a in "$outdir1"/*.txt; do
    [ -e "$a" ] || break
    b="$outdir2/$(basename "$a")"

    if [ ! -f "$b" ]; then
      cmd="$(cmd_from_chunk "$a")"
      printf "  - %s (missing in file2)\n" "${cmd:-UNKNOWN}" >> "$summary"
      {
        echo
        echo "==================================="
        echo "MISSING IN FILE2: ${cmd:-UNKNOWN}"
        echo "Chunk: $(basename "$a")"
        echo "-----------------------------------"
        cat "$a"
      } >> "$outfile"
      continue
    fi

    # Unified diff is portable and readable
    if diffout="$(diff -u "$a" "$b" 2>/dev/null || true)" && [ -n "$diffout" ]; then
      cmd="$(cmd_from_chunk "$a")"
      printf "  - %s\n" "${cmd:-UNKNOWN}" >> "$summary"
      {
        echo
        echo "==================================="
        echo "COMMAND: ${cmd:-UNKNOWN}"
        echo "CHUNK: $(basename "$a")"
        echo "-----------------------------------"
        echo "$diffout"
      } >> "$outfile"
    fi
  done

  msg "Wrote:"
  msg "  $summary"
  msg "  $outfile"
fi

msg "Done!"