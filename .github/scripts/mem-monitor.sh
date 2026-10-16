#!/bin/bash
# Log memory to the job log every 15s during a test run, so readings made
# before a VM kill survive. Run in the background and kill it when done.
while sleep 15; do
  printf '\n[mem %s] %s\n' "$(date +%T)" "$(free -m | awk '/Mem:/{print "used="$3"MB avail="$7"MB"}')"
  ps -eo rss=,comm= | awk '{s[$2]+=$1; c[$2]++} END{for(k in s) printf "%d %d %s\n", s[k]/1024, c[k], k}' | sort -rn | head -n 5 | awk '{printf "[mem]   %6d MB  x%-4d %s\n", $1, $2, $3}'
done
