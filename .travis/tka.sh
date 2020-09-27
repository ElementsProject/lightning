#!/bin/bash

# Execute a command with a timeout while printing regularly
#
# This is a refactored script reusing timeout from pxelbeat.org
# http://www.pixelbeat.org/scripts/timeout
# License: LGPLv2
#
# It also tries to print the same output as the travis_wait
# which can be found in https://github.com/travis-ci/travis-build
# path lib/travis/build/bash/travis_build.bash
# The difference is one more \n in the beginning of each
# "Still running..." line on output.

echo "$1" | grep -q '[0-9]\+' || {
  echo "The first parameter has to be the maximum time in seconds." >&2
  exit 1
}

cleanup()
{
  trap - ALRM                 #reset handler to default
  kill -ALRM "$b" 2>/dev/null #stop printing subshell
  kill -ALRM "$a" 2>/dev/null #stop timer subshell if running
  kill $! 2>/dev/null &&      #kill last job
    exit 124                  #exit with 124 if it was running
}

watchit()
{
  trap "cleanup" ALRM
  sleep "$1"& wait
  kill -ALRM $$
}

travis_wait() {
  time="$((${1}/60))"
  shift
  count=0
  while true
  do
    count="$((count + 1))"
    printf "Still running (%s of %s): ${*}\\r" "${count}" "${time}"
    sleep 60
  done
}

travis_wait "$@"& b=$!     #start the terminal writing process
watchit "$1"& a=$!         #start the timeout
shift                      #first param was timeout for sleep
trap "cleanup" ALRM INT    #cleanup after timeout
"$@"& wait $!; RET=$?      #start the job wait for it and save its return value
kill -ALRM $a 2>/dev/null  #send ALRM signal to watchit
wait $a                    #wait for watchit to finish cleanup
exit $RET                  #return the value
