#! /bin/sh

from=${1}
to=${2}
common=`printf '%s\0%s' "${from}" "${to}" | sed 's/\(.*\).*\x0\1.*/\1/' | sed 's@/[^/]*$@/@'`
prefix=`printf '%s\n' ${from#$common} | sed 's@[^/][^/]*@..@g'`
printf '%s\n' "$prefix/${to#$common}"
