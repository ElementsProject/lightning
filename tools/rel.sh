#!/usr/bin/env bash

from=${1}
to=${2}
common=$(printf '%s\n%s' "${from}" "${to}" | sed 'N;s/\(.*\).*\n\1.*$/\1/' | sed 's@/[^/]*$@/@')
prefix=$(printf '%s\n' "${from#$common}" | sed 's@[^/][^/]*@..@g')
printf '%s\n' "$prefix/${to#$common}"
