#!/bin/bash

KNOWN_EXCEPTIONS=(
    "bitcoin/short_channel_id.c:.*sscanf"
    "channeld/full_channel.c:.*sprintf"
    "common/bolt11.c:.*strtoull"
    "common/dev_disconnect.c:.*atoi"
    "common/json.c:.*strtod"
    "common/json.c:.*strtoul"
    "common/json.c:.*strtoull"
    "common/json.c:.*vsnprintf"
    "common/json.c:.*vsprintf"
    "common/json_escaped.c:.*sprintf"
    "common/subdaemon.c:.*atoi"
    "common/wireaddr.c:.*strtol"
    "devtools/bolt11-cli.c:.*ctime"
    "devtools/print_wire.c:.*isprint"
    "gossipd/test/run-bench-find_route.c:.*atoi"
    "lightningd/bitcoind.c:.*sprintf"
    "lightningd/bitcoind.c:.*strtol"
    "lightningd/log.c:.*ctime"
    "lightningd/log.c:.*snprintf"
    "lightningd/log.c:.*sprintf"
    "lightningd/log.c:.*strcasecmp"
    "lightningd/log.c:.*strftime"
    "lightningd/memdump.c:.*sprintf"
    "lightningd/opt_time.c:.*isspace"
    "lightningd/opt_time.c:.*sprintf"
    "lightningd/opt_time.c:.*strtol"
    "lightningd/options.c:.*snprintf"
    "lightningd/options.c:.*strtol"
    "lightningd/options.c:.*strtoul"
    "lightningd/options.c:.*strtoull"
    "onchaind/test/run-grind_feerate.c:.*atoi"
    "tools/check-bolt.c:.*atoi"
    "tools/check-bolt.c:.*strtol"
    "wallet/db.c:.*atol"
    "wallet/db.c:.*strftime"
)

REGEXP_IGNORE_EXTERNAL_DEPENDENCIES="^ccan/"

LOCALE_DEPENDENT_FUNCTIONS=(
    alphasort
    asctime
    asprintf
    atof
    atoi
    atol
    atoll
    atoq
    btowc
    ctime
    fgetwc
    fgetws
    fputwc
    fputws
    fscanf
    fwprintf
    getdate
    getwc
    getwchar
    isalnum
    isalpha
    isblank
    iscntrl
    isdigit
    isgraph
    islower
    isprint
    ispunct
    isspace
    isupper
    iswalnum
    iswalpha
    iswblank
    iswcntrl
    iswctype
    iswdigit
    iswgraph
    iswlower
    iswprint
    iswpunct
    iswspace
    iswupper
    iswxdigit
    isxdigit
    mblen
    mbrlen
    mbrtowc
    mbsinit
    mbsnrtowcs
    mbsrtowcs
    mbstowcs
    mbtowc
    mktime
    putwc
    putwchar
    scanf
    snprintf
    sprintf
    sscanf
    stoi
    stol
    stoll
    strcasecmp
    strcasestr
    strcoll
    strfmon
    strftime
    strncasecmp
    strptime
    strtod
    strtof
    strtoimax
    strtol
    strtold
    strtold
    strtoll
    strtoq
    strtoul
    strtoull
    strtoumax
    strtouq
    strxfrm
    swprintf
    tolower
    toupper
    towctrans
    towlower
    towupper
    ungetwc
    vasprintf
    versionsort
    vfscanf
    vfwprintf
    vscanf
    vsnprintf
    vsprintf
    vsscanf
    vswprintf
    vwprintf
    wcrtomb
    wcscasecmp
    wcscoll
    wcsftime
    wcsncasecmp
    wcsnrtombs
    wcsrtombs
    wcstod
    wcstof
    wcstoimax
    wcstol
    wcstold
    wcstoll
    wcstombs
    wcstoul
    wcstoull
    wcstoumax
    wcswidth
    wcsxfrm
    wctob
    wctomb
    wctrans
    wctype
    wcwidth
)

function join_array {
    local IFS="$1"
    shift
    echo "$*"
}

REGEXP_LOCALE_DEPENDENT_FUNCTIONS=$(join_array "|" "${LOCALE_DEPENDENT_FUNCTIONS[@]}")
REGEXP_IGNORE_KNOWN_EXCEPTIONS=$(join_array "|" "${KNOWN_EXCEPTIONS[@]}")

# Invoke "git grep" only once in order to minimize run-time
GIT_GREP_OUTPUT=$(git grep -E "[^a-zA-Z0-9_\`'\"<>](${REGEXP_LOCALE_DEPENDENT_FUNCTIONS})[^a-zA-Z0-9_\`'\"<>]" -- "*.c" "*.h")

EXIT_CODE=0
for LOCALE_DEPENDENT_FUNCTION in "${LOCALE_DEPENDENT_FUNCTIONS[@]}"; do
    MATCHES=$(grep -E "[^a-zA-Z0-9_\`'\"<>]${LOCALE_DEPENDENT_FUNCTION}(|_r)[^a-zA-Z0-9_\`'\"<>]" <<< "${GIT_GREP_OUTPUT}" | \
        grep -vE "\.(c|h):\s*(//|\*\s|/\*).*${LOCALE_DEPENDENT_FUNCTION}")
    if [[ ${REGEXP_IGNORE_EXTERNAL_DEPENDENCIES} != "" ]]; then
        MATCHES=$(grep -vE "${REGEXP_IGNORE_EXTERNAL_DEPENDENCIES}" <<< "${MATCHES}")
    fi
    if [[ ${REGEXP_IGNORE_KNOWN_EXCEPTIONS} != "" ]]; then
        MATCHES=$(grep -vE "${REGEXP_IGNORE_KNOWN_EXCEPTIONS}" <<< "${MATCHES}")
    fi
    if [[ ${MATCHES} != "" ]]; then
        echo "The locale dependent function ${LOCALE_DEPENDENT_FUNCTION}(...) appears to be used:"
        echo "${MATCHES}"
        echo
        EXIT_CODE=1
    fi
done
if [[ ${EXIT_CODE} != 0 ]]; then
    echo "Unnecessary locale dependence can cause bugs that are very"
    echo "tricky to isolate and fix. Please avoid using locale dependent"
    echo "functions if possible."
    echo
    echo "Advice not applicable in this specific case? Add an exception"
    echo "by updating the ignore list in $0"
fi
exit ${EXIT_CODE}
