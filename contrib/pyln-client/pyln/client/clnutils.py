import re


def cln_parse_rpcversion(string):
    """
    Parse cln version string to determine RPC version.

    cln switched from 'semver' alike    `major.minor.sub[rcX][-mod]`
    to ubuntu style with version 22.11  `yy.mm[.patch][-mod]`
    make sure we can read all of them for (the next 80 years).
    """
    rpcversion = string
    if rpcversion.startswith('v'):  # strip leading 'v'
        rpcversion = rpcversion[1:]
    if rpcversion.find('-') != -1:  # strip mods
        rpcversion = rpcversion[:rpcversion.find('-')]
    if re.search('.*(rc[\\d]*)$', rpcversion):  # strip release candidates
        rpcversion = rpcversion[:rpcversion.find('rc')]
    if rpcversion.count('.') == 1:  # imply patch version 0 if not given
        rpcversion = rpcversion + '.0'

    # split and convert numeric string parts to actual integers
    return list(map(int, rpcversion.split('.')))
