/* -*- c-basic-offset: 4; indent-tabs-mode: nil; -*- */
#include "config.h"
#include <assert.h>
#include <common/status.h>
#include <connectd/netaddress.h>
#include <errno.h>
#include <netinet/in.h>
#include <unistd.h>

/* Based on bitcoin's src/netaddress.cpp, hence different naming and styling!
   version 7f31762cb6261806542cc6d1188ca07db98a6950:

   Copyright (c) 2009-2010 Satoshi Nakamoto
   Copyright (c) 2009-2016 The Bitcoin Core developers
   Distributed under the MIT software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php.
*/

/* The common IPv4-in-IPv6 prefix */
static const unsigned char pchIPv4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

static bool IsRFC6145(const struct wireaddr *addr)
{
    static const unsigned char pchRFC6145[] = {0,0,0,0,0,0,0,0,0xFF,0xFF,0,0};
    return addr->type == ADDR_TYPE_IPV6
        && memcmp(addr->addr, pchRFC6145, sizeof(pchRFC6145)) == 0;
}

static bool IsRFC6052(const struct wireaddr *addr)
{
    static const unsigned char pchRFC6052[] = {0,0x64,0xFF,0x9B,0,0,0,0,0,0,0,0};
    return addr->type == ADDR_TYPE_IPV6
        && memcmp(addr->addr, pchRFC6052, sizeof(pchRFC6052)) == 0;
}

static bool IsRFC3964(const struct wireaddr *addr)
{
    return addr->type == ADDR_TYPE_IPV6
        && addr->addr[0] == 0x20 && addr->addr[1] == 0x02;
}

/* Return offset of IPv4 address, or 0 == not an IPv4 */
static size_t IPv4In6(const struct wireaddr *addr)
{
    if (addr->type != ADDR_TYPE_IPV6)
        return 0;
    if (memcmp(addr->addr, pchIPv4, sizeof(pchIPv4)) == 0)
        return sizeof(pchIPv4);
    if (IsRFC6052(addr))
        return 12;
    if (IsRFC6145(addr))
        return 12;
    if (IsRFC3964(addr))
        return 2;
    return 0;
}

/* Is this an IPv4 address, or an IPv6-wrapped IPv4 */
static bool IsIPv4(const struct wireaddr *addr)
{
    return addr->type == ADDR_TYPE_IPV4 || IPv4In6(addr) != 0;
}

static bool IsIPv6(const struct wireaddr *addr)
{
    return addr->type == ADDR_TYPE_IPV6 && IPv4In6(addr) == 0;
}

static bool RawEq(const struct wireaddr *addr, const void *cmp, size_t len)
{
    size_t off = IPv4In6(addr);

    assert(off + len <= addr->addrlen);
    return memcmp(addr->addr + off, cmp, len) == 0;
}

/* The bitcoin code packs addresses backwards, so we map it here. */
static unsigned int GetByte(const struct wireaddr *addr, int n)
{
    size_t off = IPv4In6(addr);
    assert(off + n < addr->addrlen);
    return addr->addr[addr->addrlen - 1 - off - n];
}

static bool IsRFC1918(const struct wireaddr *addr)
{
    return IsIPv4(addr) && (
        GetByte(addr, 3) == 10 ||
        (GetByte(addr, 3) == 192 && GetByte(addr, 2) == 168) ||
        (GetByte(addr, 3) == 172 && (GetByte(addr, 2) >= 16 && GetByte(addr, 2) <= 31)));
}

static bool IsRFC2544(const struct wireaddr *addr)
{
    return IsIPv4(addr) && GetByte(addr, 3) == 198 && (GetByte(addr, 2) == 18 || GetByte(addr, 2) == 19);
}

static bool IsRFC3927(const struct wireaddr *addr)
{
    return IsIPv4(addr) && (GetByte(addr, 3) == 169 && GetByte(addr, 2) == 254);
}

static bool IsRFC6598(const struct wireaddr *addr)
{
    return IsIPv4(addr) && GetByte(addr, 3) == 100 && GetByte(addr, 2) >= 64 && GetByte(addr, 2) <= 127;
}

static bool IsRFC5737(const struct wireaddr *addr)
{
    return IsIPv4(addr) && ((GetByte(addr, 3) == 192 && GetByte(addr, 2) == 0 && GetByte(addr, 1) == 2) ||
                            (GetByte(addr, 3) == 198 && GetByte(addr, 2) == 51 && GetByte(addr, 1) == 100) ||
                            (GetByte(addr, 3) == 203 && GetByte(addr, 2) == 0 && GetByte(addr, 1) == 113));
}

static bool IsRFC3849(const struct wireaddr *addr)
{
    return IsIPv6(addr) && GetByte(addr, 15) == 0x20 && GetByte(addr, 14) == 0x01 && GetByte(addr, 13) == 0x0D && GetByte(addr, 12) == 0xB8;
}

static bool IsRFC4862(const struct wireaddr *addr)
{
    static const unsigned char pchRFC4862[] = {0xFE,0x80,0,0,0,0,0,0};
    return IsIPv6(addr) && RawEq(addr, pchRFC4862, sizeof(pchRFC4862));
}

static bool IsRFC4193(const struct wireaddr *addr)
{
    return IsIPv6(addr) && ((GetByte(addr, 15) & 0xFE) == 0xFC);
}

static bool IsRFC4843(const struct wireaddr *addr)
{
    return IsIPv6(addr) && (GetByte(addr, 15) == 0x20 && GetByte(addr, 14) == 0x01 && GetByte(addr, 13) == 0x00 && (GetByte(addr, 12) & 0xF0) == 0x10);
}

static bool IsTor(const struct wireaddr *addr)
{
    return addr->type == ADDR_TYPE_TOR_V3;
}

static bool IsLocal(const struct wireaddr *addr)
{
    // IPv4 loopback
    if (IsIPv4(addr) && (GetByte(addr, 3) == 127 || GetByte(addr, 3) == 0))
        return true;

    // IPv6 loopback (::1/128)
    static const unsigned char pchLocal[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (IsIPv6(addr) && RawEq(addr, pchLocal, sizeof(pchLocal)))
        return true;

    return false;
}

static bool IsInternal(const struct wireaddr *addr)
{
    return false;
}

static bool IsValid(const struct wireaddr *addr)
{
    // unspecified IPv6 address (::/128)
    unsigned char ipNone6[16] = {};
    if (IsIPv6(addr) && RawEq(addr, ipNone6, sizeof(ipNone6)))
        return false;

    // documentation IPv6 address
    if (IsRFC3849(addr))
        return false;

    if (IsInternal(addr))
        return false;

    if (IsIPv4(addr))
    {
        // INADDR_NONE
        uint32_t ipNone = INADDR_NONE;
        if (RawEq(addr, &ipNone, sizeof(ipNone)))
            return false;

        // 0
        ipNone = 0;
        if (RawEq(addr, &ipNone, sizeof(ipNone)))
            return false;
    }

    return true;
}

static bool IsRoutable(const struct wireaddr *addr)
{
    return IsValid(addr) && !(IsRFC1918(addr) || IsRFC2544(addr) || IsRFC3927(addr) || IsRFC4862(addr) || IsRFC6598(addr) || IsRFC5737(addr) || (IsRFC4193(addr) && !IsTor(addr)) || IsRFC4843(addr) || IsLocal(addr) || IsInternal(addr));
}

/* Trick I learned from Harald Welte: create UDP socket, connect() and
 * then query address. */
/* Returns 0 if protocol completely unsupported, ADDR_LISTEN if we
 * can't reach addr, ADDR_LISTEN_AND_ANNOUNCE if we can (and fill saddr). */
static bool get_local_sockname(int af, void *saddr, socklen_t saddrlen)
{
    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        status_debug("Failed to create %u socket: %s",
                     af, strerror(errno));
        return false;
    }

    if (connect(fd, saddr, saddrlen) != 0) {
        status_debug("Failed to connect %u socket: %s",
                     af, strerror(errno));
        close(fd);
        return false;
    }

    if (getsockname(fd, saddr, &saddrlen) != 0) {
        status_debug("Failed to get %u socket name: %s",
                     af, strerror(errno));
        close(fd);
        return false;
    }

    close(fd);
    return true;
}

bool guess_address(struct wireaddr *addr)
{
    bool ret;

    /* We point to Google nameservers, works unless you're inside Google :) */
    switch (addr->type) {
    case ADDR_TYPE_IPV4: {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_port = htons(53);
        /* 8.8.8.8 */
        sin.sin_addr.s_addr = 0x08080808;
        sin.sin_family = AF_INET;
        ret = get_local_sockname(AF_INET, &sin, sizeof(sin));
        addr->addrlen = sizeof(sin.sin_addr);
        memcpy(addr->addr, &sin.sin_addr, addr->addrlen);
        return ret;
    }
    case ADDR_TYPE_IPV6: {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        /* 2001:4860:4860::8888 */
        static const unsigned char pchGoogle[16]
            = {0x20,0x01,0x48,0x60,0x48,0x60,0,0,0,0,0,0,8,8,8,8};
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_port = htons(53);
        sin6.sin6_family = AF_INET6;
        memcpy(sin6.sin6_addr.s6_addr, pchGoogle, sizeof(pchGoogle));
        ret = get_local_sockname(AF_INET6, &sin6, sizeof(sin6));
        addr->addrlen = sizeof(sin6.sin6_addr);
        memcpy(addr->addr, &sin6.sin6_addr, addr->addrlen);
        return ret;
    }
    case ADDR_TYPE_TOR_V2_REMOVED:
    case ADDR_TYPE_TOR_V3:
    case ADDR_TYPE_DNS:
    case ADDR_TYPE_WEBSOCKET:
        status_broken("Cannot guess address type %u", addr->type);
        break;
    }
    abort();
}

bool address_routable(const struct wireaddr *wireaddr, bool allow_localhost)
{
    if (allow_localhost && IsLocal(wireaddr))
        return true;
    return IsRoutable(wireaddr);
}
