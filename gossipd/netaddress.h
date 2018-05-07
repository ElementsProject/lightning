#ifndef LIGHTNING_GOSSIPD_NETADDRESS_H
#define LIGHTNING_GOSSIPD_NETADDRESS_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/wireaddr.h>

void guess_addresses(struct wireaddr_internal **wireaddrs,
		     enum addr_listen_announce **listen_announce,
		     u16 portnum);

#endif /* LIGHTNING_GOSSIPD_NETADDRESS_H */
