#include <lightningd/gossip_msg.h>
#include <wire/wire.h>

void fromwire_gossip_getnodes_entry(const tal_t *ctx, const u8 **pptr, size_t *max, struct gossip_getnodes_entry *entry)
{
	u8 hostnamelen;
	fromwire_pubkey(pptr, max, &entry->nodeid);
	hostnamelen = fromwire_u8(pptr, max);
	entry->hostname = tal_arr(ctx, char, hostnamelen);
	fromwire_u8_array(pptr, max, (u8*)entry->hostname, hostnamelen);
	entry->port = fromwire_u16(pptr, max);
}
void towire_gossip_getnodes_entry(u8 **pptr, const struct gossip_getnodes_entry *entry)
{
	u8 hostnamelen;
	towire_pubkey(pptr, &entry->nodeid);
	if (entry->hostname) {
		hostnamelen = strlen(entry->hostname);
		towire_u8(pptr, hostnamelen);
		towire_u8_array(pptr, (u8*)entry->hostname, hostnamelen);
	}else {
		/* If we don't have a hostname just write an empty string */
		hostnamelen = 0;
		towire_u8(pptr, hostnamelen);
	}
	towire_u16(pptr, entry->port);
}
