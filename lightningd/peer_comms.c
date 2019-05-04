#include <lightningd/peer_comms.h>
#include <unistd.h>

static void destroy_peer_comms(struct peer_comms *pcomms)
{
	if (pcomms->peer_fd != -1)
		close(pcomms->peer_fd);
	if (pcomms->gossip_fd != -1)
		close(pcomms->gossip_fd);
	if (pcomms->gossip_store_fd != -1)
		close(pcomms->gossip_store_fd);
}

struct peer_comms *new_peer_comms(const tal_t *ctx)
{
	struct peer_comms *pcomms = tal(ctx, struct peer_comms);

	tal_add_destructor(pcomms, destroy_peer_comms);
	return pcomms;
}
