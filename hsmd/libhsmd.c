#include <hsmd/capabilities.h>
#include <hsmd/libhsmd.h>

/* Version codes for BIP32 extended keys in libwally-core.
 * It's not suitable to add this struct into client struct,
 * so set it static.*/
struct  bip32_key_version  bip32_key_version;

#if DEVELOPER
/* If they specify --dev-force-privkey it ends up in here. */
struct privkey *dev_force_privkey;
/* If they specify --dev-force-bip32-seed it ends up in here. */
struct secret *dev_force_bip32_seed;
#endif

/* Have we initialized the secretstuff? */
bool initialized = false;

struct hsmd_client *hsmd_client_new_main(const tal_t *ctx, u64 capabilities,
					 void *extra)
{
	struct hsmd_client *c = tal(ctx, struct hsmd_client);
	c->dbid = 0;
	c->capabilities = capabilities;
	c->extra = extra;
	return c;
}

struct hsmd_client *hsmd_client_new_peer(const tal_t *ctx, u64 capabilities,
					 u64 dbid,
					 const struct node_id *peer_id,
					 void *extra)
{
	struct hsmd_client *c = tal(ctx, struct hsmd_client);
	c->dbid = dbid;
	c->capabilities = capabilities;
	c->id = *peer_id;
	c->extra = extra;
	return c;
}

u8 *hsmd_handle_client_message(const tal_t *ctx, struct hsmd_client *client,
			       const u8 *msg)
{
	return NULL;
}
