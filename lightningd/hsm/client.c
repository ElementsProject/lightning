#include <lightningd/hsm/client.h>
#include <lightningd/hsm/gen_hsm_client_wire.h>
#include <wire/wire_sync.h>

static int hsm_fd = -1;

void hsm_setup(int fd)
{
	hsm_fd = fd;
}

bool hsm_do_ecdh(struct secret *ss, const struct pubkey *point)
{
	u8 *req = towire_hsm_ecdh_req(NULL, point), *resp;
	size_t len;

	if (!wire_sync_write(hsm_fd, req))
		goto fail;
	resp = wire_sync_read(req, hsm_fd);
	if (!resp)
		goto fail;
	len = tal_count(resp);
	if (!fromwire_hsm_ecdh_resp(resp, &len, ss))
		goto fail;
	tal_free(req);
	return true;

fail:
	tal_free(req);
	return false;
}
