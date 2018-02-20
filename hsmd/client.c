#include <hsmd/client.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <wire/wire_sync.h>

static int hsm_fd = -1;

void hsm_setup(int fd)
{
	hsm_fd = fd;
}

bool hsm_do_ecdh(struct secret *ss, const struct pubkey *point)
{
	u8 *req = towire_hsm_ecdh_req(NULL, point), *resp;

	if (!wire_sync_write(hsm_fd, req))
		goto fail;
	resp = wire_sync_read(req, hsm_fd);
	if (!resp)
		goto fail;
	if (!fromwire_hsm_ecdh_resp(resp, ss))
		goto fail;
	tal_free(req);
	return true;

fail:
	tal_free(req);
	return false;
}
