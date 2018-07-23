#include "hsm_control.h"
#include "lightningd.h"
#include "subd.h"
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/take/take.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/hsm_control.h>
#include <lightningd/log.h>
#include <lightningd/log_status.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>

int hsm_get_client_fd(struct lightningd *ld,
		      const struct pubkey *id,
		      u64 dbid,
		      int capabilities)
{
	int hsm_fd;
	u8 *msg;

	assert(dbid);
	msg = towire_hsm_client_hsmfd(NULL, id, dbid, capabilities);
	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsm_client_hsmfd_reply(msg))
		fatal("Bad reply from HSM: %s", tal_hex(tmpctx, msg));

	hsm_fd = fdpass_recv(ld->hsm_fd);
	if (hsm_fd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));
	return hsm_fd;
}

void hsm_init(struct lightningd *ld)
{
	u8 *msg;
	int fds[2];

	/* We actually send requests synchronously: only status is async. */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0)
		err(1, "Could not create hsm socketpair");

	ld->hsm = new_global_subd(ld, "lightning_hsmd", NULL, NULL,
				  take(&fds[1]), NULL);
	if (!ld->hsm)
		err(1, "Could not subd hsm");

	ld->hsm_fd = fds[0];
	if (!wire_sync_write(ld->hsm_fd, towire_hsm_init(tmpctx)))
		err(1, "Writing init msg to hsm");

	ld->wallet->bip32_base = tal(ld->wallet, struct ext_key);
	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!fromwire_hsm_init_reply(msg,
				     &ld->id, ld->wallet->bip32_base))
		errx(1, "HSM did not give init reply");
}
