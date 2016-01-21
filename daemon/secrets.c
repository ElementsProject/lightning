#include "bitcoin/privkey.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/signature.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "secrets.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <secp256k1.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct secret {
	/* Secret ID of our node; public is state->id. */
	struct privkey privkey;
};

void privkey_sign(struct peer *peer, const void *src, size_t len,
		  struct signature *sig)
{
	struct sha256_double h;

	sha256_double(&h, memcheck(src, len), len);
	sign_hash(peer->state->secpctx,
		  &peer->state->secret->privkey, &h, sig);
}

void secrets_init(struct lightningd_state *state)
{
	int fd;

	state->secret = tal(state, struct secret);

	fd = open("privkey", O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			fatal("Failed to open privkey: %s", strerror(errno));

		log_unusual(state->base_log, "Creating privkey file");
		do {
			if (RAND_bytes(state->secret->privkey.secret,
				       sizeof(state->secret->privkey.secret))
			    != 1)
				fatal("Could not get random bytes for privkey");
		} while (!pubkey_from_privkey(state->secpctx,
					      &state->secret->privkey,
					      &state->id,
					      SECP256K1_EC_COMPRESSED));

		fd = open("privkey", O_CREAT|O_EXCL|O_WRONLY, 0400);
		if (fd < 0)
		 	fatal("Failed to create privkey file: %s",
			      strerror(errno));
		if (!write_all(fd, state->secret->privkey.secret,
			       sizeof(state->secret->privkey.secret))) {
			unlink_noerr("privkey");
		 	fatal("Failed to write to privkey file: %s",
			      strerror(errno));
		}
		if (fsync(fd) != 0)
		 	fatal("Failed to sync to privkey file: %s",
			      strerror(errno));
		close(fd);

		fd = open("privkey", O_RDONLY);
		if (fd < 0)
			fatal("Failed to reopen privkey: %s", strerror(errno));
	}
	if (!read_all(fd, state->secret->privkey.secret,
		      sizeof(state->secret->privkey.secret)))
		fatal("Failed to read privkey: %s", strerror(errno));
	close(fd);
	if (!pubkey_from_privkey(state->secpctx,
				 &state->secret->privkey, &state->id,
				 SECP256K1_EC_COMPRESSED))
		fatal("Invalid privkey");

	log_info(state->base_log, "ID: ");
	log_add_hex(state->base_log, state->id.der, pubkey_derlen(&state->id));
}
