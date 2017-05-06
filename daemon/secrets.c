#include "bitcoin/privkey.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/signature.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "peer_internal.h"
#include "secrets.h"
#include "utils.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/str/str.h>
#include <errno.h>
#include <fcntl.h>
#include <secp256k1.h>
#include <sodium/randombytes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void privkey_sign(struct lightningd_state *dstate, const void *src, size_t len,
		  secp256k1_ecdsa_signature *sig)
{
	struct sha256_double h;

	sha256_double(&h, memcheck(src, len), len);
	sign_hash(dstate->privkey, &h, sig);
}

struct peer_secrets {
	/* Two private keys, one for commit txs, one for final output. */
	struct privkey commit, final;
	/* Seed from which we generate revocation hashes. */
	struct sha256 revocation_seed;
};

void peer_sign_theircommit(const struct peer *peer,
			   struct bitcoin_tx *commit,
			   secp256k1_ecdsa_signature *sig)
{
	/* Commit tx only has one input: that of the anchor. */
	sign_tx_input(commit, 0,
		      NULL,
		      peer->anchor.witnessscript,
		      &peer->secrets->commit,
		      &peer->local.commitkey,
		      sig);
}

void peer_sign_ourcommit(const struct peer *peer,
			 struct bitcoin_tx *commit,
			 secp256k1_ecdsa_signature *sig)
{
	/* Commit tx only has one input: that of the anchor. */
	sign_tx_input(commit, 0,
		      NULL,
		      peer->anchor.witnessscript,
		      &peer->secrets->commit,
		      &peer->local.commitkey,
		      sig);
}

void peer_sign_spend(const struct peer *peer,
		     struct bitcoin_tx *spend,
		     const u8 *commit_witnessscript,
		     secp256k1_ecdsa_signature *sig)
{
	/* Spend tx only has one input: that of the commit tx. */
	sign_tx_input(spend, 0,
		      NULL,
		      commit_witnessscript,
		      &peer->secrets->final,
		      &peer->local.finalkey,
		      sig);
}

void peer_sign_htlc_refund(const struct peer *peer,
			   struct bitcoin_tx *spend,
			   const u8 *htlc_witnessscript,
			   secp256k1_ecdsa_signature *sig)
{
	/* Spend tx only has one input: that of the commit tx. */
	sign_tx_input(spend, 0,
		      NULL,
		      htlc_witnessscript,
		      &peer->secrets->final,
		      &peer->local.finalkey,
		      sig);
}

void peer_sign_htlc_fulfill(const struct peer *peer,
			    struct bitcoin_tx *spend,
			    const u8 *htlc_witnessscript,
			    secp256k1_ecdsa_signature *sig)
{
	/* Spend tx only has one input: that of the commit tx. */
	sign_tx_input(spend, 0,
		      NULL,
		      htlc_witnessscript,
		      &peer->secrets->final,
		      &peer->local.finalkey,
		      sig);
}

void peer_sign_mutual_close(const struct peer *peer,
			    struct bitcoin_tx *close,
			    secp256k1_ecdsa_signature *sig)
{
	sign_tx_input(close, 0,
		      NULL,
		      peer->anchor.witnessscript,
		      &peer->secrets->commit,
		      &peer->local.commitkey,
		      sig);
}

void peer_sign_steal_input(const struct peer *peer,
			   struct bitcoin_tx *spend,
			   size_t i,
			   const u8 *witnessscript,
			   secp256k1_ecdsa_signature *sig)
{
	/* Spend tx only has one input: that of the commit tx. */
	sign_tx_input(spend, i,
		      NULL,
		      witnessscript,
		      &peer->secrets->final,
		      &peer->local.finalkey,
		      sig);
}

static void new_keypair(struct lightningd_state *dstate,
			struct privkey *privkey, struct pubkey *pubkey)
{
	do {
		randombytes_buf(privkey->secret.data,
				sizeof(privkey->secret.data));
	} while (!pubkey_from_privkey(privkey, pubkey));
}

void peer_secrets_init(struct peer *peer)
{
	peer->secrets = tal(peer, struct peer_secrets);

	new_keypair(peer->dstate, &peer->secrets->commit, &peer->local.commitkey);
	new_keypair(peer->dstate, &peer->secrets->final, &peer->local.finalkey);
	randombytes_buf(peer->secrets->revocation_seed.u.u8, sizeof(peer->secrets->revocation_seed.u.u8));
}

void peer_get_revocation_preimage(const struct peer *peer, u64 index,
				  struct sha256 *preimage)
{
	// generate hashes in reverse order, otherwise the first hash gives away everything
	shachain_from_seed(&peer->secrets->revocation_seed, 0xFFFFFFFFFFFFFFFFL - index, preimage);
}

void peer_get_revocation_hash(const struct peer *peer, u64 index,
			      struct sha256 *rhash)
{
	struct sha256 preimage;

	peer_get_revocation_preimage(peer, index, &preimage);
	sha256(rhash, preimage.u.u8, sizeof(preimage.u.u8));
}

const char *peer_secrets_for_db(const tal_t *ctx, struct peer *peer)
{
	const struct peer_secrets *ps = peer->secrets;
	return tal_fmt(ctx, "x'%s', x'%s', x'%s'",
		       tal_hexstr(ctx, &ps->commit, sizeof(ps->commit)),
		       tal_hexstr(ctx, &ps->final, sizeof(ps->final)),
		       tal_hexstr(ctx, &ps->revocation_seed,
				  sizeof(ps->revocation_seed)));
}

void peer_set_secrets_from_db(struct peer *peer,
			      const void *commit_privkey,
			      size_t commit_privkey_len,
			      const void *final_privkey,
			      size_t final_privkey_len,
			      const void *revocation_seed,
			      size_t revocation_seed_len)
{
	struct peer_secrets *ps = tal(peer, struct peer_secrets);

	assert(!peer->secrets);
	peer->secrets = ps;

	if (commit_privkey_len != sizeof(ps->commit)
	    || final_privkey_len != sizeof(ps->final)
	    || revocation_seed_len != sizeof(ps->revocation_seed))
		fatal("peer_set_secrets_from_db: bad lengths %zu/%zu/%zu",
		      commit_privkey_len, final_privkey_len,
		      revocation_seed_len);

	memcpy(&ps->commit, commit_privkey, commit_privkey_len);
	memcpy(&ps->final, final_privkey, final_privkey_len);
	memcpy(&ps->revocation_seed, revocation_seed, revocation_seed_len);

	if (!pubkey_from_privkey(&ps->commit, &peer->local.commitkey))
		fatal("peer_set_secrets_from_db:bad commit privkey");
	if (!pubkey_from_privkey(&ps->final, &peer->local.finalkey))
		fatal("peer_set_secrets_from_db:bad final privkey");
}

void secrets_init(struct lightningd_state *dstate)
{
	int fd;

	dstate->privkey = tal(dstate, struct privkey);

	fd = open("privkey", O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			fatal("Failed to open privkey: %s", strerror(errno));

		log_unusual(dstate->base_log, "Creating privkey file");
		new_keypair(dstate, dstate->privkey, &dstate->id);

		fd = open("privkey", O_CREAT|O_EXCL|O_WRONLY, 0400);
		if (fd < 0)
		 	fatal("Failed to create privkey file: %s",
			      strerror(errno));
		if (!write_all(fd, &dstate->privkey->secret,
			       sizeof(dstate->privkey->secret))) {
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
	if (!read_all(fd, &dstate->privkey->secret,
		      sizeof(dstate->privkey->secret)))
		fatal("Failed to read privkey: %s", strerror(errno));
	close(fd);
	if (!pubkey_from_privkey(dstate->privkey, &dstate->id))
		fatal("Invalid privkey");

	log_info_struct(dstate->base_log, "ID: %s", struct pubkey, &dstate->id);
}
