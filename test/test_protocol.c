/* Simple simulator for protocol. */
#include "config.h"
#include "utils.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <ccan/str/str.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>

#define A_LINEX 100
#define B_LINEX 245
#define A_TEXTX 95
#define B_TEXTX 250

#define LINE_HEIGHT 5
#define TEXT_HEIGHT 4
#define STEP_HEIGHT 10
#define LETTER_WIDTH 3

#define TEXT_STYLE "style=\"font-size:4;\""

static bool verbose = false;

struct commit_tx {
	/* inhtlcs = htlcs they offered, outhtlcs = htlcs we offered */
	u32 inhtlcs, outhtlcs;
	/* This is a simple counter, reflecting fee updates. */
	u32 fee;
};

/* We keep one for them, one for us. */
struct commit_info {
	struct commit_info *prev;
	/* How deep we are */
	unsigned int number;
	/* Have sent/received revocation secret. */
	bool revoked;
	/* Have their signature, ie. can be broadcast */
	bool counterparty_signed;
	u16 pad;
	/* num_commit_or_revoke when we sent/received this. */
	size_t order;
};

/* A "signature" is a copy of the commit tx state, for easy diagnosis. */
struct signature {
	struct commit_tx f;
};

/* What are we doing: adding or removing? */
#define ADDING				0x1000
#define REMOVING			0x2000

#define PENDING				0x001 /* Change is pending. */
#define COMMITTED			0x002 /* HTLC is in commit_tx */
#define REVOKED				0x004 /* Old pre-change tx revoked */
#define OWNER				0x020 /* This side owns it */

#define OURS				LOCAL(OWNER)
#define THEIRS				REMOTE(OWNER)

#define LOCAL_				0
#define REMOTE_				6
#define SIDE(flag,local_or_remote)	((flag) << local_or_remote)
#define OTHER_SIDE(flag,local_or_remote)	((flag) << (6 - local_or_remote))
#define LOCAL(flag)			SIDE(flag, LOCAL_)
#define REMOTE(flag)			SIDE(flag, REMOTE_)

enum htlc_state {
	NONEXISTENT = 0,

	/* When we add a new htlc, it goes in this order. */
	SENT_ADD_HTLC = ADDING + OURS + REMOTE(PENDING),
	SENT_ADD_COMMIT = SENT_ADD_HTLC - REMOTE(PENDING) + REMOTE(COMMITTED),
	RECV_ADD_REVOCATION = SENT_ADD_COMMIT + REMOTE(REVOKED),
	RECV_ADD_ACK_COMMIT = RECV_ADD_REVOCATION + LOCAL(COMMITTED),
	SENT_ADD_ACK_REVOCATION = RECV_ADD_ACK_COMMIT + LOCAL(REVOKED) - ADDING,

	/* When they remove an htlc, it goes from SENT_ADD_ACK_REVOCATION: */
	RECV_REMOVE_HTLC = REMOVING + OURS + LOCAL(PENDING)
				+ LOCAL(COMMITTED) + REMOTE(COMMITTED),
	RECV_REMOVE_COMMIT = RECV_REMOVE_HTLC - LOCAL(PENDING) - LOCAL(COMMITTED),
	SENT_REMOVE_REVOCATION = RECV_REMOVE_COMMIT + LOCAL(REVOKED),
	SENT_REMOVE_ACK_COMMIT = SENT_REMOVE_REVOCATION - REMOTE(COMMITTED),
	RECV_REMOVE_ACK_REVOCATION = SENT_REMOVE_ACK_COMMIT - REMOVING + REMOTE(REVOKED),

	/* When they add a new htlc, it goes in this order. */
	RECV_ADD_HTLC = ADDING + THEIRS + LOCAL(PENDING),
	RECV_ADD_COMMIT = RECV_ADD_HTLC - LOCAL(PENDING) + LOCAL(COMMITTED),
	SENT_ADD_REVOCATION = RECV_ADD_COMMIT + LOCAL(REVOKED),
	SENT_ADD_ACK_COMMIT = SENT_ADD_REVOCATION + REMOTE(COMMITTED),
	RECV_ADD_ACK_REVOCATION = SENT_ADD_ACK_COMMIT + REMOTE(REVOKED),

	/* When we remove an htlc, it goes from RECV_ADD_ACK_REVOCATION: */
	SENT_REMOVE_HTLC = REMOVING + THEIRS + REMOTE(PENDING)
				+ LOCAL(COMMITTED) + REMOTE(COMMITTED),
	SENT_REMOVE_COMMIT = SENT_REMOVE_HTLC - REMOTE(PENDING) - REMOTE(COMMITTED),
	RECV_REMOVE_REVOCATION = SENT_REMOVE_COMMIT + REMOTE(REVOKED),
	RECV_REMOVE_ACK_COMMIT = RECV_REMOVE_REVOCATION - LOCAL(COMMITTED),
	SENT_REMOVE_ACK_REVOCATION = RECV_REMOVE_ACK_COMMIT + LOCAL(REVOKED) - REMOVING
};

static const char *htlc_statename(enum htlc_state state)
{
	switch (state) {
	case NONEXISTENT: return "NONEXISTENT";
	case SENT_ADD_HTLC: return "SENT_ADD_HTLC";
	case SENT_ADD_COMMIT: return "SENT_ADD_COMMIT";
	case RECV_ADD_REVOCATION: return "RECV_ADD_REVOCATION";
	case RECV_ADD_ACK_COMMIT: return "RECV_ADD_ACK_COMMIT";
	case SENT_ADD_ACK_REVOCATION: return "SENT_ADD_ACK_REVOCATION";
	case RECV_REMOVE_HTLC: return "RECV_REMOVE_HTLC";
	case RECV_REMOVE_COMMIT: return "RECV_REMOVE_COMMIT";
	case SENT_REMOVE_REVOCATION: return "SENT_REMOVE_REVOCATION";
	case SENT_REMOVE_ACK_COMMIT: return "SENT_REMOVE_ACK_COMMIT";
	case RECV_REMOVE_ACK_REVOCATION: return "RECV_REMOVE_ACK_REVOCATION";
	case RECV_ADD_HTLC: return "RECV_ADD_HTLC";
	case RECV_ADD_COMMIT: return "RECV_ADD_COMMIT";
	case SENT_ADD_REVOCATION: return "SENT_ADD_REVOCATION";
	case SENT_ADD_ACK_COMMIT: return "SENT_ADD_ACK_COMMIT";
	case RECV_ADD_ACK_REVOCATION: return "RECV_ADD_ACK_REVOCATION";
	case SENT_REMOVE_HTLC: return "SENT_REMOVE_HTLC";
	case SENT_REMOVE_COMMIT: return "SENT_REMOVE_COMMIT";
	case RECV_REMOVE_REVOCATION: return "RECV_REMOVE_REVOCATION";
	case RECV_REMOVE_ACK_COMMIT: return "RECV_REMOVE_ACK_COMMIT";
	case SENT_REMOVE_ACK_REVOCATION: return "SENT_REMOVE_ACK_REVOCATION";
	}
	return tal_fmt(NULL, "UNKNOWN STATE %i", state);
}

static const char *htlc_stateflags(const tal_t *ctx, enum htlc_state state)
{
	char *flags = tal_strdup(ctx, "");
#define ADD_STATE(flags, flag)					\
	if (state & flag)						\
		tal_append_fmt(&flags, #flag ",");

	ADD_STATE(flags, ADDING);
	ADD_STATE(flags, REMOVING);
	ADD_STATE(flags, OURS);
	ADD_STATE(flags, THEIRS);

	ADD_STATE(flags, LOCAL(PENDING));
	ADD_STATE(flags, LOCAL(COMMITTED));
	ADD_STATE(flags, LOCAL(REVOKED));

	ADD_STATE(flags, REMOTE(PENDING));
	ADD_STATE(flags, REMOTE(COMMITTED));
	ADD_STATE(flags, REMOTE(REVOKED));

	if (strends(flags, ","))
		flags[strlen(flags)-1] = '\0';

	return flags;
}

struct htlc {
	enum htlc_state state;
	/* 0 means this is actually a new fee, not a HTLC. */
	unsigned int id;
};

static u32 htlc_mask(unsigned int htlc)
{
	if (htlc > 32)
		errx(1, "HTLC number %u too large", htlc);
	if (!htlc)
		errx(1, "HTLC number can't be zero");
	return (1U << (htlc-1));
}

/* Make commit tx for local/remote */
static struct commit_tx make_commit_tx(struct htlc **htlcs, int local_or_remote)
{
	size_t i, n = tal_count(htlcs);
	int committed_flag = SIDE(COMMITTED, local_or_remote);
	struct commit_tx tx = { 0, 0, 0 };

	for (i = 0; i < n; i++) {
		if (!(htlcs[i]->state & committed_flag))
			continue;

		if (!(htlcs[i]->state & SIDE(OWNER, local_or_remote))) {
			/* We don't apply fee changes to each other. */
			if (htlcs[i]->id)
				tx.outhtlcs |= htlc_mask(htlcs[i]->id);
		} else {
			if (!htlcs[i]->id)
				tx.fee++;
			else
				tx.inhtlcs |= htlc_mask(htlcs[i]->id);
		}
	}

	return tx;
}

struct database {
	/* This keeps *all* our HTLCs, including expired ones. */
	size_t num_htlcs;
	struct htlc htlcs[100];

	/* This counts the number of received commit and revocation pkts. */
	size_t last_recv;
	size_t last_sent;

	/* We keep remote_prev because it might not be revoked, and this
	 * makes our receive_revoke logic simpler. */
	struct commit_info local, remote, remote_prev;
};

struct peer {
	const char *name;

	int infd, outfd, cmdfd, cmddonefd;

	/* For drawing svg */
	char *info;

	/* What we save on disk. */
	struct database db;

	/* All htlcs. */
	struct htlc **htlcs;

	/* Last one is the one we're changing. */
	struct commit_info *local, *remote;
};

static void db_update_htlc(struct database *db, const struct htlc *htlc)
{
	size_t i;

	for (i = 0; i < db->num_htlcs; i++) {
		if ((db->htlcs[i].state & (OURS|THEIRS))
		    != (htlc->state & (OURS|THEIRS)))
			continue;
		/* FIXME: This isn't quite right for multiple fee changes. */
		if (db->htlcs[i].id == htlc->id)
			break;
	}
	if (i == db->num_htlcs) {
		db->num_htlcs++;
		if (db->num_htlcs > ARRAY_SIZE(db->htlcs))
			errx(1, "Too many htlcs");
	}
	db->htlcs[i] = *htlc;
}

static void db_recv_local_commit(struct database *db,
				 const struct commit_info *ci)
{
	db->last_recv++;
	db->local = *ci;
}

static void db_send_remote_commit(struct peer *peer,
				  struct database *db,
				  const struct commit_info *ci,
				  struct signature sig)
{
	if (ci->prev)
		db->remote_prev = *ci->prev;
	db->remote = *ci;
	db->remote.order = ++db->last_sent;
}

static void db_send_local_revoke(struct database *db,
				 const struct commit_info *ci)
{
	db->last_sent++;
}

static void db_recv_remote_revoke(struct database *db,
				  const struct commit_info *ci)
{
	assert(ci->revoked);

	db->last_recv++;
	db->remote_prev.revoked = true;

	/* A real db would save the previous revocation hash here too */
}

static struct htlc *find_htlc(struct peer *peer, unsigned int htlc_id, int side)
{
	size_t i, n = tal_count(peer->htlcs);

	for (i = 0; i < n; i++) {
		if ((peer->htlcs[i]->state & side)
		    && peer->htlcs[i]->id == htlc_id)
			return peer->htlcs[i];
	}
	return NULL;
}

static struct htlc *new_htlc(struct peer *peer, unsigned int htlc_id, int side)
{
	size_t n = tal_count(peer->htlcs);

	/* Fee changes don't have to be unique. */
	if (htlc_id && find_htlc(peer, htlc_id, side))
		errx(1, "%s: %s duplicate new htlc %u", peer->name,
		     side == OURS ? "Our" : "Their", htlc_id);
	tal_resize(&peer->htlcs, n+1);
	peer->htlcs[n] = tal(peer, struct htlc);
	peer->htlcs[n]->state = NONEXISTENT;
	peer->htlcs[n]->id = htlc_id;

	return peer->htlcs[n];
}

static void htlc_changestate(struct peer *peer,
			     struct htlc *htlc,
			     bool commit,
			     enum htlc_state old,
			     enum htlc_state new)
{
	if (htlc->state != old)
		errx(1, "%s: htlc was in state %s not %s", peer->name,
		     htlc_statename(htlc->state), htlc_statename(old));
	if (htlc->id) {
		if (verbose)
			printf("%s: HTLC %u -> %s\n",
			       peer->name, htlc->id, htlc_statename(new));
		tal_append_fmt(&peer->info, "%u:%s\n",
			       htlc->id, htlc_statename(new));
	} else {
		if (verbose)
			printf("%s: FEE -> %s\n",
			       peer->name, htlc_statename(new));
		tal_append_fmt(&peer->info, "FEE:%s\n",
			       htlc_statename(new));
	}
	htlc->state = new;
	if (commit)
		db_update_htlc(&peer->db, htlc);
}

struct state_table {
	enum htlc_state from, to;
};

static bool change_htlcs_(struct peer *peer, bool commit,
			  const struct state_table *table,
			  size_t n_table)
{
	size_t i, n = tal_count(peer->htlcs);
	bool changed = false;

	for (i = 0; i < n; i++) {
		size_t t;
		for (t = 0; t < n_table; t++) {
			if (peer->htlcs[i]->state == table[t].from) {
				htlc_changestate(peer, peer->htlcs[i], commit,
						 table[t].from, table[t].to);
				changed = true;
				break;
			}
		}
	}
	return changed;
}

#define change_htlcs(peer, table, commit)				\
	change_htlcs_((peer), (commit), (table), ARRAY_SIZE(table))

static struct commit_info *new_commit_info(const struct peer *peer,
					   struct commit_info *prev)
{
	struct commit_info *ci = tal(peer, struct commit_info);

	ci->prev = prev;
	ci->revoked = false;
	ci->counterparty_signed = false;
	ci->pad = 0;
	ci->order = 0;
	if (prev)
		ci->number = prev->number + 1;
	else
		ci->number = 0;
	return ci;
}

static struct signature commit_sig(const struct commit_tx *commit_tx)
{
	struct signature sig;
	sig.f = *commit_tx;
	return sig;
}

static void write_out(int fd, const void *p, size_t len)
{
	if (!write_all(fd, p, len))
		err(1, "Writing to peer");
}

static void dump_htlcs(struct htlc **htlcs,
		       const char *prefix,
		       bool verbose,
		       int flags_inc, int flags_exc)
{
	size_t i, n = tal_count(htlcs);
	const tal_t *ctx = tal_tmpctx(htlcs);
	bool printed = false;

	for (i = 0; i < n; i++) {
		if ((htlcs[i]->state & flags_inc) != flags_inc)
			continue;
		if (htlcs[i]->state & flags_exc)
			continue;
		if (!htlcs[i]->id && !verbose)
			continue;
		if (!printed) {
			printf("%s", prefix);
			printed = true;
		}
		if (!htlcs[i]->id)
			printf(" FEE");
		else
			printf(" %u", htlcs[i]->id);
		if (verbose) {
			printf(" (%s - %s)",
			       htlc_statename(htlcs[i]->state),
			       htlc_stateflags(ctx, htlcs[i]->state));
		}
	}
	if (printed)
		printf("\n");
	tal_free(ctx);
}

static void dump_commit_info(const struct peer *peer,
			     const struct commit_info *ci,
			     int local_or_remote)
{
	struct commit_tx tx;
	int committed_flag = SIDE(COMMITTED, local_or_remote);

	tx = make_commit_tx(peer->htlcs, local_or_remote);

	printf(" Commit %u:\n", ci->number);
	dump_htlcs(peer->htlcs, "  Our htlcs:", false,
		   OURS|committed_flag, 0);
	dump_htlcs(peer->htlcs, "  Their htlcs:", false,
		   THEIRS|committed_flag, 0);

	/* Don't clutter output if fee level untouched. */
	if (tx.fee)
		printf("  Fee level %u\n", tx.fee);

	dump_htlcs(peer->htlcs, "Pending unacked:", true,
		   SIDE(PENDING, local_or_remote), committed_flag);

	dump_htlcs(peer->htlcs, "Pending acked:", true,
		   OTHER_SIDE(COMMITTED, local_or_remote), committed_flag);

	if (ci->counterparty_signed)
		printf("  SIGNED\n");
	if (ci->revoked)
		printf("  REVOKED\n");
	fflush(stdout);
}

static void dump_peer(const struct peer *peer, bool all)
{
	printf("LOCAL COMMIT:\n");
	dump_commit_info(peer, peer->local, LOCAL_);

	printf("REMOTE COMMIT:\n");
	dump_commit_info(peer, peer->remote, REMOTE_);

	if (all)
		dump_htlcs(peer->htlcs, "OLD HTLCs:", true,
			   0, LOCAL(COMMITTED)|REMOTE(COMMITTED));
}

static void read_in(int fd, void *p, size_t len)
{
	alarm(5);
	if (!read_all(fd, p, len))
		err(1, "Reading from peer");
	alarm(0);
}

static void read_peer(struct peer *peer, const char *str, const char *cmd)
{
	char *p = tal_arr(peer, char, strlen(str)+1);
	read_in(peer->infd, p, strlen(str));
	p[strlen(str)] = '\0';
	if (!streq(p, str))
		errx(1, "%s: %s: Expected %s from peer, got %s",
		     peer->name, cmd, str, p);
	tal_free(p);
}

static void PRINTF_FMT(2,3) record_send(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	tal_append_fmt(&peer->info, ">");
	tal_append_vfmt(&peer->info, fmt, ap);
	tal_append_fmt(&peer->info, "\n");
	va_end(ap);

	if (verbose) {
		va_start(ap, fmt);
		printf("%s: SEND ", peer->name);
		vprintf(fmt, ap);
		printf("\n");
		va_end(ap);
	}
}

static void PRINTF_FMT(2,3) record_recv(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	tal_append_fmt(&peer->info, "<");
	tal_append_vfmt(&peer->info, fmt, ap);
	tal_append_fmt(&peer->info, "\n");
	va_end(ap);

	if (verbose) {
		va_start(ap, fmt);
		printf("%s: RECEIVE ", peer->name);
		vprintf(fmt, ap);
		printf("\n");
		va_end(ap);
	}
}

static void xmit_add_htlc(struct peer *peer, const struct htlc *h)
{
	record_send(peer, "add_htlc %u", h->id);
	write_out(peer->outfd, "+", 1);
	write_out(peer->outfd, &h->id, sizeof(h->id));
}

static void xmit_remove_htlc(struct peer *peer, const struct htlc *h)
{
	record_send(peer, "fulfill_htlc %u", h->id);
	write_out(peer->outfd, "-", 1);
	write_out(peer->outfd, &h->id, sizeof(h->id));
}

static void xmit_feechange(struct peer *peer)
{
	record_send(peer, "update_fee");
	write_out(peer->outfd, "F", 1);
}

static void xmit_commit(struct peer *peer, struct signature sig)
{
	record_send(peer, "update_commit");
	write_out(peer->outfd, "C", 1);
	write_out(peer->outfd, &sig, sizeof(sig));
}

static void xmit_revoke(struct peer *peer, unsigned int number)
{
	record_send(peer, "update_revocation");
	write_out(peer->outfd, "R", 1);
	write_out(peer->outfd, &number, sizeof(number));
}

static void send_offer(struct peer *peer, unsigned int htlc)
{
	struct htlc *h = new_htlc(peer, htlc, OURS);

	htlc_changestate(peer, h, false, NONEXISTENT, SENT_ADD_HTLC);
	xmit_add_htlc(peer, h);
}

static void send_remove(struct peer *peer, unsigned int htlc)
{
	struct htlc *h = find_htlc(peer, htlc, THEIRS);

	if (!h)
		errx(1, "%s: send_remove: htlc %u does not exist",
		     peer->name, htlc);

	htlc_changestate(peer, h, false, RECV_ADD_ACK_REVOCATION, SENT_REMOVE_HTLC);
	xmit_remove_htlc(peer, h);
}

static void send_feechange(struct peer *peer)
{
	struct htlc *fee = new_htlc(peer, 0, OURS);

	htlc_changestate(peer, fee, false, NONEXISTENT, SENT_ADD_HTLC);
	xmit_feechange(peer);
}

/*
 * We don't enforce the rule that commits have to wait for revoke response
 * before the next one.
 */
static struct commit_info *last_unrevoked(struct commit_info *ci)
{
	struct commit_info *next = NULL;

	/* If this is already revoked, all are. */
	if (ci->revoked)
		return NULL;

	/* Find revoked commit; one we hit before that was last unrevoked. */
	for (; ci; next = ci, ci = ci->prev) {
		if (ci->revoked)
			break;
	}
	return next;
}

static void send_commit(struct peer *peer)
{
	struct commit_tx tx;
	struct signature sig;

	static const struct state_table changes[] = {
		{ SENT_ADD_HTLC, SENT_ADD_COMMIT },
		{ SENT_REMOVE_REVOCATION, SENT_REMOVE_ACK_COMMIT },
		{ SENT_ADD_REVOCATION, SENT_ADD_ACK_COMMIT},
		{ SENT_REMOVE_HTLC, SENT_REMOVE_COMMIT}
	};

	/* FIXME-OLD #2:
	 *
	 * An implementation MAY choose not to send an `update_commit`
	 * until it receives the `update_revocation` response to the
	 * previous `update_commit`, so there is only ever one
	 * unrevoked local commitment. */
	if (peer->remote->prev && !peer->remote->prev->revoked)
		errx(1, "%s: commit: must wait for previous commit", peer->name);

	/* FIXME-OLD #2:
	 *
	 * ...a sending node MUST apply all remote acked and unacked
	 * changes except unacked fee changes to the remote commitment
	 * before generating `sig`.
	 */
	if (!change_htlcs(peer, changes, true)) {
		/* FIXME-OLD #2:
		 *
		 * A node MUST NOT send an `update_commit` message which does
		 * not include any updates.
		 */
		errx(1, "%s: commit: no changes to commit", peer->name);
	}
	tx = make_commit_tx(peer->htlcs, REMOTE_);
	sig = commit_sig(&tx);

	peer->remote = new_commit_info(peer, peer->remote);
	peer->remote->counterparty_signed = true;
	db_send_remote_commit(peer, &peer->db, peer->remote, sig);

	/* Tell other side about commit and result (it should agree!) */
	xmit_commit(peer, sig);
}

static void receive_revoke(struct peer *peer, u32 number)
{
	static const struct state_table changes[] = {
		{ SENT_ADD_COMMIT, RECV_ADD_REVOCATION },
		{ SENT_REMOVE_ACK_COMMIT, RECV_REMOVE_ACK_REVOCATION },
		{ SENT_ADD_ACK_COMMIT, RECV_ADD_ACK_REVOCATION },
		{ SENT_REMOVE_COMMIT, RECV_REMOVE_REVOCATION }
	};
	struct commit_info *ci = last_unrevoked(peer->remote);

	if (!ci)
		errx(1, "%s: receive_revoke: no commit to revoke", peer->name);
	if (ci->number != number)
		errx(1, "%s: receive_revoke: revoked %u but %u is next",
		     peer->name, number, ci->number);

	/* This shouldn't happen if we don't allow multiple commits. */
	if (ci != peer->remote->prev)
		errx(1, "%s: receive_revoke: always revoke previous?",
		     peer->name);

	if (ci->revoked)
		errx(1, "%s: receive_revoke: already revoked?", peer->name);

	record_recv(peer, "update_revocation");
	ci->revoked = true;
	if (!ci->counterparty_signed)
		errx(1, "%s: receive_revoke: revoked unsigned commit?",
		     peer->name);

	if (!change_htlcs(peer, changes, true))
		errx(1, "%s: receive_revoke: no changes?", peer->name);

	db_recv_remote_revoke(&peer->db, ci);
}

/* FIXME-OLD #2:
 *
 * the receiving node MUST add the HTLC addition to the unacked
 * changeset for its local commitment.
 */
static void receive_offer(struct peer *peer, unsigned int htlc)
{
	struct htlc *h = new_htlc(peer, htlc, THEIRS);

	htlc_changestate(peer, h, false, NONEXISTENT, RECV_ADD_HTLC);
	record_recv(peer, "add_htlc %u", h->id);
}

/* FIXME-OLD #2:
 *
 * the receiving node MUST add the HTLC fulfill/fail to the unacked
 * changeset for its local commitment.
 */
static void receive_remove(struct peer *peer, unsigned int htlc)
{
	struct htlc *h = find_htlc(peer, htlc, OURS);

	if (!h)
		errx(1, "%s: recv_remove: htlc %u does not exist",
		     peer->name, htlc);

	htlc_changestate(peer, h, false, SENT_ADD_ACK_REVOCATION, RECV_REMOVE_HTLC);
	record_recv(peer, "fulfill_htlc %u", h->id);
}

/* FIXME-OLD #2:
 *
 * the receiving node MUST add the fee change to the unacked changeset
 * for its local commitment.
 */
static void receive_feechange(struct peer *peer)
{
	struct htlc *fee = new_htlc(peer, 0, THEIRS);

	htlc_changestate(peer, fee, false, NONEXISTENT, RECV_ADD_HTLC);
	record_recv(peer, "update_fee");
}

/* Send revoke.
 * - Queue changes to them.
 */
static void send_revoke(struct peer *peer, struct commit_info *ci)
{
	static const struct state_table changes[] = {
		{ RECV_ADD_ACK_COMMIT, SENT_ADD_ACK_REVOCATION },
		{ RECV_REMOVE_COMMIT, SENT_REMOVE_REVOCATION },
		{ RECV_ADD_COMMIT, SENT_ADD_REVOCATION },
		{ RECV_REMOVE_ACK_COMMIT, SENT_REMOVE_ACK_REVOCATION }
	};

	/* We always revoke in order. */
	assert(!ci->prev || ci->prev->revoked);
	assert(ci->counterparty_signed);
	assert(!ci->revoked);
	ci->revoked = true;

	if (!change_htlcs(peer, changes, true))
		errx(1, "%s: update_revocation: no changes?", peer->name);

	db_send_local_revoke(&peer->db, ci);
	xmit_revoke(peer, ci->number);
}

/* Receive commit:
 * - Apply changes to us.
 */
static void receive_commit(struct peer *peer, const struct signature *sig)
{
	struct commit_tx commit_tx;
	struct signature oursig;
	static const struct state_table changes[] = {
		{ RECV_ADD_REVOCATION, RECV_ADD_ACK_COMMIT },
		{ RECV_REMOVE_HTLC, RECV_REMOVE_COMMIT },
		{ RECV_ADD_HTLC, RECV_ADD_COMMIT },
		{ RECV_REMOVE_REVOCATION, RECV_REMOVE_ACK_COMMIT }
	};

	record_recv(peer, "update_commit");

	/* FIXME-OLD #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates.
	 */
	if (!change_htlcs(peer, changes, true))
		errx(1, "%s: receive_commit: no changes to commit", peer->name);

	commit_tx = make_commit_tx(peer->htlcs, LOCAL_);
	oursig = commit_sig(&commit_tx);
	if (!structeq(sig, &oursig))
		errx(1, "%s: Commit state %#x/%#x/%u, they gave %#x/%#x/%u",
		     peer->name,
		     sig->f.inhtlcs, sig->f.outhtlcs, sig->f.fee,
		     oursig.f.inhtlcs, oursig.f.outhtlcs, oursig.f.fee);

	peer->local = new_commit_info(peer, peer->local);
	peer->local->counterparty_signed = true;

	db_recv_local_commit(&peer->db, peer->local);

	send_revoke(peer, peer->local->prev);
}

static void resend_updates(struct peer *peer)
{
	size_t i;

	/* Re-transmit our add, removes and fee changes. */
	for (i = 0; i < tal_count(peer->htlcs); i++) {
		switch (peer->htlcs[i]->state) {
		case SENT_ADD_COMMIT:
			if (peer->htlcs[i]->id)
				xmit_add_htlc(peer, peer->htlcs[i]);
			else
				xmit_feechange(peer);
			break;
		case SENT_REMOVE_COMMIT:
			xmit_remove_htlc(peer, peer->htlcs[i]);
			break;
		default:
			break;
		}
	}
}

static void restore_state(struct peer *peer)
{
	size_t i, sent, num_revokes, revoke_idx;

	peer->htlcs = tal_arr(peer, struct htlc *, peer->db.num_htlcs);
	for (i = 0; i < peer->db.num_htlcs; i++) {
		peer->htlcs[i] = tal_dup(peer->htlcs, struct htlc,
					 &peer->db.htlcs[i]);
		if (verbose)
			printf("%s: HTLC %u %s\n",
			       peer->name, peer->htlcs[i]->id,
			       htlc_statename(peer->htlcs[i]->state));
	}

	*peer->local = peer->db.local;
	peer->local->prev = NULL;

	*peer->remote = peer->db.remote;
	if (peer->remote->number != 0) {
		peer->remote->prev = tal(peer, struct commit_info);
		*peer->remote->prev = peer->db.remote_prev;
		peer->remote->prev->prev = NULL;
	} else
		peer->remote->prev = NULL;

	/* Tell peer where we've received. */
	write_out(peer->outfd, "!", 1);
	write_out(peer->outfd, &peer->db.last_recv, sizeof(peer->db.last_recv));

	/* Find out where peer is up to. */
	read_peer(peer, "!", "restore");
	read_in(peer->infd, &sent, sizeof(sent));

	if (verbose)
		printf("%s: peer is up to %zu/%zu: last commit at %zu\n",
		       peer->name, sent, peer->db.last_sent,peer->remote->order);

	if (sent > peer->db.last_sent)
		errx(1, "%s: peer said up to %zu, but we only sent %zu",
		     peer->name, sent, peer->db.last_sent);

	/* All up to date?  Nothing to do. */
	if (sent == peer->db.last_sent)
		return;

	/* Since we wait for revocation replies, only one of the missing
	 * could be our update; the rest must be revocations. */
	num_revokes = peer->db.last_sent - sent - (sent < peer->remote->order);

	if (num_revokes > peer->local->number)
		errx(1, "%s: can't rexmit %zu revoke txs at %u",
		     peer->name, num_revokes, peer->local->number);

	revoke_idx = peer->local->number - num_revokes;

	/* If we sent a revocation before the commit. */
	if (sent + 1 < peer->remote->order) {
		xmit_revoke(peer, revoke_idx++);
		num_revokes--;
		sent++;
	}

	/* If they didn't get the last commit, re-send all. */
	if (sent + 1 == peer->remote->order) {
		struct commit_tx tx;
		struct signature sig;

		resend_updates(peer);
		tx = make_commit_tx(peer->htlcs, REMOTE_);
		sig = commit_sig(&tx);
		xmit_commit(peer, sig);
		sent++;
	}

	/* Now send any revocations after the commit. */
	if (sent + 1 == peer->db.last_sent) {
		num_revokes--;
		xmit_revoke(peer, revoke_idx++);
		sent++;
	}

	if (sent != peer->db.last_sent)
		errx(1, "%s: could not catch up %zu to %zu",
		     peer->name, sent, peer->db.last_sent);

	assert(num_revokes == 0);
}

static void do_cmd(struct peer *peer)
{
	char cmd[80];
	int i;
	unsigned int htlc;
	struct commit_info *ci;

	i = read(peer->cmdfd, cmd, sizeof(cmd)-1);
	if (i <= 0)
		err(1, "%s: reading command", peer->name);
	if (cmd[i-1] != '\0')
		errx(1, "%s: Unterminated command", peer->name);

	if (i == 1) {
		fflush(stdout);
		exit(0);
	}

	peer->info = tal_strdup(peer, "");

	if (sscanf(cmd, "offer %u", &htlc) == 1)
		send_offer(peer, htlc);
	else if (sscanf(cmd, "remove %u", &htlc) == 1)
		send_remove(peer, htlc);
	else if (streq(cmd, "feechange"))
		send_feechange(peer);
	else if (streq(cmd, "commit"))
		send_commit(peer);
	else if (streq(cmd, "recvrevoke")) {
		u32 number;
		read_peer(peer, "R", cmd);
		read_in(peer->infd, &number, sizeof(number));
		receive_revoke(peer, number);
	} else if (streq(cmd, "recvoffer")) {
		read_peer(peer, "+", cmd);
		read_in(peer->infd, &htlc, sizeof(htlc));
		receive_offer(peer, htlc);
	} else if (streq(cmd, "recvremove")) {
		read_peer(peer, "-", cmd);
		read_in(peer->infd, &htlc, sizeof(htlc));
		receive_remove(peer, htlc);
	} else if (streq(cmd, "recvfeechange")) {
		read_peer(peer, "F", cmd);
		receive_feechange(peer);
	} else if (streq(cmd, "recvcommit")) {
		struct signature sig;
		read_peer(peer, "C", cmd);
		read_in(peer->infd, &sig, sizeof(sig));
		receive_commit(peer, &sig);
	} else if (streq(cmd, "save")) {
		write_all(peer->cmddonefd, &peer->db, sizeof(peer->db));
		return;
	} else if (streq(cmd, "restore")) {
		write_all(peer->cmddonefd, "", 1);
		/* Ack, then read in blob */
		read_all(peer->cmdfd, &peer->db, sizeof(peer->db));
		restore_state(peer);
	} else if (streq(cmd, "checksync")) {
		struct commit_tx ours, theirs;

		ours = make_commit_tx(peer->htlcs, LOCAL_);
		theirs = make_commit_tx(peer->htlcs, REMOTE_);
		write_all(peer->cmddonefd, &ours, sizeof(ours));
		write_all(peer->cmddonefd, &theirs, sizeof(theirs));
		return;
	} else if (streq(cmd, "dump")) {
		dump_peer(peer, false);
	} else if (streq(cmd, "dumpall")) {
		dump_peer(peer, true);
	} else
		errx(1, "%s: Unknown command %s", peer->name, cmd);

	if (write(peer->cmddonefd, peer->info, strlen(peer->info)+1)
	    != strlen(peer->info)+1)
		abort();

	/* We must always have (at least one) signed, unrevoked commit. */
	for (ci = peer->local; ci; ci = ci->prev) {
		if (ci->counterparty_signed && !ci->revoked) {
			return;
		}
	}
	errx(1, "%s: No signed, unrevoked commit!", peer->name);
}

static void new_peer(const char *name,
		     int infdpair[2], int outfdpair[2], int cmdfdpair[2],
		     int cmddonefdpair[2])
{
	struct peer *peer;

	switch (fork()) {
	case 0:
		break;
	case -1:
		err(1, "Forking");
	default:
		return;
	}

	close(infdpair[1]);
	close(outfdpair[0]);
	close(cmdfdpair[1]);
	close(cmddonefdpair[0]);

	peer = tal(NULL, struct peer);
	peer->name = name;
	peer->htlcs = tal_arr(peer, struct htlc *, 0);

	memset(&peer->db, 0, sizeof(peer->db));

	/* Create first, signed commit info. */
	peer->local = new_commit_info(peer, NULL);
	peer->local->counterparty_signed = true;

	peer->remote = new_commit_info(peer, NULL);
	peer->remote->counterparty_signed = true;

	peer->db.local = *peer->local;
	peer->db.remote = *peer->remote;

	peer->infd = infdpair[0];
	peer->outfd = outfdpair[1];
	peer->cmdfd = cmdfdpair[0];
	peer->cmddonefd = cmddonefdpair[1];

	while (1)
		do_cmd(peer);
}

struct sent {
	int y;
	const char *desc;
};

static void add_sent(struct sent **sent, int y, const char *msg)
{
	size_t n = tal_count(*sent);
	tal_resize(sent, n+1);
	(*sent)[n].y = y;
	(*sent)[n].desc = tal_strdup(*sent, msg);
}

static void draw_restart(char **str, const char *name,
			 struct sent **a_sent, struct sent **b_sent,
			 int *y)
{
	*y += STEP_HEIGHT / 2;
	tal_append_fmt(str, "<line x1=\"%i\" y1=\"%i\" x2=\"%i\" y2=\"%i\" stroke=\"black\" stroke-width=\"1\"/>\n",
		       A_TEXTX - 50, *y, B_TEXTX + 50, *y);
	tal_append_fmt(str, "<text text-anchor=\"middle\" "TEXT_STYLE" x=\"%i\" y=\"%i\">%s</text>\n",
		       (A_TEXTX + B_TEXTX) / 2, *y - TEXT_HEIGHT/2, name);
	*y += STEP_HEIGHT / 2;
}

static void draw_line(char **str,
		      int old_x, struct sent **sent, const char *what,
		      int new_x, int new_y)
{
	size_t n = tal_count(*sent);
	if (n == 0)
		errx(1, "Receive without send?");

	if (!streq((*sent)->desc, what))
		errx(1, "Received %s but sent %s?", what, (*sent)->desc);

	if (*str) {
		tal_append_fmt(str, "<line x1=\"%i\" y1=\"%i\" x2=\"%i\" y2=\"%i\" marker-end=\"url(#tri)\" stroke=\"black\" stroke-width=\"0.5\"/>\n",
			       old_x, (*sent)[0].y - LINE_HEIGHT/2,
			       new_x, new_y - LINE_HEIGHT/2);
		tal_append_fmt(str, "<text text-anchor=\"middle\" "TEXT_STYLE" x=\"%i\" y=\"%i\">%s</text>\n",
			       (old_x + new_x) / 2,
			       ((*sent)[0].y + new_y) / 2,
			       (*sent)[0].desc);
	}

	memmove(*sent, (*sent)+1, sizeof(**sent) * (n-1));
	tal_resize(sent, n-1);
}

static void reset_sends(char **svg, bool is_a, struct sent **sent, int *y)
{
	/* These sends were lost. */
	while (tal_count(*sent)) {
		if (is_a)
			draw_line(svg, A_LINEX, sent, (*sent)->desc,
				  (B_LINEX + A_LINEX)/2, *y - STEP_HEIGHT/2);
		else
			draw_line(svg, B_LINEX, sent, (*sent)->desc,
				  (B_LINEX + A_LINEX)/2, *y - STEP_HEIGHT/2);
	}
}

static bool append_text(char **svg, bool is_a, int *y, const char *text,
			size_t *max_chars)
{
	char **texts = tal_strsplit(NULL, text, "\n", STR_NO_EMPTY);
	size_t i;

	if (tal_count(texts) == 1)
		return false;

	for (i = 0; i < tal_count(texts) - 1; i++) {
		tal_append_fmt(svg,
			       "<text x=\"%i\" y=\"%i\" text-anchor=\"%s\" "TEXT_STYLE">%s</text>",
			       is_a ? A_TEXTX : B_TEXTX, *y,
			       is_a ? "end" : "start",
			       texts[i]);
		*y += TEXT_HEIGHT;
		if (strlen(texts[i]) > *max_chars)
			*max_chars = strlen(texts[i]);
	}
	return true;
}

static bool process_output(char **svg, bool is_a, const char *output,
			   struct sent **a_sent, struct sent **b_sent,
			   int *y, size_t *max_chars)
{
	/* We can recv and send for recvcommit */
	char **outputs = tal_strsplit(NULL, output, "\n", STR_NO_EMPTY);
	size_t i;

	if (tal_count(outputs) == 1)
		return false;

	for (i = 0; i < tal_count(outputs)-1; i++) {
		if (strstarts(outputs[i], "<")) {
			if (is_a)
				draw_line(svg, B_LINEX, b_sent, outputs[i]+1,
					  A_LINEX, *y);
			else
				draw_line(svg, A_LINEX, a_sent, outputs[i]+1,
					  B_LINEX, *y);
			*y += STEP_HEIGHT;
		} else if (strstarts(outputs[i], ">")) {
			if (is_a)
				add_sent(a_sent, *y, outputs[i]+1);
			else
				add_sent(b_sent, *y, outputs[i]+1);
			*y += STEP_HEIGHT;
		} else {
			append_text(svg, is_a, y, outputs[i], max_chars);
		}
	}
	return true;
}

static void get_output(int donefd, char **svg, bool is_a,
		       struct sent **a_sent, struct sent **b_sent,
		       int *y, size_t *max_chars)
{
	char output[200];
	int r;

	alarm(5);
	/* FIXME: Assumes large pipebuf, atomic read */
	r = read(donefd, output, sizeof(output)-1);
	if (r <= 0)
		err(1, "Reading from %s", is_a ? "A" : "B");
	output[r] = '\0';
	alarm(0);

	if (*svg)
		process_output(svg, is_a, output, a_sent, b_sent, y, max_chars);
}

static void start_clients(int a_to_b[2],
			  int b_to_a[2],
			  int acmd[2],
			  int bcmd[2],
			  int adonefd[2],
			  int bdonefd[2])
{
	if (pipe(a_to_b) || pipe(b_to_a) || pipe(adonefd) || pipe(acmd))
		err(1, "Creating pipes");

	new_peer("A", a_to_b, b_to_a, acmd, adonefd);

	if (pipe(bdonefd) || pipe(bcmd))
		err(1, "Creating pipes");

	new_peer("B", b_to_a, a_to_b, bcmd, bdonefd);

	close(acmd[0]);
	close(bcmd[0]);
	close(adonefd[1]);
	close(bdonefd[1]);
	close(b_to_a[0]);
	close(b_to_a[1]);
	close(a_to_b[0]);
	close(a_to_b[1]);
}

static void do_nothing(int sig)
{
}

static void read_from_client(const char *desc, int fd, void *dst, size_t len)
{
	alarm(5);
	while (len) {
		int r = read(fd, dst, len);
		if (r < 0)
			err(1, "Reading from %s", desc);
		if (r == 0)
			errx(1, "%s closed", desc);
		len -= r;
		dst += r;
	}
	alarm(0);
}

static void write_to_client(const char *desc, int fd, const void *dst, size_t len)
{
	if (!write_all(fd, dst, len))
		err(1, "Writing to %s", desc);
}


static void stop_clients(int acmd[2],
			 int bcmd[2],
			 int adonefd[2],
			 int bdonefd[2])
{
	char unused;

	write_to_client("A", acmd[1], "", 1);
	write_to_client("B", bcmd[1], "", 1);

	/* Make sure they've finished */
	alarm(5);
	if (read(adonefd[0], &unused, 1) || read(bdonefd[0], &unused, 1))
		errx(1, "Response after sending exit command");
	alarm(0);

	close(acmd[1]);
	close(bcmd[1]);
	close(adonefd[0]);
	close(bdonefd[0]);
}

int main(int argc, char *argv[])
{
	char cmd[80], *svg;
	int a_to_b[2], b_to_a[2], acmd[2], bcmd[2], adonefd[2], bdonefd[2];
	int y = STEP_HEIGHT + LINE_HEIGHT;
	struct sent *a_sent = tal_arr(NULL, struct sent, 0),
		*b_sent = tal_arr(NULL, struct sent, 0);
	size_t max_chars = 0;
	bool do_svg = false;

	err_set_progname(argv[0]);
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "\n"
			   "Lightning protocol tester.",
			   "Print this message.");
	opt_register_noarg("--svg", opt_set_bool, &do_svg, "Output SVG diagram");
	opt_register_noarg("--verbose", opt_set_bool, &verbose,
			   "Extra output");
	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 1)
		errx(1, "no arguments accepted");

	if (do_svg)
		svg = tal_strdup(NULL, "");
	else
		svg = NULL;

#if 1
	{
	struct sigaction alarmed, old;

	memset(&alarmed, 0, sizeof(alarmed));
	alarmed.sa_flags = SA_RESETHAND;
	alarmed.sa_handler = do_nothing;

	if (sigaction(SIGALRM, &alarmed, &old) != 0)
		err(1, "Setting alarm handler");
	}
#else
	signal(SIGALRM, do_nothing);
#endif

	start_clients(a_to_b, b_to_a, acmd, bcmd, adonefd, bdonefd);

	while (fgets(cmd, sizeof(cmd), stdin)) {
		int cmdfd, donefd;

		if (!strends(cmd, "\n"))
			errx(1, "Truncated command");
		cmd[strlen(cmd)-1] = '\0';

		if (verbose)
			printf("%s\n", cmd);

		if (strstarts(cmd, "A:")) {
			cmdfd = acmd[1];
			donefd = adonefd[0];
		} else if (strstarts(cmd, "B:")) {
			cmdfd = bcmd[1];
			donefd = bdonefd[0];
		} else if (strstarts(cmd, "echo ")) {
			if (!svg) {
				printf("%s\n", cmd + 5);
				fflush(stdout);
			}
			continue;
		} else if (streq(cmd, "checksync")) {
			struct commit_tx fa_us, fa_them, fb_us, fb_them;
			write_to_client("A", acmd[1], cmd, strlen(cmd)+1);
			write_to_client("B", bcmd[1], cmd, strlen(cmd)+1);
			read_from_client("A", adonefd[0], &fa_us, sizeof(fa_us));
			read_from_client("B", bdonefd[0], &fb_us, sizeof(fb_us));
			read_from_client("A", adonefd[0],
					 &fa_them, sizeof(fa_them));
			read_from_client("A", bdonefd[0],
					 &fb_them, sizeof(fb_them));
			if (!structeq(&fa_us, &fb_them)
			    || !structeq(&fa_them, &fb_us))
				errx(1, "checksync: not equal");
			continue;
		} else if (streq(cmd, "restart")) {
			struct database a_db, b_db;
			char ack;

			if (svg)
				draw_restart(&svg, "RESTART",
					     &a_sent, &b_sent, &y);

			write_to_client("A", acmd[1], "save", strlen("save")+1);
			write_to_client("B", bcmd[1], "save", strlen("save")+1);

			read_from_client("A", adonefd[0], &a_db, sizeof(a_db));
			read_from_client("B", bdonefd[0], &b_db, sizeof(b_db));

			stop_clients(acmd, bcmd, adonefd, bdonefd);

			/* Forget everything they sent */
			reset_sends(&svg, true, &a_sent, &y);
			reset_sends(&svg, false, &b_sent, &y);

			start_clients(a_to_b, b_to_a, acmd, bcmd,
				      adonefd, bdonefd);

			/* Send restore command, wait for ack, send blob */
			write_to_client("A", acmd[1], "restore", strlen("restore")+1);
			write_to_client("B", bcmd[1], "restore", strlen("restore")+1);

			read_from_client("A", adonefd[0], &ack, 1);
			read_from_client("B", bdonefd[0], &ack, 1);

			write_to_client("A", acmd[1], &a_db, sizeof(a_db));
			write_to_client("B", bcmd[1], &b_db, sizeof(b_db));

			get_output(adonefd[0], &svg, true,
				   &a_sent, &b_sent, &y, &max_chars);
			get_output(bdonefd[0], &svg, false,
				   &a_sent, &b_sent, &y, &max_chars);

			if (svg)
				draw_restart(&svg, "RESTART END",
					     &a_sent, &b_sent, &y);
			continue;
		} else if (strstarts(cmd, "#") || streq(cmd, ""))
			continue;
		else
			errx(1, "Unknown command %s", cmd);

		/* Don't dump if outputting svg. */
		if (svg && strstarts(cmd+2, "dump"))
			continue;

		write_to_client(cmd, cmdfd, cmd+2, strlen(cmd)-1);

		get_output(donefd, &svg, strstarts(cmd, "A:"),
			   &a_sent, &b_sent, &y, &max_chars);
	}

	stop_clients(acmd, bcmd, adonefd, bdonefd);

	if (svg)
		printf("<svg width=\"%zu\" height=\"%u\">\n"
		       "<marker id=\"tri\" "
		       "viewBox=\"0 0 5 5\" refX=\"0\" refY=\"5\" "
		       "markerUnits=\"strokeWidth\" "
		       "markerWidth=\"4\" markerHeight=\"3\" "
		       "orient=\"auto\">"
		       "<path d=\"M 0 0 L 10 5 L 0 10 z\" />"
		       "</marker>"
		       "<text x=\"%i\" y=\"%i\" text-anchor=\"middle\">Node A</text>\n"
		       "<text x=\"%i\" y=\"%i\" text-anchor=\"middle\">Node B</text>\n"
		       "%s\n"
		       "</svg>\n",
		       B_TEXTX + max_chars*LETTER_WIDTH, y + LINE_HEIGHT,
		       A_LINEX, STEP_HEIGHT, B_LINEX, STEP_HEIGHT,
		       svg);

	return 0;
}
