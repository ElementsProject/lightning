/* Simple simulator for protocol. */
#include "config.h"
#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <ccan/str/str.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>

#define A_LINEX 50
#define B_LINEX 195
#define A_TEXTX 45
#define B_TEXTX 200

#define LINE_HEIGHT 5
#define STEP_HEIGHT 10
#define LETTER_WIDTH 3

#define TEXT_STYLE "style=\"font-size:4;\""

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
	/* Commit_Tx before changes. */
	const struct commit_tx *commit_tx;
	/* Pending changes (already applied to commit_tx_next) */
	int *unacked_changeset;
	bool have_acked_changes;
	/* Cache of commit_tx with changes applied. */
	struct commit_tx commit_tx_next;
	/* Have sent/received revocation secret. */
	bool revoked;
	/* Have their signature, ie. can be broadcast */
	bool counterparty_signed;
};

/* A "signature" is a copy of the commit tx state, for easy diagnosis. */
struct signature {
	struct commit_tx f;
};

struct peer {
	int infd, outfd, cmdfd, cmddonefd;

	struct commit_tx initial_commit_tx;

	/* Are we allowed to send another commit before receiving revoke? */
	bool commitwait;

	/* For drawing svg */
	char *text;
	char *io;

	/* Last one is the one we're changing. */
	struct commit_info *local, *remote;
};

static u32 htlc_mask(unsigned int htlc)
{
	if (htlc > 32)
		errx(1, "HTLC number %u too large", htlc);
	if (!htlc)
		errx(1, "HTLC number can't be zero");
	return (1U << (htlc-1));
}

static bool have_htlc(u32 htlcs, unsigned int htlc)
{
	return htlcs & htlc_mask(htlc);
}

static void PRINTF_FMT(2,3) add_text(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	tal_append_vfmt(&peer->text, fmt, ap);
	va_end(ap);
}

/* Each side can add their own incoming HTLC, or close your outgoing HTLC. */
static bool do_change(struct peer *peer, const char *what,
		      u32 *add, u32 *remove, u32 *fees, int htlc)
{
	/* We ignore fee changes from them: they only count when reflected
	 * back to us via revocation. */
	if (htlc == 0) {
		if (fees) {
			if (what)
				add_text(peer, " FEE");
			(*fees)++;
		} else {
			if (what)
				add_text(peer, " (ignoring FEE)");
		}
	} else if (htlc < 0) {
		if (!have_htlc(*remove, -htlc))
			return false;
		*remove &= ~htlc_mask(-htlc);
		if (what)
			add_text(peer, " -%u", -htlc);
	} else {
		if (have_htlc(*add, htlc))
			return false;
		*add |= htlc_mask(htlc);
		if (what)
			add_text(peer, " +%u", htlc);
	}
	return true;
}

static void add_change_internal(struct peer *peer, int **changes, int c)
{
	size_t i, n = tal_count(*changes);

	/* You can have as many fee changes as you like */
	if (c == 0)
		goto add;

	/* Can't request add/remove twice. */
	for (i = 0; i < n; i++)
		if ((*changes)[i] == c)
			errx(1, "Already requestd htlc %+i", c);

add:
	if (c)
		add_text(peer, "%+i", c);
	else
		add_text(peer, "FEE");
	tal_resize(changes, n+1);
	(*changes)[n] = c;
}

/* BOLT #2:
 *
 * The node sending `update_revocation` MUST add the local unacked
 * changes to the set of remote acked changes.
 *
 * The receiver... MUST add the remote unacked changes to the set of
 * local acked changes.
 */
static bool add_unacked_changes(struct peer *peer,
				struct commit_info *ci, int *changes,
				const char *what)
{
	size_t i, n = tal_count(changes);

	if (n)
		add_text(peer, "%s acked:", what);

	/* BOLT #2:
	 *
	 * Note that an implementation MAY optimize this internally,
	 * for example, pre-applying the changesets in some cases
	 */
	for (i = 0; i < n; i++) {
		if (!do_change(peer, what, &ci->commit_tx_next.outhtlcs,
			       &ci->commit_tx_next.inhtlcs,
			       &ci->commit_tx_next.fee,
			       changes[i]))
			return false;
		ci->have_acked_changes = true;
	}
	return true;
}

/*
 * Normally, we add incoming changes.
 */
/* BOLT #2:
 *
 * A sending node MUST apply all remote acked and unacked changes
 * except unacked fee changes to the remote commitment before
 * generating `sig`. ... A receiving node MUST apply all local acked
 * and unacked changes except unacked fee changes to the local
 * commitment
 */
static bool add_incoming_change(struct peer *peer,
				struct commit_info *ci, int c, const char *who)
{
	/* BOLT #2:
	 *
	 * Note that an implementation MAY optimize this internally,
	 * for example, pre-applying the changesets in some cases
	 */
	if (!do_change(NULL, NULL,
		       &ci->commit_tx_next.inhtlcs, &ci->commit_tx_next.outhtlcs,
		       NULL, c))
		return false;

	add_text(peer, "%s unacked: ", who);
	add_change_internal(peer, &ci->unacked_changeset, c);
	return true;
}

static struct commit_info *new_commit_info(const struct peer *peer,
					   struct commit_info *prev)
{
	struct commit_info *ci = talz(peer, struct commit_info);
	ci->prev = prev;
	ci->unacked_changeset = tal_arr(ci, int, 0);
	ci->have_acked_changes = false;
	if (prev) {
		ci->number = prev->number + 1;
		ci->commit_tx = &prev->commit_tx_next;
		ci->commit_tx_next = prev->commit_tx_next;
	} else
		ci->commit_tx = &peer->initial_commit_tx;
	return ci;
}

/* We duplicate the commit info, with the changes applied. */
static struct commit_info *apply_changes(struct peer *peer,
					 struct commit_info *old,
					 const char *who)
{
	struct commit_info *next = new_commit_info(peer, old);
	size_t i;

	add_text(peer, "%s:[", who);
	if (old->commit_tx_next.inhtlcs)
		add_text(peer, "in");
	for (i = 1; i <= 32; i++)
		if (have_htlc(old->commit_tx_next.inhtlcs, i))
			add_text(peer, " %zu", i);
	if (old->commit_tx_next.outhtlcs)
		add_text(peer, "%sout",
			 old->commit_tx_next.inhtlcs ? ", " : "");
	for (i = 1; i <= 32; i++)
		if (have_htlc(old->commit_tx_next.outhtlcs, i))
			add_text(peer, " %zu", i);
	if (old->commit_tx_next.fee)
		add_text(peer, " fee %u", old->commit_tx_next.fee);
	add_text(peer, "]");

	return next;
}

static struct signature commit_sig(const struct commit_info *ci)
{
	struct signature sig;
	sig.f = *ci->commit_tx;
	return sig;
}

static void write_out(int fd, const void *p, size_t len)
{
	if (!write_all(fd, p, len))
		err(1, "Writing to peer");
}

static void dump_htlcs(u32 htlcs)
{
	unsigned int i;

	for (i = 1; i <= 32; i++)
		if (have_htlc(htlcs, i))
			printf(" %u", i);
}

static void dump_commit_info(const struct commit_info *ci)
{
	size_t i, n;

	printf(" Commit %u:", ci->number);
	printf("\n  Offered htlcs:");
	dump_htlcs(ci->commit_tx->outhtlcs);
	printf("\n  Received htlcs:");
	dump_htlcs(ci->commit_tx->inhtlcs);

	/* Don't clutter output if fee level untouched. */
	if (ci->commit_tx->fee)
		printf("\n  Fee level %u", ci->commit_tx->fee);

	n = tal_count(ci->unacked_changeset);
	if (n > 0) {
		printf("\n  Pending unacked:");
		for (i = 0; i < n; i++) {
			if (ci->unacked_changeset[i] == 0)
				printf(" FEE");
			else
				printf(" %+i", ci->unacked_changeset[i]);
		}
	}

	if (ci->have_acked_changes) {
		printf("\n  Pending acked");
	}

	if (ci->counterparty_signed)
		printf("\n  SIGNED");
	if (ci->revoked)
		printf("\n  REVOKED");
	printf("\n");
	fflush(stdout);
}

static void dump_rev(const struct commit_info *ci, bool all)
{
	if (ci->prev)
		dump_rev(ci->prev, all);
	if (all || !ci->revoked)
		dump_commit_info(ci);
}

static void dump_peer(const struct peer *peer, bool all)
{
	printf("LOCAL COMMITS:\n");
	dump_rev(peer->local, all);

	printf("REMOTE COMMITS:\n");
	dump_rev(peer->remote, all);
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
		errx(1, "%s: Expected %s from peer, got %s", cmd, str, p);
	tal_free(p);
}

/* BOLT #2:
 *
 * The sending node MUST add the HTLC addition to the unacked
 * changeset for its remote commitment
 */
static void send_offer(struct peer *peer, unsigned int htlc)
{
	tal_append_fmt(&peer->io, "add_htlc %u", htlc);
	/* Can't have sent already. */
	if (!add_incoming_change(peer, peer->remote, htlc, "remote"))
		errx(1, "offer: already offered %u", htlc);
	write_out(peer->outfd, "+", 1);
	write_out(peer->outfd, &htlc, sizeof(htlc));
}

/* BOLT #2:
 *
 * The sending node MUST add the HTLC fulfill/fail to the unacked
 * changeset for its remote commitment
 */
static void send_remove(struct peer *peer, unsigned int htlc)
{
	tal_append_fmt(&peer->io, "fulfill_htlc %u", htlc);
	/* Can't have removed already. */
	if (!add_incoming_change(peer, peer->remote, -htlc, "remote"))
		errx(1, "remove: already removed of %u", htlc);
	write_out(peer->outfd, "-", 1);
	write_out(peer->outfd, &htlc, sizeof(htlc));
}

/* BOLT #2:
 *
 * The sending node MUST add the fee change to the unacked changeset
 * for its remote commitment
 */
static void send_feechange(struct peer *peer)
{
	tal_append_fmt(&peer->io, "update_fee");
	if (!add_incoming_change(peer, peer->remote, 0, "remote"))
		errx(1, "INTERNAL: failed to change fee");
	write_out(peer->outfd, "F", 1);
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

/* Commit:
 * - Apply changes to remote.
 */
static void send_commit(struct peer *peer)
{
	struct signature sig;

	/* BOLT #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates. */
	if (tal_count(peer->remote->unacked_changeset) == 0
	    && !peer->remote->have_acked_changes)
		errx(1, "commit: no changes to commit");

	/* BOLT #2:
	 *
	 * An implementation MAY choose not to send an `update_commit`
	 * until it receives the `update_revocation` response to the
	 * previous `update_commit`, so there is only ever one
	 * unrevoked local commitment. */
	if (peer->commitwait
	    && peer->remote->prev && !peer->remote->prev->revoked)
		errx(1, "commit: must wait for previous commit");

	tal_append_fmt(&peer->io, "update_commit");
	/* BOLT #2:
	 *
	 * A sending node MUST apply all remote acked and unacked
	 * changes except unacked fee changes to the remote commitment
	 * before generating `sig`. */
	peer->remote = apply_changes(peer, peer->remote, "REMOTE");
	sig = commit_sig(peer->remote);
	peer->remote->counterparty_signed = true;

	/* Tell other side about commit and result (it should agree!) */
	write_out(peer->outfd, "C", 1);
	write_out(peer->outfd, &sig, sizeof(sig));
}

/* Receive revoke:
 * - Queue pending changes to us.
 */
static void receive_revoke(struct peer *peer, u32 number)
{
	struct commit_info *ci = last_unrevoked(peer->remote);

	if (!ci)
		errx(1, "receive_revoke: no commit to revoke");
	if (ci->number != number)
		errx(1, "receive_revoke: revoked %u but %u is next",
		     number, ci->number);

	/* This shouldn't happen if we don't allow multiple commits. */
	if (peer->commitwait && ci != peer->remote->prev)
		errx(1, "receive_revoke: always revoke previous?");

	tal_append_fmt(&peer->io, "<");
	ci->revoked = true;
	if (!ci->counterparty_signed)
		errx(1, "receive_revoke: revoked unsigned commit?");

	/* BOLT #2:
	 *
	 * The receiver of `update_revocation`... MUST add the remote
	 * unacked changes to the set of local acked changes. */
	if (!add_unacked_changes(peer, peer->local, ci->unacked_changeset,
				 "local"))
		errx(1, "receive_revoke: could not add their changes to local");

	/* Cleans up dump output now we've consumed them. */
	tal_free(ci->unacked_changeset);
	ci->unacked_changeset = tal_arr(ci, int, 0);
}

/* BOLT #2:
 *
 * the receiving node MUST add the HTLC addition to the unacked
 * changeset for its local commitment.
 */
static void receive_offer(struct peer *peer, unsigned int htlc)
{
	tal_append_fmt(&peer->io, "<");
	if (!add_incoming_change(peer, peer->local, htlc, "local"))
		errx(1, "receive_offer: already offered of %u", htlc);
}

/* BOLT #2:
 *
 * the receiving node MUST add the HTLC fulfill/fail to the unacked
 * changeset for its local commitment.
 */
static void receive_remove(struct peer *peer, unsigned int htlc)
{
	tal_append_fmt(&peer->io, "<");
	if (!add_incoming_change(peer, peer->local, -htlc, "local"))
		errx(1, "receive_remove: already removed %u", htlc);
}

/* BOLT #2:
 *
 * the receiving node MUST add the fee change to the unacked changeset
 * for its local commitment.
 */
static void receive_feechange(struct peer *peer)
{
	tal_append_fmt(&peer->io, "<");
	if (!add_incoming_change(peer, peer->local, 0, "local"))
		errx(1, "INTERNAL: failed to change fee");
}

/* Send revoke.
 * - Queue changes to them.
 */
static void send_revoke(struct peer *peer, struct commit_info *ci)
{
	tal_append_fmt(&peer->io, "update_revocation");

	/* We always revoke in order. */
	assert(!ci->prev || ci->prev->revoked);
	assert(ci->counterparty_signed);
	assert(!ci->revoked);
	ci->revoked = true;

	/* BOLT #2:
	 *
	 * The node sending `update_revocation` MUST add the local
	 * unacked changes to the set of remote acked changes. */
	if (!add_unacked_changes(peer, peer->remote, ci->unacked_changeset,
				 "remote"))
		errx(1, "Failed queueing changes to remote for send_revoke");

	/* Clean up for dump output. */
	tal_free(ci->unacked_changeset);
	ci->unacked_changeset = tal_arr(ci, int, 0);
	
	write_out(peer->outfd, "R", 1);
	write_out(peer->outfd, &ci->number, sizeof(ci->number));
}

/* Receive commit:
 * - Apply changes to us.
 */
static void receive_commit(struct peer *peer, const struct signature *sig)
{
	struct signature oursig;

	/* BOLT #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates.
	 */
	if (tal_count(peer->local->unacked_changeset) == 0
	    && !peer->local->have_acked_changes)
		errx(1, "receive_commit: no changes to commit");

	tal_append_fmt(&peer->io, "<");

	/* BOLT #2:
	 *
	 * A receiving node MUST apply all local acked and unacked
	 * changes except unacked fee changes to the local commitment,
	 * then it MUST check `sig` is valid for that transaction.
	 */
	peer->local = apply_changes(peer, peer->local, "LOCAL");
	oursig = commit_sig(peer->local);
	if (!structeq(sig, &oursig))
		errx(1, "Commit state %#x/%#x/%u, they gave %#x/%#x/%u",
		     sig->f.inhtlcs, sig->f.outhtlcs, sig->f.fee,
		     oursig.f.inhtlcs, oursig.f.outhtlcs, oursig.f.fee);
	peer->local->counterparty_signed = true;

	/* This is the one case where we send without a command. */
	tal_append_fmt(&peer->text, "\n");
	send_revoke(peer, peer->local->prev);
}

static void do_cmd(struct peer *peer)
{
	char cmd[80];
	int i;
	unsigned int htlc;
	struct commit_info *ci;
	struct iovec iov[2];

	i = read(peer->cmdfd, cmd, sizeof(cmd)-1);
	if (cmd[i-1] != '\0')
		errx(1, "Unterminated command");

	if (i == 1) {
		fflush(stdout);
		exit(0);
	}

	peer->io = tal_strdup(peer, "");
	peer->text = tal_strdup(peer->io, "");
	
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
	} else if (streq(cmd, "nocommitwait")) {
		peer->commitwait = false;
	} else if (streq(cmd, "checksync")) {
		write_all(peer->cmddonefd, peer->local->commit_tx,
			  sizeof(*peer->local->commit_tx));
		write_all(peer->cmddonefd, peer->remote->commit_tx,
			  sizeof(*peer->remote->commit_tx));
		return;
	} else if (streq(cmd, "dump")) {
		dump_peer(peer, false);
	} else if (streq(cmd, "dumpall")) {
		dump_peer(peer, true);
	} else
		errx(1, "Unknown command %s", cmd);

	iov[0].iov_base = peer->io;
	iov[0].iov_len = strlen(peer->io)+1;
	iov[1].iov_base = peer->text;
	iov[1].iov_len = strlen(peer->text)+1;
	writev(peer->cmddonefd, iov, 2);
	tal_free(peer->io);

	/* We must always have (at least one) signed, unrevoked commit. */
	for (ci = peer->local; ci; ci = ci->prev) {
		if (ci->counterparty_signed && !ci->revoked) {
			return;
		}
	}
	errx(1, "No signed, unrevoked commit!");
}

static void new_peer(int infdpair[2], int outfdpair[2], int cmdfdpair[2],
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
	memset(&peer->initial_commit_tx, 0, sizeof(peer->initial_commit_tx));
	peer->commitwait = true;
	
	/* Create first, signed commit info. */
	peer->local = new_commit_info(peer, NULL);
	peer->local->counterparty_signed = true;
	
	peer->remote = new_commit_info(peer, NULL);
	peer->remote->counterparty_signed = true;

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

static void draw_line(char **str,
		      int old_x, struct sent **sent, int new_x, int new_y)
{
	size_t n = tal_count(*sent);
	if (n == 0)
		errx(1, "Receive without send?");

	tal_append_fmt(str, "<line x1=\"%i\" y1=\"%i\" x2=\"%i\" y2=\"%i\" marker-end=\"url(#tri)\" stroke=\"black\" stroke-width=\"0.5\"/>\n",
		       old_x, (*sent)[0].y - LINE_HEIGHT/2,
		       new_x, new_y - LINE_HEIGHT/2);
	tal_append_fmt(str, "<text text-anchor=\"middle\" "TEXT_STYLE" x=\"%i\" y=\"%i\">%s</text>\n",
		       (old_x + new_x) / 2,
		       ((*sent)[0].y + new_y) / 2,
		       (*sent)[0].desc);

	memmove(*sent, (*sent)+1, sizeof(**sent) * (n-1));
	tal_resize(sent, n-1);
}

static void append_text(char **svg, bool is_a, int *y, char *text,
			size_t *max_chars)
{
	char *eol;
	
	eol = strchr(text, '\n');
	if (eol)
		*eol = '\0';

	tal_append_fmt(svg,
		       "<text x=\"%i\" y=\"%i\" text-anchor=\"%s\" "TEXT_STYLE">%s</text>",
		       is_a ? A_TEXTX : B_TEXTX, *y,
		       is_a ? "end" : "start",
		       text);
	if (strlen(text) > *max_chars)
		*max_chars = strlen(text);

	if (eol) {
		*y += LINE_HEIGHT;
		append_text(svg, is_a, y, eol+1, max_chars);
	}
	*y += STEP_HEIGHT;
}

int main(int argc, char *argv[])
{
	char cmd[80], output[200], *svg = tal_strdup(NULL, "");
	int a_to_b[2], b_to_a[2], acmd[2], bcmd[2], adonefd[2], bdonefd[2];
	int y = STEP_HEIGHT + LINE_HEIGHT;
	struct sent *a_sent = tal_arr(NULL, struct sent, 0),
		*b_sent = tal_arr(NULL, struct sent, 0);
	bool output_svg = false;
	size_t max_chars = 0;

	err_set_progname(argv[0]);

	if (argv[1] && streq(argv[1], "--svg"))
		output_svg = true;

	if (pipe(a_to_b) || pipe(b_to_a) || pipe(adonefd) || pipe(acmd))
		err(1, "Creating pipes");

	new_peer(a_to_b, b_to_a, acmd, adonefd);

	if (pipe(bdonefd) || pipe(bcmd))
		err(1, "Creating pipes");

	new_peer(b_to_a, a_to_b, bcmd, bdonefd);

	close(acmd[0]);
	close(bcmd[0]);
	close(adonefd[1]);
	close(bdonefd[1]);
	close(b_to_a[0]);
	close(b_to_a[1]);
	close(a_to_b[0]);
	close(a_to_b[1]);

	while (fgets(cmd, sizeof(cmd), stdin)) {
		int cmdfd, donefd, r;
		char *io, *text;

		if (!strends(cmd, "\n"))
			errx(1, "Truncated command");
		cmd[strlen(cmd)-1] = '\0';
	
		if (strstarts(cmd, "A:")) {
			cmdfd = acmd[1];
			donefd = adonefd[0];
		} else if (strstarts(cmd, "B:")) { 
			cmdfd = bcmd[1];
			donefd = bdonefd[0];
		} else if (strstarts(cmd, "echo ")) {
			if (!output_svg) {
				printf("%s\n", cmd + 5);
				fflush(stdout);
			}
			continue;
		} else if (streq(cmd, "checksync")) {
			struct commit_tx fa_us, fa_them, fb_us, fb_them;
			if (!write_all(acmd[1], cmd, strlen(cmd)+1)
			    || !write_all(bcmd[1], cmd, strlen(cmd)+1))
				errx(1, "Failed writing command to peers");
			alarm(5);
			if (!read_all(adonefd[0], &fa_us, sizeof(fa_us))
			    || !read_all(adonefd[0], &fa_them, sizeof(fa_them))
			    || !read_all(bdonefd[0], &fb_us, sizeof(fb_us))
			    || !read_all(bdonefd[0], &fb_them, sizeof(fb_them)))
				errx(1, "Failed reading status from peers");
			if (!structeq(&fa_us, &fb_them)
			    || !structeq(&fa_them, &fb_us))
				errx(1, "checksync: not equal");
			continue;
		} else if (strstarts(cmd, "#") || streq(cmd, ""))
			continue;
		else
			errx(1, "Unknown command %s", cmd);

		/* Don't dump if outputting svg. */
		if (output_svg && strstarts(cmd+2, "dump"))
			continue;

		if (!write_all(cmdfd, cmd+2, strlen(cmd)-1))
			errx(1, "Sending %s", cmd);

		alarm(5);
		r = read(donefd, output, sizeof(output)-2);
		if (r <= 0)
			errx(1, "Failed on cmd %s", cmd);
		output[r] = output[r+1] = '\0';
		io = output;
		text = output + strlen(output) + 1;
		if (r != strlen(text) + strlen(io) + 2)
			errx(1, "Not nul-terminated: %s+%s gave %zi not %u",
			     io, text, strlen(text) + strlen(io) + 2, r);
		alarm(0);

		/* We can recv and send for recvcommit */
		if (strstarts(io, "<")) {
			if (strstarts(cmd, "A:"))
				draw_line(&svg, B_LINEX, &b_sent, A_LINEX, y);
			else
				draw_line(&svg, A_LINEX, &a_sent, B_LINEX, y);
			memmove(io, io+1, strlen(io));
		}
		if (!streq(io, "")) {
			if (strstarts(cmd, "A:"))
				add_sent(&a_sent, y, io);
			else
				add_sent(&b_sent, y, io);
		}
		if (!streq(text, "") && output_svg) {
			append_text(&svg,
				    strstarts(cmd, "A:"),
				    &y,
				    text,
				    &max_chars);
		}
	}

	write_all(acmd[1], "", 1);
	write_all(bcmd[1], "", 1);

	/* Make sure they've finished */
	alarm(5);
	if (read_all(adonefd[0], &y, 1)
	    || read_all(bdonefd[0], &y, 1))
		errx(1, "Response after sending exit command");
	alarm(0);

	if (output_svg)
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
