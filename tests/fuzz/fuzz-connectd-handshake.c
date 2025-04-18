#include "config.h"
#include <assert.h>
#include <ccan/io/io.h>
#include <ccan/str/hex/hex.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/wireaddr.h>
#include <fcntl.h>
#include <tests/fuzz/libfuzz.h>

#define STATE_FUZZ
#include "connectd_handshake.h"

/* Define handshake states */
enum hs_state {
    /* Common States */
    HS_INIT,
    HS_COMPLETE,

    /* Initiator-specific */
    INITIATOR_ACT1_SEND,
    INITIATOR_ACT2_RECEIVE,
    INITIATOR_ACT3_SEND,

    /* Responder-specific */
    RESPONDER_ACT1_RECEIVE,
    RESPONDER_ACT2_SEND,
    RESPONDER_ACT3_RECEIVE,
};

static struct fuzz_ctx {
    enum hs_state state;
    struct handshake *init_hs, *resp_hs;
	struct io_conn *conn;
    u8 act_one[ACT_ONE_SIZE];
    u8 act_two[ACT_TWO_SIZE];
    u8 act_three[ACT_THREE_SIZE];
} ctx;

/* The io_write() interceptor.*/
static struct io_plan *
test_write(struct io_conn *conn, const void *data, size_t len,
	   struct io_plan *(*next)(struct io_conn *, struct handshake *),
	   struct handshake *h)
{
	if (ctx.state == INITIATOR_ACT1_SEND || ctx.state == HS_INIT) {
		/* Initiator is sending the Act 1 packet. Save it for the
		 * responder and then error out. */
		assert(h->side == INITIATOR);
		assert(len == ACT_ONE_SIZE);

		memcpy(&ctx.act_one, data, sizeof(ctx.act_one));
		check_act_one((struct act_one*) ctx.act_one);

        ctx.state = RESPONDER_ACT1_RECEIVE;
		return handshake_failed(conn, ctx.init_hs);
	}
	if (ctx.state == RESPONDER_ACT2_SEND) {
		/* Responder is sending the Act 2 packet. Save it for the
		 * responder and then error out. */
		assert(h->side == RESPONDER);
		assert(len == ACT_TWO_SIZE);

		memcpy(&ctx.act_two, data, sizeof(ctx.act_two));
		check_act_two((struct act_two*) ctx.act_two);

        ctx.state = INITIATOR_ACT2_RECEIVE;
		return handshake_failed(conn, ctx.resp_hs);
	}
    if (ctx.state == INITIATOR_ACT3_SEND) {
		/* Initiator is sending the Act 3 packet. Save it for the
		 * responder and then error out. */
		assert(h->side == INITIATOR);
		assert(len == ACT_THREE_SIZE);

		memcpy(ctx.act_three, data, sizeof(ctx.act_three));
		check_act_three((struct act_three*) ctx.act_three);

        ctx.state = RESPONDER_ACT3_RECEIVE;
		return handshake_failed(conn, ctx.init_hs);
	}
	assert(false && "Unknown state");
}

/* The io_read() interceptor.*/
static struct io_plan *test_read(struct io_conn *conn, void *data, size_t len,
				 struct io_plan *(*next)(struct io_conn *,
							 struct handshake *),
				 struct handshake *h)
{
	if (ctx.state == RESPONDER_ACT1_RECEIVE) {
		/* Responder is reading the Act 1 packet. Use the packet
		 * provided by the initiator. */
		assert(h->side == RESPONDER);
		assert(len == ACT_ONE_SIZE);

        memcpy(data, ctx.act_one, sizeof(ctx.act_one));
        ctx.state = RESPONDER_ACT2_SEND;
		return next(conn, ctx.resp_hs);
	}
	if (ctx.state == INITIATOR_ACT2_RECEIVE) {
		/* Initiator is reading the Act 2 packet. Use the packet
		 * provided by the responder. */
		assert(h->side == INITIATOR);
		assert(len == ACT_TWO_SIZE);

		memcpy(data, ctx.act_two, sizeof(ctx.act_two));
        ctx.state = INITIATOR_ACT3_SEND;
		return next(conn, ctx.init_hs);
	}
    if (ctx.state == RESPONDER_ACT3_RECEIVE) {
		/* Responder is reading the Act 3 packet. Use the packet
		 * provided by the initiator. */
		assert(h->side == RESPONDER);
		assert(len == ACT_THREE_SIZE);

        memcpy(data, ctx.act_three, sizeof(ctx.act_three));
        ctx.state = HS_COMPLETE;
		return next(conn, ctx.resp_hs);
	}
	assert(false && "Unknown state");
}

/* An interceptor that performs ECDH using the correct private key corresponding
   to the sender or reciever. This is expected to be called exactly twice. */
void ecdh(const struct pubkey *point, struct secret *ss)
{
	if (ctx.state == RESPONDER_ACT2_SEND)
		assert(secp256k1_ecdh(secp256k1_ctx, ss->data, &point->pubkey,
				resp_priv.secret.data, NULL, NULL) == 1);
	else if (ctx.state == INITIATOR_ACT3_SEND)
		assert(secp256k1_ecdh(secp256k1_ctx, ss->data, &point->pubkey,
				init_priv.secret.data, NULL, NULL) == 1);
	else
		assert(false && "ECDH called out of state");
}

static struct handshake *initialize_handshake(struct io_conn *conn,
	const struct pubkey *my_id,
	const struct pubkey *their_id,
	const struct wireaddr_internal *addr,
	struct oneshot *timeout,
	enum is_websocket is_websocket,
	enum bolt8_side side,
	struct io_plan *(*cb)(struct io_conn *,
			  const struct pubkey *,
			  const struct wireaddr_internal *,
			  struct crypto_state *,
			  struct oneshot *timeout,
			  enum is_websocket is_websocket,
			  void *cbarg),
	void *cbarg)
{
	struct handshake *h = (side == INITIATOR) ? new_handshake(conn, their_id) :
							new_handshake(conn, my_id);

	h->my_id = *my_id;
	if (their_id)
		h->their_id = *their_id;
	h->addr = *addr;
	h->cbarg = cbarg;
	h->cb = cb;
	h->is_websocket = is_websocket;
	h->side = side;
	h->timeout = timeout;

	return h;
}

static struct io_plan *
silent_success(struct io_conn *conn UNUSED, const struct pubkey *them UNUSED,
	const struct wireaddr_internal *addr UNUSED, struct crypto_state *cs,
	struct oneshot *timeout UNUSED, enum is_websocket is_websocket UNUSED,
	void *unused UNUSED)
{
	return NULL;
}

static void reset_fuzz_ctx(struct fuzz_ctx *ctx)
{
	struct wireaddr_internal dummy;
	dummy.itype = ADDR_INTERNAL_WIREADDR;
	dummy.u.wireaddr.wireaddr.addrlen = 0;

	ctx->conn = NULL;

    ctx->init_hs = initialize_handshake(ctx->conn, &init_pub, &resp_pub, &dummy, NULL,
					NORMAL_SOCKET, INITIATOR, silent_success, NULL);

    ctx->resp_hs = initialize_handshake(ctx->conn, &resp_pub, NULL, &dummy, NULL,
					NORMAL_SOCKET, RESPONDER, silent_success, NULL);

    ctx->state = HS_INIT;
}

void run(const uint8_t *data, size_t size)
{
    if (size < randombytes_SEEDBYTES + ACT_ONE_SIZE + ACT_TWO_SIZE + ACT_THREE_SIZE)
        return;

    init_globals(data, size);
    reset_fuzz_ctx(&ctx);

	/* Simulate a complete handshake by invoking the correct caller after
	   each write—because the harness errors out after each write. */
	act_one_initiator(ctx.conn, ctx.init_hs);
	act_one_responder(ctx.conn, ctx.resp_hs);
	act_two_initiator(ctx.conn, ctx.init_hs);
	act_three_responder(ctx.conn, ctx.resp_hs);

}
