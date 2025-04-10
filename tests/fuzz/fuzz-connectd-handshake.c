#include "config.h"
#include <assert.h>
#include <ccan/io/io.h>
#include <ccan/str/hex/hex.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/wireaddr.h>
#include <fcntl.h>
#include <tests/fuzz/libfuzz.h>
#include <tests/fuzz/connectd_handshake.h>

/* Define handshake states */
enum hs_state {
    /* Common States */
    HS_INIT,
    HS_FAILED_COMPLETE,

    /* Initiator-specific */
    INITIATOR_ACT1_SEND,
    INITIATOR_ACT2_RECEIVE,
    INITIATOR_ACT3_SEND,

    /* Responder-specific */
    RESPONDER_ACT1_RECEIVE,
    RESPONDER_ACT2_SEND,
    RESPONDER_ACT3_RECEIVE,

    STATES_COUNT
};

static struct fuzz_ctx {
    enum hs_state state;
    struct handshake *init_hs, *resp_hs;
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
	if (ctx.state == INITIATOR_ACT1_SEND) {
		/* Initiator is sending the Act 1 packet. Save it for the
		 * responder and then error out. */
		assert(h->side == INITIATOR);
		assert(len == ACT_ONE_SIZE);

		memcpy(&ctx.act_one, data, sizeof(ctx.act_one));
        ctx.state = RESPONDER_ACT1_RECEIVE;
		return handshake_failed(conn, h);
	}
	if (ctx.state == RESPONDER_ACT2_SEND) {
		/* Responder is sending the Act 2 packet. Save it for the
		 * responder and then error out. */
		assert(h->side == RESPONDER);
		assert(len == ACT_TWO_SIZE);

		memcpy(&ctx.act_two, data, sizeof(ctx.act_two));
        ctx.state = INITIATOR_ACT2_RECEIVE;
		return handshake_failed(conn, h);
	}
    if (ctx.state == INITIATOR_ACT3_SEND) {
		/* Initiator is sending the Act 3 packet. Save it for the
		 * responder and then error out. */
		assert(h->side == INITIATOR);
		assert(len == ACT_THREE_SIZE);

		memcpy(ctx.act_three, data, sizeof(ctx.act_three));
        ctx.state = RESPONDER_ACT3_RECEIVE;
		return handshake_failed(conn, h);
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

        memcpy(data, ctx.act_one, sizeof(ctx.act_three));
        ctx.state = RESPONDER_ACT2_SEND;
		return next(conn, h);
	}
	if (ctx.state == INITIATOR_ACT2_RECEIVE) {
		/* Initiator is reading the Act 2 packet. Use the packet
		 * provided by the responder. */
		assert(h->side == INITIATOR);
		assert(len == ACT_TWO_SIZE);

		memcpy(data, ctx.act_two, sizeof(ctx.act_two));
        ctx.state = INITIATOR_ACT3_SEND;
		return next(conn, h);
	}
    if (ctx.state == RESPONDER_ACT3_RECEIVE) {
		/* Responder is reading the Act 3 packet. Use the packet
		 * provided by the initiator. */
		assert(h->side == RESPONDER);
		assert(len == ACT_THREE_SIZE);

        memcpy(data, ctx.act_three, sizeof(ctx.act_three));
        ctx.state = RESPONDER_ACT2_SEND;
		return next(conn, h);
	}
	assert(false && "Unknown state");
}

static void reset_fuzz_ctx(struct fuzz_ctx *ctx) {
    ctx->init_hs = new_handshake(tmpctx, &resp_pub);
    ctx->resp_hs = new_handshake(tmpctx, &resp_pub);
    ctx->init_hs->side = INITIATOR, ctx->resp_hs->side = RESPONDER;
    ctx->state = HS_INIT;
}

void run(const uint8_t *data, size_t size)
{
    if (size < randombytes_SEEDBYTES + ACT_ONE_SIZE + ACT_TWO_SIZE + ACT_THREE_SIZE)
        return;

    init_globals(data, size);
    reset_fuzz_ctx(&ctx);

    struct io_conn *conn = io_new_conn(tmpctx, -1, NULL, NULL);

    while (bytes_remaining > 0) {
        int op = bytes[0] % (STATES_COUNT - 1);
        bytes++; bytes_remaining--;
        switch(op) {
            case INITIATOR_ACT1_SEND:
                ctx.state = INITIATOR_ACT1_SEND;
                act_one_initiator(conn, ctx.init_hs);
                break;

            case RESPONDER_ACT1_RECEIVE:
                ctx.state = RESPONDER_ACT1_RECEIVE;
                act_one_responder(conn, ctx.resp_hs);
                break;

            case RESPONDER_ACT2_SEND:
                ctx.state = RESPONDER_ACT2_SEND;
                act_two_initiator(conn, ctx.resp_hs);
                break;

            case INITIATOR_ACT2_RECEIVE:
                ctx.state = INITIATOR_ACT2_RECEIVE;
                act_two_responder(conn, ctx.init_hs);
                break;

            case INITIATOR_ACT3_SEND:
                ctx.state = INITIATOR_ACT3_SEND;
                act_three_initiator(conn, ctx.init_hs);
                break;

            case RESPONDER_ACT3_RECEIVE:
                ctx.state = HS_FAILED_COMPLETE;
                act_three_responder(conn, ctx.resp_hs);
                break;

            case HS_INIT:
            case HS_FAILED_COMPLETE:
                reset_fuzz_ctx(&ctx);
                break;

            default:
                assert(false && "Invalid state encountered");
        }
    }
}
