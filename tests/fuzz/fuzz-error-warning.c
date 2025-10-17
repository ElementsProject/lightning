#include "config.h"
#include <common/peer_failed.h>
#include <common/per_peer_state.h>
#include <common/read_peer_msg.h>
#include <common/status.h>
#include <common/utils.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdio.h>
#include <tests/fuzz/libfuzz.h>

static jmp_buf exit_jmp;

/* MOCKS START */
/* Stub for peer_failed_connection_lost */
void peer_failed_connection_lost(void)
{ fprintf(stderr, "peer_failed_connection_lost called!\n"); abort(); }
/* Stub for peer_failed_received_errmsg */
void peer_failed_received_errmsg(struct per_peer_state *pps UNNEEDED,
				 bool disconnect UNNEEDED,
				 const char *desc)

{ longjmp(exit_jmp, 1); }
/* MOCKS END */

void init(int *argc, char ***argv)
{
	int devnull = open("/dev/null", O_WRONLY);
	status_setup_sync(devnull);
}

void run(const u8 *data, size_t size)
{
	if (setjmp(exit_jmp) != 0)
		return;

	u8 *msg = tal_dup_arr(tmpctx, u8, data, size, 0);
	struct per_peer_state pps = { .peer_fd = -1 };
	handle_peer_error_or_warning(&pps, msg);

	clean_tmpctx();
}
