#include "hsm_control.h"
#include "lightningd.h"
#include "subdaemon.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/take/take.h>
#include <daemon/log.h>
#include <lightningd/hsm/gen_hsm_control_wire.h>
#include <lightningd/hsm/gen_hsm_status_wire.h>

static void hsm_init_done(struct subdaemon *hsm, const u8 *msg,
			  struct lightningd *ld)
{
	if (!fromwire_hsmctl_init_response(msg, NULL, &ld->dstate.id))
		errx(1, "HSM did not give init response");

	log_info_struct(ld->log, "Our ID: %s", struct pubkey, &ld->dstate.id);
	io_break(ld->hsm);
}

static void hsm_finished(struct subdaemon *hsm, int status)
{
	if (WIFEXITED(status))
		errx(1, "HSM failed (exit status %i), exiting.",
		     WEXITSTATUS(status));
	errx(1, "HSM failed (signal %u), exiting.", WTERMSIG(status));
}

void hsm_init(struct lightningd *ld, bool newdir)
{
	bool create;

	ld->hsm = new_subdaemon(ld, ld, "lightningd_hsm",
				hsm_status_wire_type_name,
				hsm_control_wire_type_name,
				hsm_finished, -1);
	if (!ld->hsm)
		err(1, "Could not subdaemon hsm");

	if (newdir)
		create = true;
	else
		create = (access("hsm_secret", F_OK) != 0);

	if (create)
		subdaemon_req(ld->hsm, take(towire_hsmctl_init_new(ld->hsm)),
			      -1, NULL, hsm_init_done, ld);
	else
		subdaemon_req(ld->hsm, take(towire_hsmctl_init_load(ld->hsm)),
			      -1, NULL, hsm_init_done, ld);

	if (io_loop(NULL, NULL) != ld->hsm)
		errx(1, "Unexpected io exit during HSM startup");
}

