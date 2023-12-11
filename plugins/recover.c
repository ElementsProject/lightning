#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/features.h>
#include <common/gossmap.h>
#include <common/hsm_encryption.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <plugins/libplugin.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
        setup_locale();

	plugin_main(argv, init, PLUGIN_STATIC, true, NULL,
		    NULL, 0,
		    NULL, 0, NULL, 0,
		    NULL, 0,  /* Notification topics we publish */
		    NULL);
}

