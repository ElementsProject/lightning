#ifndef LIGHTNING_CLI_CONFIG_CLI_H
#define LIGHTNING_CLI_CONFIG_CLI_H

#include "config.h"
#include <stdio.h>

#ifndef CLN_TEST
/* Redefinition procedure is a very cool feature, but
   if we try to redefine a procedure that is already
   redefined somewhere (like read in alpine) we can have
   tricky compilation error */
#define cli_read read
#endif

#endif /* LIGHTNING_CLI_CONFIG_CLI_H */
