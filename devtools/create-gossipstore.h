#ifndef LIGHTNING_DEVTOOLS_CREATE_GOSSIPSTORE_H
#define LIGHTNING_DEVTOOLS_CREATE_GOSSIPSTORE_H
#include <stdlib.h>
#include <stdio.h>
#include <common/amount.h>

struct scidsat {
	char scid[17];
        struct amount_sat sat;
} scidsat;

struct scidsat * load_scid_file(FILE * scidfd);
#endif /* LIGHTNING_DEVTOOLS_CREATE_GOSSIPSTORE_H */
