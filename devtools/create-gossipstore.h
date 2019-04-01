#include <stdlib.h>
#include <stdio.h>
#include <common/amount.h>

struct scidsat {
	char scid[17];
        struct amount_sat sat;
} scidsat;

struct scidsat * load_scid_file(FILE * scidfd);

