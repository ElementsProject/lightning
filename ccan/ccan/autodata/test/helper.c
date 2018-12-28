/* Check that linking together works. */
#include <ccan/autodata/autodata.h>

AUTODATA_TYPE(autostrings, char);

AUTODATA(autostrings, "helper");
