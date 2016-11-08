#include "names.h"
#include <ccan/str/str.h>
/* Indented for 'check-source' because it has to be included after names.h */
  #include "daemon/gen_state_names.h"
  #include "daemon/gen_pkt_names.h"

const char *state_name(enum state s)
{
	size_t i;

	for (i = 0; enum_state_names[i].name; i++)
		if (enum_state_names[i].v == s)
			return enum_state_names[i].name;
	return "unknown";
}

enum state name_to_state(const char *name)
{
	size_t i;

	for (i = 0; enum_state_names[i].name; i++)
		if (streq(name, enum_state_names[i].name))
			return enum_state_names[i].v;

	return STATE_MAX;
}

const char *pkt_name(Pkt__PktCase pkt)
{
	size_t i;

	for (i = 0; enum_PktCase_names[i].name; i++)
		if (enum_PktCase_names[i].v == pkt)
			return enum_PktCase_names[i].name;
	return "unknown";
}
