#include "names.h"
#include <ccan/str/str.h>
/* Indented for 'check-source' because it has to be included after names.h */
  #include "gen_state_names.h"
  #include "gen_pkt_names.h"

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

const char *input_name(enum state_input in)
{
	size_t i;

	for (i = 0; enum_state_input_names[i].name; i++)
		if (enum_state_input_names[i].v == in)
			return enum_state_input_names[i].name;
	return "unknown";
}

const char *pkt_name(Pkt__PktCase pkt)
{
	size_t i;

	for (i = 0; enum_PktCase_names[i].name; i++)
		if (enum_PktCase_names[i].v == pkt)
			return enum_PktCase_names[i].name;
	return "unknown";
}
