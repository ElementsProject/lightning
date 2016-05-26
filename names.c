#include "names.h"
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

const char *input_name(enum state_input in)
{
	size_t i;

	for (i = 0; enum_state_input_names[i].name; i++)
		if (enum_state_input_names[i].v == in)
			return enum_state_input_names[i].name;
	return "unknown";
}

const char *cstatus_name(enum command_status cstatus)
{
	size_t i;

	for (i = 0; enum_command_status_names[i].name; i++)
		if (enum_command_status_names[i].v == cstatus)
			return enum_command_status_names[i].name;
	return "unknown";
}
	
const char *peercond_name(enum state_peercond peercond)
{
	size_t i;

	for (i = 0; enum_state_peercond_names[i].name; i++)
		if (enum_state_peercond_names[i].v == peercond)
			return enum_state_peercond_names[i].name;
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
