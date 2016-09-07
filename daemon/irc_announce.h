#ifndef LIGHTNING_DAEMON_IRC_ANNOUNCE_H
#define LIGHTNING_DAEMON_IRC_ANNOUNCE_H
#include "config.h"
#include "irc.h"

// Main entrypoint for the lightning daemon
void setup_irc_connection(struct lightningd_state *dstate);

#endif /* LIGHTNING_DAEMON_IRC_ANNOUNCE_H */
