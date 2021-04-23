#ifndef LIGHTNING_CONTRIB_LIBHSMD_PYTHON_LIBHSMD_PYTHON_H
#define LIGHTNING_CONTRIB_LIBHSMD_PYTHON_LIBHSMD_PYTHON_H

#include <hsmd/libhsmd.h>
char *handle(long long cap, long long dbid, char *peer_id, char *msg);
char *init(char *hex_hsm_secret, char *network_name);

#endif /* LIGHTNING_CONTRIB_LIBHSMD_PYTHON_LIBHSMD_PYTHON_H */
