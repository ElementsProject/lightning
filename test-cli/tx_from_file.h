#ifndef LIGHTNING_TEST_CLI_TX_FROM_FILE_H
#define LIGHTNING_TEST_CLI_TX_FROM_FILE_H
#include "config.h"
#include "bitcoin/tx.h"

struct bitcoin_tx *bitcoin_tx_from_file(const tal_t *ctx, const char *filename);
#endif /* LIGHTNING_TEST_CLI_TX_FROM_FILE_H */
