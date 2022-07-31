#ifndef LIGHTNING_PLUGINS_BKPR_ACCOUNT_ENTRY_H
#define LIGHTNING_PLUGINS_BKPR_ACCOUNT_ENTRY_H
#include "config.h"

#define NUM_ACCOUNT_ENTRY_TAGS (REBALANCEFEE + 1)
enum account_entry_tag {
	JOURNAL_ENTRY = 0,
	PENALTY_ADJ = 1,
	INVOICEFEE = 2,
	REBALANCEFEE= 3,
};

/* Convert an enum into a string */
const char *account_entry_tag_str(enum account_entry_tag tag);

/* True if entry tag found, false otherwise */
bool account_entry_tag_find(char *str, enum account_entry_tag *tag);
#endif /* LIGHTNING_PLUGINS_BKPR_ACCOUNT_ENTRY_H */
