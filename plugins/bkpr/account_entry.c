#include "config.h"

#include <ccan/tal/str/str.h>
#include <plugins/bkpr/account_entry.h>
#include <stddef.h>

static const char *tags[] = {
	"journal_entry",
	"penalty_adj",
	"invoice_fee",
};

const char *account_entry_tag_str(enum account_entry_tag tag)
{
	return tags[tag];
}

bool account_entry_tag_find(char *str, enum account_entry_tag *tag)
{
	for (size_t i = 0; i < NUM_ACCOUNT_ENTRY_TAGS; i++) {
		if (streq(str, tags[i])) {
			*tag = (enum account_entry_tag) i;
			return true;
		}
	}

	return false;
}
