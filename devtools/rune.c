/* Decodes a rune. */
#include "config.h"
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/rune/rune.h>
#include <common/configdir.h>
#include <common/setup.h>
#include <common/utils.h>
#include <common/version.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	struct rune *rune;
	common_setup(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<rune>", "Show this message");
	opt_register_version();

	opt_early_parse(argc, argv, opt_log_stderr_exit);
	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 2)
		opt_usage_exit_fail("needs rune");

	rune = rune_from_base64(NULL, argv[1]);
	if (!rune)
		opt_usage_exit_fail("invalid rune");

	printf("string encoding: %s\n", rune_to_string(rune, rune));
	for (size_t i = 0; i < tal_count(rune->restrs); i++) {
		const struct rune_restr *restr = rune->restrs[i];
		const char *sep = "- ";
		for (size_t j = 0; j < tal_count(restr->alterns); j++) {
			const struct rune_altern *alt = restr->alterns[j];
			if (streq(alt->fieldname, "")) {
				printf("Unique id is %s", alt->value);
			} else {
				printf("%s", sep);
				switch (alt->condition) {
				case RUNE_COND_IF_MISSING:
					printf("%s is missing", alt->fieldname);
					break;
				case RUNE_COND_EQUAL:
					printf("%s equal to %s", alt->fieldname, alt->value);
					break;
				case RUNE_COND_NOT_EQUAL:
					printf("%s unequal to %s", alt->fieldname, alt->value);
					break;
				case RUNE_COND_BEGINS:
					printf("%s starts with %s", alt->fieldname, alt->value);
					break;
				case RUNE_COND_ENDS:
					printf("%s ends with %s", alt->fieldname, alt->value);
					break;
				case RUNE_COND_CONTAINS:
					printf("%s contains %s", alt->fieldname, alt->value);
					break;
				case RUNE_COND_INT_LESS:
					printf("%s < %s", alt->fieldname, alt->value);
					break;
				case RUNE_COND_INT_GREATER:
					printf("%s > %s", alt->fieldname, alt->value);
					break;
				case RUNE_COND_LEXO_BEFORE:
					printf("%s sorts before %s", alt->fieldname, alt->value);
					break;
				case RUNE_COND_LEXO_AFTER:
					printf("%s sorts after %s", alt->fieldname, alt->value);
					break;
				case RUNE_COND_COMMENT:
					printf("comment: %s%s", alt->fieldname, alt->value);
					break;
				}
				sep = " OR ";
			}
		}
		printf("\n");
	}
	common_shutdown();
}
