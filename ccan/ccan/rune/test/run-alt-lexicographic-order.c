#include <ccan/rune/rune.c>
#include <ccan/rune/coding.c>
#include <ccan/tal/str/str.h>
#include <ccan/tap/tap.h>

int main(void)
{
	const char *str = "test string";
	plan_tests(strlen(str) * strlen(str));

	for (size_t i = 0; str[i]; i++) {
		char *stra = strdup(str);
		stra[i] = '\0';
		for (size_t j = 0; str[j]; j++) {
			char *strb = strdup(str);
			strb[j] = '\0';
			int lexo, strc;

			lexo = lexo_order(str, i, strb);
			strc = strcmp(stra, strb);
			if (strc > 0)
				ok1(lexo > 0);
			else if (strc < 0)
				ok1(lexo < 0);
			else
				ok1(lexo == 0);
			free(strb);
		}
		free(stra);
	}
	/* This exits depending on whether all tests passed */
	return exit_status();
}
