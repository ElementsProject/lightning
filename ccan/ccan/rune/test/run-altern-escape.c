#include <ccan/rune/rune.c>
#include <ccan/rune/coding.c>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <ccan/tap/tap.h>

int main(void)
{
	static const u8 secret_zero[16];
	struct rune *rune;
	struct rune_restr *restr;
	const tal_t *ctx = tal(NULL, char);

	plan_tests(9);
	restr = rune_restr_from_string(ctx, "desc=@tipjar\\|jb55@sendsats.lol",
				       strlen("desc=@tipjar\\|jb55@sendsats.lol"));
	ok1(tal_count(restr->alterns) == 1);
	ok1(restr->alterns[0]->condition == '=');
	ok1(streq(restr->alterns[0]->fieldname, "desc"));
	ok1(streq(restr->alterns[0]->value, "@tipjar|jb55@sendsats.lol"));

	rune = rune_new(ctx, secret_zero, sizeof(secret_zero), NULL); 
	rune_add_restr(rune, take(restr));

	/* Converting via base64 should not change it! */
	rune = rune_from_base64(ctx, rune_to_base64(ctx, rune));
	ok1(tal_count(rune->restrs) == 1);
	restr = rune->restrs[0];
	ok1(tal_count(restr->alterns) == 1);
	ok1(restr->alterns[0]->condition == '=');
	ok1(streq(restr->alterns[0]->fieldname, "desc"));
	ok1(streq(restr->alterns[0]->value, "@tipjar|jb55@sendsats.lol"));
	
	tal_free(ctx);
	/* This exits depending on whether all tests passed */
	return exit_status();
}
