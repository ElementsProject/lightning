#ifndef CCAN_OPT_TEST_UTILS_H
#define CCAN_OPT_TEST_UTILS_H
#include <ccan/opt/opt.h>
#include <stdbool.h>

bool parse_args(int *argc, char ***argv, ...);
bool parse_early_args(int *argc, char ***argv, ...);
extern char *err_output;
void save_err_output(const char *fmt, ...);
void reset_options(void);

extern unsigned int test_cb_called;
char *test_noarg(void *arg);
char *test_arg(const char *optarg, const char *arg);
void show_arg(char buf[OPT_SHOW_LEN], const char *arg);

extern struct opt_table short_table[];
extern struct opt_table long_table[];
extern struct opt_table long_and_short_table[];
extern struct opt_table subtables[];
#endif /* CCAN_OPT_TEST_UTILS_H */
