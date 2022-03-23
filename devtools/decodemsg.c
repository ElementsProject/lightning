#include "config.h"
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <unistd.h>
#if EXPERIMENTAL_FEATURES
  #include <wire/onion_exp_printgen.h>
  #include <wire/peer_exp_printgen.h>
#else
  #include <wire/onion_printgen.h>
  #include <wire/peer_printgen.h>
#endif

static char *opt_set_tlvname(const char *arg,
			     bool (**printwire)(const char *fieldname,
						const u8 **cursor,
						size_t *plen))
{
	for (size_t i = 0; tlvs_printpeer_wire_byname[i].name; i++) {
		if (streq(arg, tlvs_printpeer_wire_byname[i].name)) {
			*printwire = tlvs_printpeer_wire_byname[i].print;
			return NULL;
		}
	}

	for (size_t i = 0; tlvs_printonion_wire_byname[i].name; i++) {
		if (streq(arg, tlvs_printonion_wire_byname[i].name)) {
			*printwire = tlvs_printonion_wire_byname[i].print;
			return NULL;
		}
	}
	return "Unknown tlv name";
}

static char *opt_set_onionprint(bool (**printwire)(const u8 *msg))
{
	*printwire = printonion_wire_message;
	return NULL;
}

static char *opt_list_tlvnames(void *unused)
{
	for (size_t i = 0; tlvs_printpeer_wire_byname[i].name; i++)
		printf("  %s\n", tlvs_printpeer_wire_byname[i].name);

	for (size_t i = 0; tlvs_printonion_wire_byname[i].name; i++)
		printf("  %s\n", tlvs_printonion_wire_byname[i].name);
	exit(0);
}

int main(int argc, char *argv[])
{
	const u8 *m;
	bool (*printtlv)(const char *fieldname, const u8 **cursor, size_t *plen) = NULL;
	bool (*printwire)(const u8 *msg) = printpeer_wire_message;
	bool ok = true;

	setup_locale();

	opt_register_noarg("--onion", opt_set_onionprint, &printwire,
			   "Decode an error message instead of a peer message");
	opt_register_arg("--tlv", opt_set_tlvname, NULL, &printtlv,
			"Decode a TLV of this type instead of a peer message");
	opt_register_noarg("--list-tlvs", opt_list_tlvnames, NULL,
			   "List all --tlv names supported");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "[<hexmsg>]"
			   "Decode a lightning spec wire message from hex, or a series of messages from stdin",
			   "Print this message.");

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc > 2)
		opt_usage_and_exit("Too many arguments");

	if (argc == 2) {
		/* Arg is hex string */
		m = tal_hexdata(NULL, argv[1], strlen(argv[1]));
		if (!m)
			errx(1, "'%s' is not valid hex", argv[1]);

		if (printtlv) {
			size_t len = tal_bytelen(m);
			ok &= printtlv("", &m, &len);
		} else {
			ok &= printwire(m);
		}
	} else {
		u8 *f = grab_fd(NULL, STDIN_FILENO);
		size_t off = 0;

		while (off != tal_count(f)) {
			be16 len;

			if (off + sizeof(len) > tal_count(f)) {
				warnx("Truncated file");
				ok = false;
				break;
			}
			memcpy(&len, f + off, sizeof(len));
			off += sizeof(len);
			if (off + be16_to_cpu(len) > tal_count(f)) {
				warnx("Truncated file");
				ok = false;
				break;
			}
			m = tal_dup_arr(f, u8, f + off, be16_to_cpu(len), 0);
			if (printtlv) {
				size_t len = tal_bytelen(m);
				ok &= printtlv("", &m, &len);
			} else {
				ok &= printwire(m);
			}
			off += be16_to_cpu(len);
			tal_free(m);
		}
	}
	printf("\n");

	return ok ? 0 : 1;
}
