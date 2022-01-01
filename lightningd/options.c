#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/mem/mem.h>
#include <ccan/opt/opt.h>
#include <ccan/opt/private.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/features.h>
#include <common/hsm_encryption.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/json_tok.h>
#include <common/param.h>
#include <common/type_to_string.h>
#include <common/version.h>
#include <common/wireaddr.h>
#include <dirent.h>
#include <errno.h>
#include <lightningd/chaintopology.h>
#include <lightningd/options.h>
#include <lightningd/plugin.h>
#include <lightningd/subd.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* Unless overridden, we exit with status 1 when option parsing fails */
static int opt_exitcode = 1;

static void opt_log_stderr_exitcode(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(opt_exitcode);
}

/* Declare opt_add_addr here, because we we call opt_add_addr
 * and opt_announce_addr vice versa
*/
static char *opt_add_addr(const char *arg, struct lightningd *ld);

/* FIXME: Put into ccan/time. */
#define TIME_FROM_SEC(sec) { { .tv_nsec = 0, .tv_sec = sec } }
#define TIME_FROM_MSEC(msec) \
	{ { .tv_nsec = ((msec) % 1000) * 1000000, .tv_sec = (msec) / 1000 } }

static char *opt_set_u64(const char *arg, u64 *u)
{
	char *endp;
	unsigned long long l;

	assert(arg != NULL);

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	l = strtoull(arg, &endp, 0);
	if (*endp || !arg[0])
		return tal_fmt(NULL, "'%s' is not a number", arg);
	*u = l;
	if (errno || *u != l)
		return tal_fmt(NULL, "'%s' is out of range", arg);
	return NULL;
}
static char *opt_set_u32(const char *arg, u32 *u)
{
	char *endp;
	unsigned long l;

	assert(arg != NULL);

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	l = strtoul(arg, &endp, 0);
	if (*endp || !arg[0])
		return tal_fmt(NULL, "'%s' is not a number", arg);
	*u = l;
	if (errno || *u != l)
		return tal_fmt(NULL, "'%s' is out of range", arg);
	return NULL;
}

static char *opt_set_s32(const char *arg, s32 *u)
{
	char *endp;
	long l;

	assert(arg != NULL);

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	l = strtol(arg, &endp, 0);
	if (*endp || !arg[0])
		return tal_fmt(NULL, "'%s' is not a number", arg);
	*u = l;
	if (errno || *u != l)
		return tal_fmt(NULL, "'%s' is out of range", arg);
	return NULL;
}

static char *opt_set_mode(const char *arg, mode_t *m)
{
	char *endp;
	long l;

	assert(arg != NULL);

	/* Ensure length, and starts with 0.  */
	if (strlen(arg) != 4 || arg[0] != '0')
		return tal_fmt(NULL, "'%s' is not a file mode", arg);

	/* strtol, manpage, yech.  */
	errno = 0;
	l = strtol(arg, &endp, 8); /* Octal.  */
	if (errno || *endp)
		return tal_fmt(NULL, "'%s' is not a file mode", arg);
	*m = l;
	/* Range check not needed, previous strlen checks ensures only
	 * 9-bit, which fits mode_t (unless your Unix is seriously borked).
	 */

	return NULL;
}

static char *opt_force_feerates(const char *arg, struct lightningd *ld)
{
	char **vals = tal_strsplit(tmpctx, arg, "/", STR_EMPTY_OK);
	size_t n;

	/* vals has NULL at end, enum feerate is 0 based */
	if (tal_count(vals) - 1 > FEERATE_PENALTY + 1)
		return "Too many values";

	if (!ld->force_feerates)
		ld->force_feerates = tal_arr(ld, u32, FEERATE_PENALTY + 1);

	n = 0;
	for (size_t i = 0; i < tal_count(ld->force_feerates); i++) {
		char *err = opt_set_u32(vals[n], &ld->force_feerates[i]);
		if (err)
			return err;
		fprintf(stderr, "Set feerate %zu based on val %zu\n", i, n);
		if (vals[n+1])
			n++;
	}
	return NULL;
}

static char *fmt_force_feerates(const tal_t *ctx, const u32 *force_feerates)
{
	char *ret;
	size_t last;

	if (!force_feerates)
		return NULL;

	ret = tal_fmt(ctx, "%i", force_feerates[0]);
	last = 0;
	for (size_t i = 1; i < tal_count(force_feerates); i++) {
		if (force_feerates[i] == force_feerates[i-1])
			continue;
		/* Different?  Catchup! */
		for (size_t j = last + 1; j <= i; j++)
			tal_append_fmt(&ret, "/%i", force_feerates[j]);
		last = i;
	}
	return ret;
}

#if EXPERIMENTAL_FEATURES
static char *opt_set_accept_extra_tlv_types(const char *arg,
					     struct lightningd *ld)
{
	char *endp, **elements = tal_strsplit(NULL, arg, ",", STR_NO_EMPTY);;
	unsigned long long l;
	u64 u;
	for (int i = 0; elements[i] != NULL; i++) {
		/* This is how the manpage says to do it.  Yech. */
		errno = 0;
		l = strtoull(elements[i], &endp, 0);
		if (*endp || !arg[0])
			return tal_fmt(NULL, "'%s' is not a number", arg);
		u = l;
		if (errno || u != l)
			return tal_fmt(NULL, "'%s' is out of range", arg);
		tal_arr_expand(&ld->accept_extra_tlv_types, u);
	}

	tal_free(elements);
	return NULL;
}
#endif

#if EXPERIMENTAL_FEATURES /* BOLT7 DNS RFC #911 */
/* Returns the number of wireaddr types already announced */
static size_t num_announced_types(enum wire_addr_type type, struct lightningd *ld)
{
	size_t num = 0;
	for (size_t i = 0; i < tal_count(ld->proposed_wireaddr); i++) {
		if (ld->proposed_wireaddr[i].itype != ADDR_INTERNAL_WIREADDR)
			continue;
		if (ld->proposed_wireaddr[i].u.wireaddr.type != type)
			continue;
		if (ld->proposed_listen_announce[i] & ADDR_ANNOUNCE)
			num++;
	}
	return num;
}
#endif

static char *opt_add_addr_withtype(const char *arg,
				   struct lightningd *ld,
				   enum addr_listen_announce ala,
				   bool wildcard_ok)
{
	char const *err_msg;
	struct wireaddr_internal wi;
	bool dns_ok;
	char *address;
	u16 port;

	assert(arg != NULL);
	dns_ok = !ld->always_use_proxy && ld->config.use_dns;

	if (!separate_address_and_port(tmpctx, arg, &address, &port))
		return tal_fmt(NULL, "Unable to parse address:port '%s'", arg);

	if (is_ipaddr(address)
	    || is_toraddr(address)
	    || is_wildcardaddr(address)
	    || ala != ADDR_ANNOUNCE) {
		if (!parse_wireaddr_internal(arg, &wi, ld->portnum,
					     wildcard_ok, dns_ok, false,
					     deprecated_apis, &err_msg)) {
			return tal_fmt(NULL, "Unable to parse address '%s': %s", arg, err_msg);
		}

		/* Sanity check for exact duplicates. */
		for (size_t i = 0; i < tal_count(ld->proposed_wireaddr); i++) {
			/* Only compare announce vs announce and bind vs bind */
			if ((ld->proposed_listen_announce[i] & ala) == 0)
				continue;

			if (wireaddr_internal_eq(&ld->proposed_wireaddr[i], &wi))
				return tal_fmt(NULL, "Duplicate %s address %s",
					       ala & ADDR_ANNOUNCE ? "announce" : "listen",
					       type_to_string(tmpctx, struct wireaddr_internal, &wi));
		}

		tal_arr_expand(&ld->proposed_listen_announce, ala);
		tal_arr_expand(&ld->proposed_wireaddr, wi);
	}

#if EXPERIMENTAL_FEATURES /* BOLT7 DNS RFC #911 */
	/* Add ADDR_TYPE_DNS to announce DNS hostnames */
	if (is_dnsaddr(address) && ala & ADDR_ANNOUNCE) {
		/* BOLT-hostnames #7:
		 * The origin node:
		 * ...
		 *   - MUST NOT announce more than one `type 5` DNS hostname.
		 */
		if (num_announced_types(ADDR_TYPE_DNS, ld) > 0) {
			return tal_fmt(NULL, "Only one DNS can be announced");
		}
		memset(&wi, 0, sizeof(wi));
		wi.itype = ADDR_INTERNAL_WIREADDR;
		wi.u.wireaddr.type = ADDR_TYPE_DNS;
		wi.u.wireaddr.addrlen = strlen(address);
		strncpy((char * restrict)&wi.u.wireaddr.addr,
			address, sizeof(wi.u.wireaddr.addr) - 1);
		wi.u.wireaddr.port = port;

		tal_arr_expand(&ld->proposed_listen_announce, ADDR_ANNOUNCE);
		tal_arr_expand(&ld->proposed_wireaddr, wi);
	}
#endif

	return NULL;

}

static char *opt_add_announce_addr(const char *arg, struct lightningd *ld)
{
	size_t n = tal_count(ld->proposed_wireaddr);
	char *err;

	/* Check for autotor and reroute the call to --addr  */
	if (strstarts(arg, "autotor:"))
		return opt_add_addr(arg, ld);

	/* Check for statictor and reroute the call to --addr  */
	if (strstarts(arg, "statictor:"))
		return opt_add_addr(arg, ld);

	err = opt_add_addr_withtype(arg, ld, ADDR_ANNOUNCE, false);
	if (err)
		return err;

	/* Can't announce anything that's not a normal wireaddr. */
	if (ld->proposed_wireaddr[n].itype != ADDR_INTERNAL_WIREADDR)
		return tal_fmt(NULL, "address '%s' is not announcable",
			       arg);

	return NULL;
}

static char *opt_add_addr(const char *arg, struct lightningd *ld)
{
	struct wireaddr_internal addr;

	/* handle in case you used the addr option with an .onion */
	if (parse_wireaddr_internal(arg, &addr, 0, true, false, true,
				    deprecated_apis, NULL)) {
		if (addr.itype == ADDR_INTERNAL_WIREADDR &&
		    addr.u.wireaddr.type == ADDR_TYPE_TOR_V3) {
				log_unusual(ld->log, "You used `--addr=%s` option with an .onion address, please use"
							" `--announce-addr` ! You are lucky in this node live some wizards and"
							" fairies, we have done this for you and announce, Be as hidden as wished",
							arg);
				return opt_add_announce_addr(arg, ld);
		}
	}
	/* the intended call */
	return opt_add_addr_withtype(arg, ld, ADDR_LISTEN_AND_ANNOUNCE, true);
}

static char *opt_subdaemon(const char *arg, struct lightningd *ld)
{
	char *subdaemon;
	char *sdpath;

	/* example arg: "hsmd:remote_hsmd" */

	size_t colonoff = strcspn(arg, ":");
	if (!arg[colonoff])
		return tal_fmt(NULL, "argument must contain ':'");

	subdaemon = tal_strndup(ld, arg, colonoff);
	if (!is_subdaemon(subdaemon))
		return tal_fmt(NULL, "\"%s\" is not a subdaemon", subdaemon);

	/* Make the value a tal-child of the subdaemon */
	sdpath = tal_strdup(subdaemon, arg + colonoff + 1);

	/* Remove any preexisting alt subdaemon mapping (and
	 * implicitly, the sdpath). */
	tal_free(strmap_del(&ld->alt_subdaemons, subdaemon, NULL));

	strmap_add(&ld->alt_subdaemons, subdaemon, sdpath);

	return NULL;
}

static char *opt_add_bind_addr(const char *arg, struct lightningd *ld)
{
	struct wireaddr_internal addr;

	/* handle in case you used the bind option with an .onion */
	if (parse_wireaddr_internal(arg, &addr, 0, true, false, true,
				    deprecated_apis, NULL)) {
		if (addr.itype == ADDR_INTERNAL_WIREADDR &&
		    addr.u.wireaddr.type == ADDR_TYPE_TOR_V3) {
				log_unusual(ld->log, "You used `--bind-addr=%s` option with an .onion address,"
							" You are lucky in this node live some wizards and"
							" fairies, we have done this for you and don't announce, Be as hidden as wished",
							arg);
				return NULL;
		}
	}
	/* the intended call */
	return opt_add_addr_withtype(arg, ld, ADDR_LISTEN, true);
}

static void opt_show_u64(char buf[OPT_SHOW_LEN], const u64 *u)
{
	snprintf(buf, OPT_SHOW_LEN, "%"PRIu64, *u);
}
static void opt_show_u32(char buf[OPT_SHOW_LEN], const u32 *u)
{
	snprintf(buf, OPT_SHOW_LEN, "%"PRIu32, *u);
}

static void opt_show_s32(char buf[OPT_SHOW_LEN], const s32 *u)
{
	snprintf(buf, OPT_SHOW_LEN, "%"PRIi32, *u);
}

static void opt_show_mode(char buf[OPT_SHOW_LEN], const mode_t *m)
{
	snprintf(buf, OPT_SHOW_LEN, "\"%04o\"", (int) *m);
}

static char *opt_set_rgb(const char *arg, struct lightningd *ld)
{
	assert(arg != NULL);

	ld->rgb = tal_free(ld->rgb);
	/* BOLT #7:
	 *
	 *    - Note: the first byte of `rgb_color` is the red value, the second
	 *      byte is the green value, and the last byte is the blue value.
	 */
	ld->rgb = tal_hexdata(ld, arg, strlen(arg));
	if (!ld->rgb || tal_count(ld->rgb) != 3)
		return tal_fmt(NULL, "rgb '%s' is not six hex digits", arg);
	return NULL;
}

static char *opt_set_alias(const char *arg, struct lightningd *ld)
{
	assert(arg != NULL);

	ld->alias = tal_free(ld->alias);
	/* BOLT #7:
	 *
	 *    * [`32*byte`:`alias`]
	 *...
	 *  - MUST set `alias` to a valid UTF-8 string, with any
	 *   `alias` trailing-bytes equal to 0.
	 */
	if (strlen(arg) > 32)
		return tal_fmt(NULL, "Alias '%s' is over 32 characters", arg);
	ld->alias = tal_arrz(ld, u8, 33);
	strncpy((char*)ld->alias, arg, 32);
	return NULL;
}

static char *opt_set_offline(struct lightningd *ld)
{
	ld->reconnect = false;
	ld->listen = false;

	return NULL;
}

static char *opt_add_proxy_addr(const char *arg, struct lightningd *ld)
{
	bool needed_dns = false;
	tal_free(ld->proxyaddr);

	/* We use a tal_arr here, so we can marshal it to gossipd */
	ld->proxyaddr = tal_arr(ld, struct wireaddr, 1);

	if (!parse_wireaddr(arg, ld->proxyaddr, 9050,
			    ld->always_use_proxy ? &needed_dns : NULL,
			    NULL)) {
		return tal_fmt(NULL, "Unable to parse Tor proxy address '%s' %s",
			       arg, needed_dns ? " (needed dns)" : "");
	}
	return NULL;
}

static char *opt_add_plugin(const char *arg, struct lightningd *ld)
{
	if (plugin_blacklisted(ld->plugins, arg)) {
		log_info(ld->log, "%s: disabled via disable-plugin", arg);
		return NULL;
	}
	plugin_register(ld->plugins, arg, NULL, false, NULL, NULL);
	return NULL;
}

static char *opt_disable_plugin(const char *arg, struct lightningd *ld)
{
	plugin_blacklist(ld->plugins, arg);
	return NULL;
}

static char *opt_add_plugin_dir(const char *arg, struct lightningd *ld)
{
	return add_plugin_dir(ld->plugins, arg, false);
}

static char *opt_clear_plugins(struct lightningd *ld)
{
	clear_plugins(ld->plugins);
	return NULL;
}

static char *opt_important_plugin(const char *arg, struct lightningd *ld)
{
	if (plugin_blacklisted(ld->plugins, arg)) {
		log_info(ld->log, "%s: disabled via disable-plugin", arg);
		return NULL;
	}
	plugin_register(ld->plugins, arg, NULL, true, NULL, NULL);
	return NULL;
}

/* Prompt the user to enter a password, from which will be derived the key used
 * for `hsm_secret` encryption.
 * The algorithm used to derive the key is Argon2(id), to which libsodium
 * defaults. However argon2id-specific constants are used in case someone runs it
 * with a libsodium version which default constants differs (typically <1.0.9).
 */
static char *opt_set_hsm_password(struct lightningd *ld)
{
	char *passwd, *passwd_confirmation, *err_msg;

	printf("The hsm_secret is encrypted with a password. In order to "
	       "decrypt it and start the node you must provide the password.\n");
	printf("Enter hsm_secret password:\n");
	/* If we don't flush we might end up being buffered and we might seem
	 * to hang while we wait for the password. */
	fflush(stdout);

	passwd = read_stdin_pass_with_exit_code(&err_msg, &opt_exitcode);
	if (!passwd)
		return err_msg;
	printf("Confirm hsm_secret password:\n");
	fflush(stdout);
	passwd_confirmation = read_stdin_pass_with_exit_code(&err_msg, &opt_exitcode);
	if (!passwd_confirmation)
		return err_msg;
	printf("\n");

	ld->config.keypass = tal(NULL, struct secret);

	opt_exitcode = hsm_secret_encryption_key_with_exitcode(passwd, ld->config.keypass, &err_msg);
	if (opt_exitcode > 0)
		return err_msg;

	ld->encrypted_hsm = true;
	free(passwd);
	free(passwd_confirmation);

	return NULL;
}

#if DEVELOPER
static char *opt_subprocess_debug(const char *optarg, struct lightningd *ld)
{
	ld->dev_debug_subprocess = optarg;
	return NULL;
}

static char *opt_force_privkey(const char *optarg, struct lightningd *ld)
{
	tal_free(ld->dev_force_privkey);
	ld->dev_force_privkey = tal(ld, struct privkey);
	if (!hex_decode(optarg, strlen(optarg),
			ld->dev_force_privkey, sizeof(*ld->dev_force_privkey)))
		return tal_fmt(NULL, "Unable to parse privkey '%s'", optarg);
	return NULL;
}

static char *opt_force_bip32_seed(const char *optarg, struct lightningd *ld)
{
	tal_free(ld->dev_force_bip32_seed);
	ld->dev_force_bip32_seed = tal(ld, struct secret);
	if (!hex_decode(optarg, strlen(optarg),
			ld->dev_force_bip32_seed,
			sizeof(*ld->dev_force_bip32_seed)))
		return tal_fmt(NULL, "Unable to parse secret '%s'", optarg);
	return NULL;
}

static char *opt_force_tmp_channel_id(const char *optarg, struct lightningd *ld)
{
	tal_free(ld->dev_force_tmp_channel_id);
	ld->dev_force_tmp_channel_id = tal(ld, struct channel_id);
	if (!hex_decode(optarg, strlen(optarg),
			ld->dev_force_tmp_channel_id,
			sizeof(*ld->dev_force_tmp_channel_id)))
		return tal_fmt(NULL, "Unable to parse channel id '%s'", optarg);
	return NULL;
}

static char *opt_force_channel_secrets(const char *optarg,
				       struct lightningd *ld)
{
	char **strs;
	tal_free(ld->dev_force_channel_secrets);
	tal_free(ld->dev_force_channel_secrets_shaseed);
	ld->dev_force_channel_secrets = tal(ld, struct secrets);
	ld->dev_force_channel_secrets_shaseed = tal(ld, struct sha256);

	strs = tal_strsplit(tmpctx, optarg, "/", STR_EMPTY_OK);
	if (tal_count(strs) != 7) /* Last is NULL */
		return "Expected 6 hex secrets separated by /";

	if (!hex_decode(strs[0], strlen(strs[0]),
			&ld->dev_force_channel_secrets->funding_privkey,
			sizeof(ld->dev_force_channel_secrets->funding_privkey))
	    || !hex_decode(strs[1], strlen(strs[1]),
			   &ld->dev_force_channel_secrets->revocation_basepoint_secret,
			   sizeof(ld->dev_force_channel_secrets->revocation_basepoint_secret))
	    || !hex_decode(strs[2], strlen(strs[2]),
			   &ld->dev_force_channel_secrets->payment_basepoint_secret,
			   sizeof(ld->dev_force_channel_secrets->payment_basepoint_secret))
	    || !hex_decode(strs[3], strlen(strs[3]),
			   &ld->dev_force_channel_secrets->delayed_payment_basepoint_secret,
			   sizeof(ld->dev_force_channel_secrets->delayed_payment_basepoint_secret))
	    || !hex_decode(strs[4], strlen(strs[4]),
			   &ld->dev_force_channel_secrets->htlc_basepoint_secret,
			   sizeof(ld->dev_force_channel_secrets->htlc_basepoint_secret))
	    || !hex_decode(strs[5], strlen(strs[5]),
			   ld->dev_force_channel_secrets_shaseed,
			   sizeof(*ld->dev_force_channel_secrets_shaseed)))
		return "Expected 6 hex secrets separated by /";

	return NULL;
}

static char *opt_force_featureset(const char *optarg,
				  struct lightningd *ld)
{
	char **parts = tal_strsplit(tmpctx, optarg, "/", STR_EMPTY_OK);
	if (tal_count(parts) != NUM_FEATURE_PLACE) {
		if (!strstarts(optarg, "-") && !strstarts(optarg, "+"))
			return "Expected 5 feature sets (init, globalinit,"
			       " node_announce, channel, bolt11) separated"
			       " by / OR +/-<feature_num>";

		char *endp;
		long int n = strtol(optarg + 1, &endp, 10);
		const struct feature_set *f;
		if (*endp || endp == optarg + 1)
			return "Invalid feature number";

		f = feature_set_for_feature(NULL, n);
		if (strstarts(optarg, "-")
		    && !feature_set_sub(ld->our_features, take(f)))
			return "Feature unknown";

		if (strstarts(optarg, "+")
		    && !feature_set_or(ld->our_features, take(f)))
			return "Feature already flagged-on";

		return NULL;
	}
	for (size_t i = 0; parts[i]; i++) {
		char **bits = tal_strsplit(tmpctx, parts[i], ",", STR_EMPTY_OK);
		tal_resize(&ld->our_features->bits[i], 0);

		for (size_t j = 0; bits[j]; j++) {
			char *endp;
			long int n = strtol(bits[j], &endp, 10);
			if (*endp || endp == bits[j])
				return "Invalid bitnumber";
			set_feature_bit(&ld->our_features->bits[i], n);
		}
	}
	return NULL;
}

static void dev_register_opts(struct lightningd *ld)
{
	/* We might want to debug plugins, which are started before normal
	 * option parsing */
	opt_register_early_arg("--dev-debugger=<subprocess>", opt_subprocess_debug, NULL,
			 ld, "Invoke gdb at start of <subprocess>");

	opt_register_early_noarg("--dev-no-plugin-checksum", opt_set_bool,
				 &ld->dev_no_plugin_checksum,
				 "Don't checksum plugins to detect changes");

	opt_register_noarg("--dev-no-reconnect", opt_set_invbool,
			   &ld->reconnect,
			   "Disable automatic reconnect-attempts by this node, but accept incoming");
	opt_register_noarg("--dev-fail-on-subdaemon-fail", opt_set_bool,
			   &ld->dev_subdaemon_fail, opt_hidden);
	opt_register_arg("--dev-disconnect=<filename>", opt_subd_dev_disconnect,
			 NULL, ld, "File containing disconnection points");
	opt_register_noarg("--dev-allow-localhost", opt_set_bool,
			   &ld->dev_allow_localhost,
			   "Announce and allow announcments for localhost address");
	opt_register_arg("--dev-bitcoind-poll", opt_set_u32, opt_show_u32,
			 &ld->topology->poll_seconds,
			 "Time between polling for new transactions");

	opt_register_noarg("--dev-fast-gossip", opt_set_bool,
			   &ld->dev_fast_gossip,
			   "Make gossip broadcast 1 second, etc");
	opt_register_noarg("--dev-fast-gossip-prune", opt_set_bool,
			   &ld->dev_fast_gossip_prune,
			   "Make gossip pruning 30 seconds");

	opt_register_arg("--dev-gossip-time", opt_set_u32, opt_show_u32,
			 &ld->dev_gossip_time,
			 "UNIX time to override gossipd to use.");
	opt_register_arg("--dev-force-privkey", opt_force_privkey, NULL, ld,
			 "Force HSM to use this as node private key");
	opt_register_arg("--dev-force-bip32-seed", opt_force_bip32_seed, NULL, ld,
			 "Force HSM to use this as bip32 seed");
	opt_register_arg("--dev-force-channel-secrets", opt_force_channel_secrets, NULL, ld,
			 "Force HSM to use these for all per-channel secrets");
	opt_register_arg("--dev-max-funding-unconfirmed-blocks",
			 opt_set_u32, opt_show_u32,
			 &ld->dev_max_funding_unconfirmed,
			 "Maximum number of blocks we wait for a channel "
			 "funding transaction to confirm, if we are the "
			 "fundee.");
	opt_register_arg("--dev-force-tmp-channel-id", opt_force_tmp_channel_id, NULL, ld,
			 "Force the temporary channel id, instead of random");
	opt_register_noarg("--dev-no-htlc-timeout", opt_set_bool,
			   &ld->dev_no_htlc_timeout,
			   "Don't kill channeld if HTLCs not confirmed within 30 seconds");
	opt_register_noarg("--dev-fail-process-onionpacket", opt_set_bool,
			   &dev_fail_process_onionpacket,
			   "Force all processing of onion packets to fail");
	opt_register_noarg("--dev-no-version-checks", opt_set_bool,
			   &ld->dev_no_version_checks,
			   "Skip calling subdaemons with --version on startup");
	opt_register_early_noarg("--dev-builtin-plugins-unimportant",
				 opt_set_bool,
				 &ld->plugins->dev_builtin_plugins_unimportant,
				 "Make builtin plugins unimportant so you can plugin stop them.");
	opt_register_arg("--dev-force-features", opt_force_featureset, NULL, ld,
			 "Force the init/globalinit/node_announce/channel/bolt11 features, each comma-separated bitnumbers");
	opt_register_arg("--dev-timeout-secs", opt_set_u32, opt_show_u32,
			 &ld->config.connection_timeout_secs,
			 "Seconds to timeout if we don't receive INIT from peer");
	opt_register_noarg("--dev-no-modern-onion", opt_set_bool,
			   &ld->dev_ignore_modern_onion,
			   "Ignore modern onion messages");
	opt_register_noarg("--dev-no-obsolete-onion", opt_set_bool,
			   &ld->dev_ignore_obsolete_onion,
			   "Ignore obsolete onion messages");
	opt_register_arg("--dev-disable-commit-after",
			 opt_set_intval, opt_show_intval,
			 &ld->dev_disable_commit,
			 "Disable commit timer after this many commits");
}
#endif /* DEVELOPER */

static const struct config testnet_config = {
	/* 6 blocks to catch cheating attempts. */
	.locktime_blocks = 6,

	/* They can have up to 14 days, maximumu value that lnd will ask for by default. */
	/* FIXME Convince lnd to use more reasonable defaults... */
	.locktime_max = 14 * 24 * 6,

	/* We're fairly trusting, under normal circumstances. */
	.anchor_confirms = 1,

	/* Testnet blockspace is free. */
	.max_concurrent_htlcs = 483,

	/* Max amount of dust allowed per channel (50ksat) */
	.max_dust_htlc_exposure_msat = AMOUNT_MSAT(50000000),

	/* Be aggressive on testnet. */
	.cltv_expiry_delta = 6,
	.cltv_final = 10,

	/* Send commit 10msec after receiving; almost immediately. */
	.commit_time_ms = 10,

	/* Allow dust payments */
	.fee_base = 1,
	/* Take 0.001% */
	.fee_per_satoshi = 10,

	/* Testnet sucks */
	.ignore_fee_limits = true,

	/* Rescan 5 hours of blocks on testnet, it's reorg happy */
	.rescan = 30,

	.use_dns = true,

	/* Sets min_effective_htlc_capacity - at 1000$/BTC this is 10ct */
	.min_capacity_sat = 10000,

	.use_v3_autotor = true,

	/* 1 minute should be enough for anyone! */
	.connection_timeout_secs = 60,

	.exp_offers = IFEXPERIMENTAL(true, false),
};

/* aka. "Dude, where's my coins?" */
static const struct config mainnet_config = {
	/* ~one day to catch cheating attempts. */
	.locktime_blocks = 6 * 24,

	/* They can have up to 14 days, maximumu value that lnd will ask for by default. */
	/* FIXME Convince lnd to use more reasonable defaults... */
	.locktime_max = 14 * 24 * 6,

	/* We're fairly trusting, under normal circumstances. */
	.anchor_confirms = 3,

	/* While up to 483 htlcs are possible we do 30 by default (as eclair does) to save blockspace */
	.max_concurrent_htlcs = 30,

	/* Max amount of dust allowed per channel (50ksat) */
	.max_dust_htlc_exposure_msat = AMOUNT_MSAT(50000000),

	/* BOLT #2:
	 *
	 * 1. the `cltv_expiry_delta` for channels, `3R+2G+2S`: if in doubt, a
	 *   `cltv_expiry_delta` of at least 34 is reasonable (R=2, G=2, S=12)
	 */
	/* R = 2, G = 2, S = 12 */
	.cltv_expiry_delta = 34,

	/* BOLT #2:
	 *
	 * 4. the minimum `cltv_expiry` accepted for terminal payments: the
	 *    worst case for the terminal node C is `2R+G+S` blocks */
	.cltv_final = 18,

	/* Send commit 10msec after receiving; almost immediately. */
	.commit_time_ms = 10,

	/* Discourage dust payments */
	.fee_base = 1000,
	/* Take 0.001% */
	.fee_per_satoshi = 10,

	/* Mainnet should have more stable fees */
	.ignore_fee_limits = false,

	/* Rescan 2.5 hours of blocks on startup, it's not so reorg happy */
	.rescan = 15,

	.use_dns = true,

	/* Sets min_effective_htlc_capacity - at 1000$/BTC this is 10ct */
	.min_capacity_sat = 10000,

	/* Allow to define the default behavior of tor services calls*/
	.use_v3_autotor = true,

	/* 1 minute should be enough for anyone! */
	.connection_timeout_secs = 60,

	.exp_offers = IFEXPERIMENTAL(true, false),
};

static void check_config(struct lightningd *ld)
{
	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *   - `max_accepted_htlcs` is greater than 483.
	 */
	if (ld->config.max_concurrent_htlcs < 1 || ld->config.max_concurrent_htlcs > 483)
		fatal("--max-concurrent-htlcs value must be between 1 and 483 it is: %u",
		      ld->config.max_concurrent_htlcs);
	if (ld->config.anchor_confirms == 0)
		fatal("anchor-confirms must be greater than zero");

	if (ld->always_use_proxy && !ld->proxyaddr)
		fatal("--always-use-proxy needs --proxy");

	if (ld->daemon_parent_fd != -1 && !ld->logfile)
		fatal("--daemon needs --log-file");
}

static char *test_subdaemons_and_exit(struct lightningd *ld)
{
	test_subdaemons(ld);
	exit(0);
	return NULL;
}

static char *list_features_and_exit(struct lightningd *ld)
{
	const char **features = list_supported_features(tmpctx, ld->our_features);
	for (size_t i = 0; i < tal_count(features); i++)
		printf("%s\n", features[i]);
#if EXPERIMENTAL_FEATURES
	printf("supports_open_accept_channel_type\n");
#endif
	exit(0);
}

static char *opt_lightningd_usage(struct lightningd *ld)
{
	char *extra = tal_fmt(NULL, "\nA bitcoin lightning daemon (default "
			"values shown for network: %s).", chainparams->network_name);
	opt_usage_and_exit(extra);
	tal_free(extra);
	return NULL;
}

static char *opt_start_daemon(struct lightningd *ld)
{
	int fds[2];
	int exitcode, pid;

	/* Already a daemon?  OK. */
	if (ld->daemon_parent_fd != -1)
		return NULL;

	if (pipe(fds) != 0)
		err(1, "Creating pipe to talk to --daemon");

	pid = fork();
	if (pid == -1)
		err(1, "Fork failed for --daemon");

	if (pid == 0) {
		/* Child returns, continues as normal. */
		close(fds[0]);
		ld->daemon_parent_fd = fds[1];
		return NULL;
	}

	/* OK, we are the parent.  We exit with status told to us by
	 * child. */
	close(fds[1]);
	if (read(fds[0], &exitcode, sizeof(exitcode)) == sizeof(exitcode))
		_exit(exitcode);
	/* It died before writing exitcode (presumably 0), so we grab it */
	waitpid(pid, &exitcode, 0);
	if (WIFEXITED(exitcode))
		_exit(WEXITSTATUS(exitcode));
	errx(1, "Died with signal %u", WTERMSIG(exitcode));
}

static char *opt_set_msat(const char *arg, struct amount_msat *amt)
{
	if (!parse_amount_msat(amt, arg, strlen(arg)))
		return tal_fmt(NULL, "Unable to parse millisatoshi '%s'", arg);

	return NULL;
}

static char *opt_set_wumbo(struct lightningd *ld)
{
	feature_set_or(ld->our_features,
		       take(feature_set_for_feature(NULL,
						    OPTIONAL_FEATURE(OPT_LARGE_CHANNELS))));
	return NULL;
}

static char *opt_set_websocket_port(const char *arg, struct lightningd *ld)
{
	u32 port COMPILER_WANTS_INIT("9.3.0 -O2");
	char *err;

	err = opt_set_u32(arg, &port);
	if (err)
		return err;

	ld->websocket_port = port;
	if (ld->websocket_port != port)
		return tal_fmt(NULL, "'%s' is out of range", arg);
	return NULL;
}

static char *opt_set_dual_fund(struct lightningd *ld)
{
	/* Dual funding implies anchor outputs */
	feature_set_or(ld->our_features,
		       take(feature_set_for_feature(NULL,
						    OPTIONAL_FEATURE(OPT_ANCHOR_OUTPUTS))));
	feature_set_or(ld->our_features,
		       take(feature_set_for_feature(NULL,
						    OPTIONAL_FEATURE(OPT_DUAL_FUND))));
	return NULL;
}

static char *opt_set_onion_messages(struct lightningd *ld)
{
	feature_set_or(ld->our_features,
		       take(feature_set_for_feature(NULL,
						    OPTIONAL_FEATURE(OPT_ONION_MESSAGES))));
	return NULL;
}

static char *opt_set_shutdown_wrong_funding(struct lightningd *ld)
{
	feature_set_or(ld->our_features,
		       take(feature_set_for_feature(NULL,
						    OPTIONAL_FEATURE(OPT_SHUTDOWN_WRONG_FUNDING))));
	return NULL;
}

static char *opt_set_offers(struct lightningd *ld)
{
	ld->config.exp_offers = true;
	return opt_set_onion_messages(ld);
}

static void register_opts(struct lightningd *ld)
{
	/* This happens before plugins started */
	opt_register_early_noarg("--test-daemons-only",
				 test_subdaemons_and_exit,
				 ld, opt_hidden);
	/* Register plugins as an early args, so we can initialize them and have
	 * them register more command line options */
	opt_register_early_arg("--plugin", opt_add_plugin, NULL, ld,
			       "Add a plugin to be run (can be used multiple times)");
	opt_register_early_arg("--plugin-dir", opt_add_plugin_dir,
			       NULL, ld,
			       "Add a directory to load plugins from (can be used multiple times)");
	opt_register_early_noarg("--clear-plugins", opt_clear_plugins,
				 ld,
				 "Remove all plugins added before this option");
	opt_register_early_arg("--disable-plugin", opt_disable_plugin,
			       NULL, ld,
			       "Disable a particular plugin by filename/name");

	opt_register_early_arg("--important-plugin", opt_important_plugin,
			       NULL, ld,
			       "Add an important plugin to be run (can be used multiple times). Die if the plugin dies.");

	/* Early, as it suppresses DNS lookups from cmdline too. */
	opt_register_early_arg("--always-use-proxy",
			       opt_set_bool_arg, opt_show_bool,
			       &ld->always_use_proxy, "Use the proxy always");

	/* This immediately makes is a daemon. */
	opt_register_early_noarg("--daemon", opt_start_daemon, ld,
				 "Run in the background, suppress stdout/stderr");
	opt_register_early_arg("--wallet", opt_set_talstr, NULL,
			       &ld->wallet_dsn,
			       "Location of the wallet database.");

	/* This affects our features, so set early. */
	opt_register_early_noarg("--large-channels|--wumbo",
				 opt_set_wumbo, ld,
				 "Allow channels larger than 0.16777215 BTC");

	opt_register_early_noarg("--experimental-dual-fund",
				 opt_set_dual_fund, ld,
				 "experimental: Advertise dual-funding"
				 " and allow peers to establish channels"
				 " via v2 channel open protocol.");

	/* This affects our features, so set early. */
	opt_register_early_noarg("--experimental-onion-messages",
				 opt_set_onion_messages, ld,
				 "EXPERIMENTAL: enable send, receive and relay"
				 " of onion messages");
	opt_register_early_noarg("--experimental-offers",
				 opt_set_offers, ld,
				 "EXPERIMENTAL: enable send and receive of offers"
				 " (also sets experimental-onion-messages)");
	opt_register_early_noarg("--experimental-shutdown-wrong-funding",
				 opt_set_shutdown_wrong_funding, ld,
				 "EXPERIMENTAL: allow shutdown with alternate txids");

	opt_register_noarg("--help|-h", opt_lightningd_usage, ld,
				 "Print this message.");
	opt_register_arg("--rgb", opt_set_rgb, NULL, ld,
			 "RRGGBB hex color for node");
	opt_register_arg("--alias", opt_set_alias, NULL, ld,
			 "Up to 32-byte alias for node");

	opt_register_arg("--pid-file=<file>", opt_set_talstr, opt_show_charp,
			 &ld->pidfile,
			 "Specify pid file");

	opt_register_arg("--ignore-fee-limits", opt_set_bool_arg, opt_show_bool,
			 &ld->config.ignore_fee_limits,
			 "(DANGEROUS) allow peer to set any feerate");
	opt_register_arg("--watchtime-blocks", opt_set_u32, opt_show_u32,
			 &ld->config.locktime_blocks,
			 "Blocks before peer can unilaterally spend funds");
	opt_register_arg("--max-locktime-blocks", opt_set_u32, opt_show_u32,
			 &ld->config.locktime_max,
			 "Maximum blocks funds may be locked for");
	opt_register_arg("--funding-confirms", opt_set_u32, opt_show_u32,
			 &ld->config.anchor_confirms,
			 "Confirmations required for funding transaction");
	opt_register_arg("--cltv-delta", opt_set_u32, opt_show_u32,
			 &ld->config.cltv_expiry_delta,
			 "Number of blocks for cltv_expiry_delta");
	opt_register_arg("--cltv-final", opt_set_u32, opt_show_u32,
			 &ld->config.cltv_final,
			 "Number of blocks for final cltv_expiry");
	opt_register_arg("--commit-time=<millseconds>",
			 opt_set_u32, opt_show_u32,
			 &ld->config.commit_time_ms,
			 "Time after changes before sending out COMMIT");
	opt_register_arg("--fee-base", opt_set_u32, opt_show_u32,
			 &ld->config.fee_base,
			 "Millisatoshi minimum to charge for HTLC");
	opt_register_arg("--rescan", opt_set_s32, opt_show_s32,
			 &ld->config.rescan,
			 "Number of blocks to rescan from the current head, or "
			 "absolute blockheight if negative");
	opt_register_arg("--fee-per-satoshi", opt_set_u32, opt_show_u32,
			 &ld->config.fee_per_satoshi,
			 "Microsatoshi fee for every satoshi in HTLC");
	opt_register_arg("--max-concurrent-htlcs", opt_set_u32, opt_show_u32,
			 &ld->config.max_concurrent_htlcs,
			 "Number of HTLCs one channel can handle concurrently. Should be between 1 and 483");
	opt_register_arg("--max-dust-htlc-exposure-msat", opt_set_msat,
			 NULL, &ld->config.max_dust_htlc_exposure_msat,
			 "Max HTLC amount that can be trimmed");
	opt_register_arg("--min-capacity-sat", opt_set_u64, opt_show_u64,
			 &ld->config.min_capacity_sat,
			 "Minimum capacity in satoshis for accepting channels");
	opt_register_arg("--addr", opt_add_addr, NULL,
			 ld,
			 "Set an IP address (v4 or v6) to listen on and announce to the network for incoming connections");
	opt_register_arg("--bind-addr", opt_add_bind_addr, NULL,
			 ld,
			 "Set an IP address (v4 or v6) to listen on, but not announce");
	opt_register_arg("--announce-addr", opt_add_announce_addr, NULL,
			 ld,
			 "Set an IP address (v4 or v6) or .onion v3 to announce, but not listen on");

	opt_register_noarg("--offline", opt_set_offline, ld,
			   "Start in offline-mode (do not automatically reconnect and do not accept incoming connections)");
	opt_register_arg("--autolisten", opt_set_bool_arg, opt_show_bool,
			 &ld->autolisten,
			 "If true, listen on default port and announce if it seems to be a public interface");

	opt_register_arg("--proxy", opt_add_proxy_addr, NULL,
			ld,"Set a socks v5 proxy IP address and port");
	opt_register_arg("--tor-service-password", opt_set_talstr, NULL,
			 &ld->tor_service_password,
			 "Set a Tor hidden service password");

#if EXPERIMENTAL_FEATURES
	opt_register_arg("--experimental-accept-extra-tlv-types",
			 opt_set_accept_extra_tlv_types, NULL, ld,
			 "Comma separated list of extra TLV types to accept.");
#endif

	opt_register_early_noarg("--disable-dns", opt_set_invbool, &ld->config.use_dns,
				 "Disable DNS lookups of peers");

	if (deprecated_apis)
		opt_register_noarg("--enable-autotor-v2-mode", opt_set_invbool, &ld->config.use_v3_autotor,
				   opt_hidden);

	opt_register_noarg("--encrypted-hsm", opt_set_hsm_password, ld,
					  "Set the password to encrypt hsm_secret with. If no password is passed through command line, "
					  "you will be prompted to enter it.");

	opt_register_arg("--rpc-file-mode", &opt_set_mode, &opt_show_mode,
			 &ld->rpc_filemode,
			 "Set the file mode (permissions) for the "
			 "JSON-RPC socket");

	opt_register_arg("--force-feerates",
			 opt_force_feerates, NULL, ld,
			 "Set testnet/regtest feerates in sats perkw, opening/mutual_close/unlateral_close/delayed_to_us/htlc_resolution/penalty: if fewer specified, last number applies to remainder");

	opt_register_arg("--subdaemon", opt_subdaemon, NULL,
			 ld, "Arg specified as SUBDAEMON:PATH. "
			 "Specifies an alternate subdaemon binary. "
			 "If the supplied path is relative the subdaemon "
			 "binary is found in the working directory. "
			 "This option may be specified multiple times. "
			 "For example, "
			 "--subdaemon=hsmd:remote_signer "
			 "would use a hypothetical remote signing subdaemon.");

	opt_register_arg("--experimental-websocket-port",
			 opt_set_websocket_port, NULL,
			 ld,
			 "experimental: alternate port for peers to connect"
			 " using WebSockets (RFC6455)");
	opt_register_logging(ld);
	opt_register_version();

#if DEVELOPER
	dev_register_opts(ld);
#endif
}

/* We are in ld->config_netdir when this is run! */
static void promote_missing_files(struct lightningd *ld)
{
#ifdef COMPAT_V073
	DIR *d_from;
	struct dirent *d;
	struct stat st;

	/* If hsm_secret already exists, we assume we're ugpraded */
	if (stat("hsm_secret", &st) == 0)
		return;

	if (errno != ENOENT)
		err(1, "Looking for hsm_secret in lightning dir");

	/* If hsm doesn't exist in basedir, we've nothing to upgrade. */
	if (stat(path_join(tmpctx, ld->config_basedir, "hsm_secret"), &st) != 0)
		return;

	d_from = opendir(ld->config_basedir);
	if (!d_from)
		err(1, "Opening %s", ld->config_basedir);

	while ((d = readdir(d_from)) != NULL) {
		const char *fullname;

		/* Ignore this directory and upper one, and leave
		 * config and pid files */
		if (streq(d->d_name, ".")
		    || streq(d->d_name, "..")
		    || streq(d->d_name, "config")
		    || strends(d->d_name, ".pid"))
			continue;

		fullname = path_join(tmpctx, ld->config_basedir, d->d_name);

		/* Simply remove rpc file: if they use --rpc-file to place it
		 * here explicitly it will get recreated, but moving it would
		 * be confusing as it would be unused. */
		if (streq(d->d_name, "lightning-rpc")) {
			if (unlink(fullname) != 0)
				log_unusual(ld->log, "Could not unlink %s: %s",
					    fullname, strerror(errno));
			continue;
		}

		/* Ignore any directories. */
		if (lstat(fullname, &st) != 0)
			errx(1, "Could not stat %s", fullname);
		if ((st.st_mode & S_IFMT) == S_IFDIR)
			continue;

		/* Check we don't overwrite something in this dir! */
		if (lstat(d->d_name, &st) != -1)
			errx(1, "Refusing to overwrite %s into %s/",
			     fullname, ld->config_netdir);
		log_unusual(ld->log, "Moving %s into %s/",
			    d->d_name, ld->config_netdir);
		if (rename(fullname, d->d_name) != 0)
			err(1, "Could not move %s/%s to %s",
			    ld->config_basedir, d->d_name, ld->config_netdir);
	}
	closedir(d_from);
#endif /* COMPAT_V073 */
}

/* Names stolen from https://github.com/ternus/nsaproductgenerator/blob/master/nsa.js */
static const char *codename_adjective[]
= { "LOUD", "RED", "BLUE", "GREEN", "YELLOW", "IRATE", "ANGRY", "PEEVED",
    "HAPPY", "SLIMY", "SLEEPY", "JUNIOR", "SLICKER", "UNITED", "SOMBER",
    "BIZARRE", "ODD", "WEIRD", "WRONG", "LATENT", "CHILLY", "STRANGE", "LOUD",
    "SILENT", "HOPPING", "ORANGE", "VIOLET", "VIOLENT", "LIGHTNING" };

static const char *codename_noun[]
= { "WHISPER", "FELONY", "MOON", "SUCKER", "PENGUIN", "WAFFLE", "MAESTRO",
    "NIGHT", "TRINITY", "DEITY", "MONKEY", "ARK", "SQUIRREL", "IRON", "BOUNCE",
    "FARM", "CHEF", "TROUGH", "NET", "TRAWL", "GLEE", "WATER", "SPORK", "PLOW",
    "FEED", "SOUFFLE", "ROUTE", "BAGEL", "MONTANA", "ANALYST", "AUTO", "WATCH",
    "PHOTO", "YARD", "SOURCE", "MONKEY", "SEAGULL", "TOLL", "SPAWN", "GOPHER",
    "CHIPMUNK", "SET", "CALENDAR", "ARTIST", "CHASER", "SCAN", "TOTE", "BEAM",
    "ENTOURAGE", "GENESIS", "WALK", "SPATULA", "RAGE", "FIRE", "MASTER" };

void setup_color_and_alias(struct lightningd *ld)
{
	if (!ld->rgb)
		/* You can't get much red by default */
		ld->rgb = tal_dup_arr(ld, u8, ld->id.k, 3, 0);

	if (!ld->alias) {
		u64 adjective, noun;
		char *name;

		memcpy(&adjective, ld->id.k+3, sizeof(adjective));
		memcpy(&noun, ld->id.k+3+sizeof(adjective), sizeof(noun));
		noun %= ARRAY_SIZE(codename_noun);
		adjective %= ARRAY_SIZE(codename_adjective);

		/* Only use 32 characters */
		name = tal_fmt(ld, "%s%s",
			       codename_adjective[adjective],
			       codename_noun[noun]);
#if DEVELOPER
		assert(strlen(name) < 32);
		int taillen = 31 - strlen(name);
		if (taillen > strlen(version()))
			taillen = strlen(version());
		/* Fit as much of end of version() as possible */
		tal_append_fmt(&name, "-%s",
			       version() + strlen(version()) - taillen);
#endif
		assert(strlen(name) <= 32);
		ld->alias = tal_arrz(ld, u8, 33);
		strcpy((char*)ld->alias, name);
		tal_free(name);
	}
}

void handle_early_opts(struct lightningd *ld, int argc, char *argv[])
{
	/* Make ccan/opt use tal for allocations */
	setup_option_allocators();

	/*~ List features immediately, before doing anything interesting */
	opt_register_early_noarg("--list-features-only",
				 list_features_and_exit,
				 ld, opt_hidden);

	/*~ This does enough parsing to get us the base configuration options */
	initial_config_opts(ld, argc, argv,
			    &ld->config_filename,
			    &ld->config_basedir,
			    &ld->config_netdir,
			    &ld->rpc_filename);

	/* Copy in default config, to be modified by further options */
	if (chainparams->testnet)
		ld->config = testnet_config;
	else
		ld->config = mainnet_config;

	/* Now we can initialize wallet_dsn */
	ld->wallet_dsn = tal_fmt(ld, "sqlite3://%s/lightningd.sqlite3",
				 ld->config_netdir);

	/* Set default PID file name to be per-network (in base dir) */
	ld->pidfile = path_join(ld, ld->config_basedir,
				tal_fmt(tmpctx, "lightningd-%s.pid",
					chainparams->network_name));

	/*~ Move into config dir: this eases path manipulation and also
	 * gives plugins a good place to store their stuff. */
	if (chdir(ld->config_netdir) != 0) {
		log_info(ld->log, "Creating configuration directory %s",
			    ld->config_netdir);
		/* We assume home dir exists, so only create two. */
		if (mkdir(ld->config_basedir, 0700) != 0 && errno != EEXIST)
			fatal("Could not make directory %s: %s",
			      ld->config_basedir,
			      strerror(errno));
		if (mkdir(ld->config_netdir, 0700) != 0)
			fatal("Could not make directory %s: %s",
			      ld->config_netdir, strerror(errno));
		if (chdir(ld->config_netdir) != 0)
			fatal("Could not change directory %s: %s",
			      ld->config_netdir, strerror(errno));
	}

	/*~ We move files from old locations on first upgrade. */
	promote_missing_files(ld);

	/*~ The ccan/opt code requires registration then parsing; we
	 *  mimic this API here, even though they're on separate lines.*/
	register_opts(ld);

	/* Now look inside config file(s), but only handle the early
	 * options (testnet, plugins etc), others may be added on-demand */
	parse_config_files(ld->config_filename, ld->config_basedir, true);

	/* Early cmdline options now override config file options. */
	opt_early_parse_incomplete(argc, argv, opt_log_stderr_exit);

	/* Finalize the logging subsystem now. */
	logging_options_parsed(ld->log_book);
}

void handle_opts(struct lightningd *ld, int argc, char *argv[])
{
	/* Now look for config file, but only handle non-early
	 * options, early ones have been parsed in
	 * handle_early_opts */
	parse_config_files(ld->config_filename, ld->config_basedir, false);

	/* Now parse cmdline, which overrides config. */
	opt_parse(&argc, argv, opt_log_stderr_exitcode);
	if (argc != 1)
		errx(1, "no arguments accepted");
	/* We keep a separate variable rather than overriding always_use_proxy,
	 * so listconfigs shows the correct thing. */
	if (tal_count(ld->proposed_wireaddr) != 0
	    && all_tor_addresses(ld->proposed_wireaddr)) {
		ld->pure_tor_setup = true;
		if (!ld->proxyaddr)
			log_info(ld->log, "Pure Tor setup with no --proxy:"
				 " you won't be able to make connections out");
	}
	check_config(ld);
}

/* FIXME: This is a hack!  Expose somehow in ccan/opt.*/
/* Returns string after first '-'. */
static const char *first_name(const char *names, unsigned *len)
{
	*len = strcspn(names + 1, "|= ");
	return names + 1;
}

static const char *next_name(const char *names, unsigned *len)
{
	names += *len;
	if (names[0] == ' ' || names[0] == '=' || names[0] == '\0')
		return NULL;
	return first_name(names + 1, len);
}

static void json_add_opt_addrs(struct json_stream *response,
			       const char *name0,
			       const struct wireaddr_internal *wireaddrs,
			       const enum addr_listen_announce *listen_announce,
			       enum addr_listen_announce ala)
{
	for (size_t i = 0; i < tal_count(wireaddrs); i++) {
		if (listen_announce[i] != ala)
			continue;
		json_add_string(response,
				name0,
				fmt_wireaddr_internal(name0, wireaddrs+i));
	}
}

struct json_add_opt_alt_subdaemon_args {
	const char *name0;
	struct json_stream *response;
};

static bool json_add_opt_alt_subdaemon(const char *member,
				       const char *value,
				       struct json_add_opt_alt_subdaemon_args *argp)
{
	json_add_string(argp->response,
			argp->name0,
			tal_fmt(argp->name0, "%s:%s", member, value));
	return true;
}

static void json_add_opt_subdaemons(struct json_stream *response,
				    const char *name0,
				    alt_subdaemon_map *alt_subdaemons)
{
	struct json_add_opt_alt_subdaemon_args args;
	args.name0 = name0;
	args.response = response;
	strmap_iterate(alt_subdaemons, json_add_opt_alt_subdaemon, &args);
}

static void add_config(struct lightningd *ld,
		       struct json_stream *response,
		       const struct opt_table *opt,
		       const char *name, size_t len)
{
	char *name0 = tal_strndup(tmpctx, name, len);
	const char *answer = NULL;
	char buf[OPT_SHOW_LEN + sizeof("...")];

#if DEVELOPER
	if (strstarts(name0, "dev-")) {
		/* Ignore dev settings */
		return;
	}
#endif

	if (opt->type & OPT_NOARG) {
		if (opt->desc == opt_hidden) {
			/* Ignore hidden options (deprecated) */
		} else if (opt->cb == (void *)opt_usage_and_exit
		    || opt->cb == (void *)version_and_exit
		    || is_restricted_ignored(opt->cb)
		    || opt->cb == (void *)opt_lightningd_usage
		    || opt->cb == (void *)test_subdaemons_and_exit
		    /* FIXME: we can't recover this. */
		    || opt->cb == (void *)opt_clear_plugins) {
			/* These are not important */
		} else if (opt->cb == (void *)opt_set_bool) {
			const bool *b = opt->u.carg;
			json_add_bool(response, name0, *b);
		} else if (opt->cb == (void *)opt_set_invbool) {
			const bool *b = opt->u.carg;
			json_add_bool(response, name0, !*b);
		} else if (opt->cb == (void *)opt_set_offline) {
			json_add_bool(response, name0,
				      !ld->reconnect && !ld->listen);
		} else if (opt->cb == (void *)opt_start_daemon) {
			json_add_bool(response, name0,
				      ld->daemon_parent_fd != -1);
		} else if (opt->cb == (void *)opt_set_hsm_password) {
			json_add_bool(response, "encrypted-hsm", ld->encrypted_hsm);
		} else if (opt->cb == (void *)opt_set_wumbo) {
			json_add_bool(response, name0,
				      feature_offered(ld->our_features
						      ->bits[INIT_FEATURE],
						      OPT_LARGE_CHANNELS));
		} else if (opt->cb == (void *)opt_set_dual_fund) {
			json_add_bool(response, name0,
				      feature_offered(ld->our_features
						      ->bits[INIT_FEATURE],
						      OPT_DUAL_FUND));
		} else if (opt->cb == (void *)opt_set_onion_messages) {
			json_add_bool(response, name0,
				      feature_offered(ld->our_features
						      ->bits[INIT_FEATURE],
						      OPT_ONION_MESSAGES));
		} else if (opt->cb == (void *)opt_set_offers) {
			json_add_bool(response, name0, ld->config.exp_offers);
		} else if (opt->cb == (void *)opt_set_shutdown_wrong_funding) {
			json_add_bool(response, name0,
				      feature_offered(ld->our_features
						      ->bits[INIT_FEATURE],
						      OPT_SHUTDOWN_WRONG_FUNDING));
		} else if (opt->cb == (void *)plugin_opt_flag_set) {
			/* Noop, they will get added below along with the
			 * OPT_HASARG options. */
		} else {
			/* Insert more decodes here! */
			assert(!"A noarg option was added but was not handled");
		}
	} else if (opt->type & OPT_HASARG) {
		if (opt->desc == opt_hidden) {
			/* Ignore hidden options (deprecated) */
		} else if (opt->show) {
			strcpy(buf + OPT_SHOW_LEN, "...");
			opt->show(buf, opt->u.carg);

			if (streq(buf, "true") || streq(buf, "false")
			    || strspn(buf, "0123456789.") == strlen(buf)) {
				/* Let pure numbers and true/false through as
				 * literals. */
				json_add_literal(response, name0,
						 buf, strlen(buf));
				return;
			}

			/* opt_show_charp surrounds with "", strip them */
			if (strstarts(buf, "\"")) {
				char *end = strrchr(buf, '"');
				memmove(end, end + 1, strlen(end));
				answer = buf + 1;
			} else
				answer = buf;
		} else if (opt->cb_arg == (void *)opt_set_talstr
			   || opt->cb_arg == (void *)opt_set_charp
			   || is_restricted_print_if_nonnull(opt->cb_arg)) {
			const char *arg = *(char **)opt->u.carg;
			if (arg)
				answer = tal_fmt(name0, "%s", arg);
		} else if (opt->cb_arg == (void *)opt_set_rgb) {
			if (ld->rgb)
				answer = tal_hexstr(name0, ld->rgb, 3);
		} else if (opt->cb_arg == (void *)opt_set_alias) {
			answer = (const char *)ld->alias;
		} else if (opt->cb_arg == (void *)arg_log_to_file) {
			answer = ld->logfile;
		} else if (opt->cb_arg == (void *)opt_add_addr) {
			json_add_opt_addrs(response, name0,
					   ld->proposed_wireaddr,
					   ld->proposed_listen_announce,
					   ADDR_LISTEN_AND_ANNOUNCE);
			return;
		} else if (opt->cb_arg == (void *)opt_add_bind_addr) {
			json_add_opt_addrs(response, name0,
					   ld->proposed_wireaddr,
					   ld->proposed_listen_announce,
					   ADDR_LISTEN);
			return;
		} else if (opt->cb_arg == (void *)opt_add_announce_addr) {
			json_add_opt_addrs(response, name0,
					   ld->proposed_wireaddr,
					   ld->proposed_listen_announce,
					   ADDR_ANNOUNCE);
			return;
		} else if (opt->cb_arg == (void *)opt_subdaemon) {
			json_add_opt_subdaemons(response, name0,
						    &ld->alt_subdaemons);
			return;
		} else if (opt->cb_arg == (void *)opt_add_proxy_addr) {
			if (ld->proxyaddr)
				answer = fmt_wireaddr(name0, ld->proxyaddr);
		} else if (opt->cb_arg == (void *)opt_add_plugin) {
			json_add_opt_plugins(response, ld->plugins);
		} else if (opt->cb_arg == (void *)opt_log_level) {
			json_add_opt_log_levels(response, ld->log);
		} else if (opt->cb_arg == (void *)opt_disable_plugin) {
			json_add_opt_disable_plugins(response, ld->plugins);
		} else if (opt->cb_arg == (void *)opt_force_feerates) {
			answer = fmt_force_feerates(name0, ld->force_feerates);
		} else if (opt->cb_arg == (void *)opt_set_websocket_port) {
			if (ld->websocket_port)
				json_add_u32(response, name0,
					     ld->websocket_port);
			return;
		} else if (opt->cb_arg == (void *)opt_important_plugin) {
			/* Do nothing, this is already handled by
			 * opt_add_plugin.  */
		} else if (opt->cb_arg == (void *)opt_add_plugin_dir
			   || opt->cb_arg == (void *)plugin_opt_set
			   || opt->cb_arg == (void *)plugin_opt_flag_set) {
			/* FIXME: We actually treat it as if they specified
			 * --plugin for each one, so ignore these */
		} else if (opt->cb_arg == (void *)opt_set_msat) {
			json_add_amount_msat_only(response, name0, ld->config.max_dust_htlc_exposure_msat);
#if EXPERIMENTAL_FEATURES
		} else if (opt->cb_arg == (void *)opt_set_accept_extra_tlv_types) {
                        /* TODO Actually print the option */
#endif
#if DEVELOPER
		} else if (strstarts(name, "dev-")) {
			/* Ignore dev settings */
#endif
		} else {
			/* Insert more decodes here! */
			abort();
		}
	}

	if (answer) {
		struct json_escape *esc = json_escape(NULL, answer);
		json_add_escaped_string(response, name0, take(esc));
	}
}

static struct command_result *json_listconfigs(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	size_t i;
	struct json_stream *response = NULL;
	const jsmntok_t *configtok;

	if (!param(cmd, buffer, params,
		   p_opt("config", param_tok, &configtok),
		   NULL))
		return command_param_failed();

	if (!configtok) {
		response = json_stream_success(cmd);
		json_add_string(response, "# version", version());
	}

	for (i = 0; i < opt_count; i++) {
		unsigned int len;
		const char *name;

		/* FIXME: Print out comment somehow? */
		if (opt_table[i].type == OPT_SUBTABLE)
			continue;

		for (name = first_name(opt_table[i].names, &len);
		     name;
		     name = next_name(name, &len)) {
			/* Skips over first -, so just need to look for one */
			if (name[0] != '-')
				continue;

			if (configtok
			    && !memeq(buffer + configtok->start,
				      configtok->end - configtok->start,
				      name + 1, len - 1))
				continue;

			if (!response)
				response = json_stream_success(cmd);
			add_config(cmd->ld, response, &opt_table[i],
				   name+1, len-1);
			/* If we have more than one long name, first
			 * is preferred */
			break;
		}
	}

	if (configtok && !response) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Unknown config option '%.*s'",
				    json_tok_full_len(configtok),
				    json_tok_full(buffer, configtok));
	}
	return command_success(cmd, response);
}

static const struct json_command listconfigs_command = {
	"listconfigs",
	"utility",
	json_listconfigs,
	"List all configuration options, or with [config], just that one.",
	.verbose = "listconfigs [config]\n"
	"Outputs an object, with each field a config options\n"
	"(Option names which start with # are comments)\n"
	"With [config], object only has that field"
};
AUTODATA(json_command, &listconfigs_command);
