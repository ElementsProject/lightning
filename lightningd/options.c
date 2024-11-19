#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/opt/opt.h>
#include <ccan/opt/private.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/codex32.h>
#include <common/configdir.h>
#include <common/configvar.h>
#include <common/features.h>
#include <common/hsm_encryption.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/version.h>
#include <common/wireaddr.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/chaintopology.h>
#include <lightningd/hsm_control.h>
#include <lightningd/options.h>
#include <lightningd/plugin.h>
#include <lightningd/subd.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* FIXME: Put into ccan/time. */
#define TIME_FROM_SEC(sec) { { .tv_nsec = 0, .tv_sec = sec } }
#define TIME_FROM_MSEC(msec) \
	{ { .tv_nsec = ((msec) % 1000) * 1000000, .tv_sec = (msec) / 1000 } }

/* issue is NULL, or what the issue is with the argname */
static bool opt_deprecated_ok(struct lightningd *ld,
			      const char *argname,
			      const char *issue,
			      const char *start,
			      const char *end)
{
	return lightningd_deprecated_in_ok(ld, ld->log,
					   ld->deprecated_ok,
					   argname, issue,
					   start, end, NULL);
}

static char *opt_set_u64(const char *arg, u64 *u)
{
	char *endp;
	unsigned long long l;

	assert(arg != NULL);

	/* This is how the manpage says to do it.  Yech. */
	errno = 0;
	l = strtoull(arg, &endp, 0);
	if (*endp || !arg[0])
		return tal_fmt(tmpctx, "'%s' is not a number", arg);
	*u = l;
	if (errno || *u != l)
		return tal_fmt(tmpctx, "'%s' is out of range", arg);
	return NULL;
}

static char *opt_set_u64_dynamic(const char *arg, u64 *u)
{
	u64 ignored;

	/* In case we're called for arg checking only */
	if (!u)
		u = &ignored;

	return opt_set_u64(arg, u);
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
		return tal_fmt(tmpctx, "'%s' is not a number", arg);
	*u = l;
	if (errno || *u != l)
		return tal_fmt(tmpctx, "'%s' is out of range", arg);
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
		return tal_fmt(tmpctx, "'%s' is not a number", arg);
	*u = l;
	if (errno || *u != l)
		return tal_fmt(tmpctx, "'%s' is out of range", arg);
	return NULL;
}

char *opt_set_autobool_arg(const char *arg, enum opt_autobool *b)
{
	if (!strcasecmp(arg, "yes") ||
	    !strcasecmp(arg, "true")) {
		*b = OPT_AUTOBOOL_TRUE;
		return NULL;
	}
	if (!strcasecmp(arg, "no") ||
	    !strcasecmp(arg, "false")) {
		*b = OPT_AUTOBOOL_FALSE;
		return NULL;
	}
	if (!strcasecmp(arg, "auto") ||
	    !strcasecmp(arg, "default")) {
		*b = OPT_AUTOBOOL_AUTO;
		return NULL;
	}
	return opt_invalid_argument(arg);
}

bool opt_show_autobool(char *buf, size_t len, const enum opt_autobool *b)
{
	switch (*b) {
	case OPT_AUTOBOOL_TRUE:
		strncpy(buf, "true", len);
		return true;
	case OPT_AUTOBOOL_FALSE:
		strncpy(buf, "false", len);
		return true;
	case OPT_AUTOBOOL_AUTO:
		strncpy(buf, "auto", len);
		return true;
	}
	abort();
}

static char *opt_set_mode(const char *arg, mode_t *m)
{
	char *endp;
	long l;

	assert(arg != NULL);

	/* Ensure length, and starts with 0.  */
	if (strlen(arg) != 4 || arg[0] != '0')
		return tal_fmt(tmpctx, "'%s' is not a file mode", arg);

	/* strtol, manpage, yech.  */
	errno = 0;
	l = strtol(arg, &endp, 8); /* Octal.  */
	if (errno || *endp)
		return tal_fmt(tmpctx, "'%s' is not a file mode", arg);
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

static char *opt_add_accept_htlc_tlv(const char *arg,
				     u64 **accept_extra_tlv_types)
{
	size_t n = tal_count(*accept_extra_tlv_types);

	tal_resize(accept_extra_tlv_types, n+1);
	return opt_set_u64(arg, &(*accept_extra_tlv_types)[n]);
}

static char *opt_set_accept_extra_tlv_types(const char *arg,
					    struct lightningd *ld)
{
	char *ret, **elements = tal_strsplit(tmpctx, arg, ",", STR_NO_EMPTY);

	if (!opt_deprecated_ok(ld, "accept-htlc-tlv-types", NULL,
			       "v23.08", "v24.08")) {
		return "Please use --accept-htlc-tlv-type multiple times";
	}
	for (int i = 0; elements[i] != NULL; i++) {
		ret = opt_add_accept_htlc_tlv(elements[i],
					      &ld->accept_extra_tlv_types);
		if (ret)
			return ret;
	}
	return NULL;
}

/* Returns the number of wireaddr types already announced */
static size_t num_announced_types(enum wire_addr_type type, struct lightningd *ld)
{
	size_t num = 0;
	for (size_t i = 0; i < tal_count(ld->proposed_wireaddr); i++) {
		if (ld->proposed_wireaddr[i].itype != ADDR_INTERNAL_WIREADDR)
			continue;
		if (ld->proposed_wireaddr[i].u.wireaddr.wireaddr.type != type)
			continue;
		if (ld->proposed_listen_announce[i] & ADDR_ANNOUNCE)
			num++;
	}
	return num;
}

static char *opt_add_addr_withtype(const char *arg,
				   struct lightningd *ld,
				   enum addr_listen_announce ala)
{
	char const *err_msg;
	struct wireaddr_internal wi;
	bool dns_lookup_ok;
	char *address;
	u16 port;

	assert(arg != NULL);
	dns_lookup_ok = !ld->always_use_proxy && ld->config.use_dns;

	/* Deprecated announce-addr-dns: autodetect DNS addresses. */
	if (ld->announce_dns && (ala == ADDR_ANNOUNCE)
	    && separate_address_and_port(tmpctx, arg, &address, &port)
	    && is_dnsaddr(address)) {
		log_unusual(ld->log, "Adding dns prefix to %s!", arg);
		arg = tal_fmt(tmpctx, "dns:%s", arg);
	}

	err_msg = parse_wireaddr_internal(tmpctx, arg, ld->portnum,
					  dns_lookup_ok, &wi);
	if (err_msg)
		return tal_fmt(tmpctx, "Unable to parse address '%s': %s", arg, err_msg);

	/* Check they didn't specify some weird type! */
	switch (wi.itype) {
	case ADDR_INTERNAL_WIREADDR:
		switch (wi.u.wireaddr.wireaddr.type) {
		case ADDR_TYPE_IPV4:
		case ADDR_TYPE_IPV6:
			if ((ala & ADDR_ANNOUNCE) && wi.u.allproto.is_websocket)
				return tal_fmt(tmpctx,
					       "Cannot announce websocket address, use --bind-addr=%s", arg);
			/* These can be either bind or announce */
			break;
		case ADDR_TYPE_TOR_V2_REMOVED:
			/* Can't happen any more */
			abort();
		case ADDR_TYPE_TOR_V3:
			switch (ala) {
			case ADDR_LISTEN:
				if (!opt_deprecated_ok(ld, "bind-addr", "torv3",
						       "v23.08", "v24.08"))
					return tal_fmt(tmpctx,
						       "Don't use --bind-addr=%s, use --announce-addr=%s",
						       arg, arg);
				log_unusual(ld->log,
					    "You used `--bind-addr=%s` option with an .onion address,"
					    " You are lucky in this node live some wizards and"
					    " fairies, we have done this for you and don't announce, Be as hidden as wished",
					    arg);
				/* And we ignore it */
				return NULL;
			case ADDR_LISTEN_AND_ANNOUNCE:
				if (!opt_deprecated_ok(ld, "addr", "torv3",
						       "v23.08", "v24.08"))
					return tal_fmt(tmpctx,
						       "Don't use --addr=%s, use --announce-addr=%s",
						       arg, arg);
				log_unusual(ld->log,
					    "You used `--addr=%s` option with an .onion address,"
					    " You are lucky in this node live some wizards and"
					    " fairies, we have done this for you and don't announce, Be as hidden as wished",
					    arg);
				ala = ADDR_LISTEN;
				break;
			case ADDR_ANNOUNCE:
				break;
			}
			break;
		case ADDR_TYPE_DNS:
			/* Can only announce this */
			switch (ala) {
			case ADDR_ANNOUNCE:
				break;
			case ADDR_LISTEN:
				return tal_fmt(tmpctx,
					       "Cannot use dns: prefix with --bind-addr, use --bind-addr=%s", arg + strlen("dns:"));
			case ADDR_LISTEN_AND_ANNOUNCE:
				return tal_fmt(tmpctx,
					       "Cannot use dns: prefix with --addr, use --bind-addr=%s and --addr=%s",
					       arg + strlen("dns:"),
					       arg);
			}
			/* BOLT #7:
			 * The origin node:
			 * ...
			 *   - MUST NOT announce more than one `type 5` DNS hostname.
			 */
			if (num_announced_types(ADDR_TYPE_DNS, ld) > 0)
				return tal_fmt(tmpctx, "Only one DNS can be announced");
			break;
		}
		break;
	case ADDR_INTERNAL_SOCKNAME:
		switch (ala) {
			case ADDR_ANNOUNCE:
				return tal_fmt(tmpctx,
					       "Cannot announce sockets, try --bind-addr=%s", arg);
			case ADDR_LISTEN_AND_ANNOUNCE:
				if (!opt_deprecated_ok(ld, "addr", "socket",
						       "v23.08", "v24.08"))
					return tal_fmt(tmpctx, "Don't use --addr=%s, use --bind-addr=%s",
						       arg, arg);
				ala = ADDR_LISTEN;
				/* Fall thru */
			case ADDR_LISTEN:
				break;
			}
		break;
	case ADDR_INTERNAL_AUTOTOR:
	case ADDR_INTERNAL_STATICTOR:
		/* We turn --announce-addr into --addr */
		switch (ala) {
			case ADDR_ANNOUNCE:
				ala = ADDR_LISTEN_AND_ANNOUNCE;
				break;
			case ADDR_LISTEN_AND_ANNOUNCE:
			case ADDR_LISTEN:
				break;
		}
		break;
	case ADDR_INTERNAL_ALLPROTO:
		/* You can only bind to wildcard, and optionally announce */
		switch (ala) {
			case ADDR_ANNOUNCE:
				return tal_fmt(tmpctx, "Cannot use wildcard address '%s'", arg);
			case ADDR_LISTEN_AND_ANNOUNCE:
				if (wi.u.allproto.is_websocket)
				return tal_fmt(tmpctx,
					       "Cannot announce websocket address, use --bind-addr=%s", arg);
				/* fall thru */
			case ADDR_LISTEN:
				break;
		}
		break;
	case ADDR_INTERNAL_FORPROXY:
		/* You can't use these addresses here at all: this means we've
		 * suppressed DNS and given a string-style name */
		return tal_fmt(tmpctx, "Cannot resolve address '%s' (not using DNS!)", arg);
	}

	/* Sanity check for exact duplicates. */
	for (size_t i = 0; i < tal_count(ld->proposed_wireaddr); i++) {
		/* Only compare announce vs announce and bind vs bind */
		if ((ld->proposed_listen_announce[i] & ala) == 0)
			continue;

		if (wireaddr_internal_eq(&ld->proposed_wireaddr[i], &wi))
			return tal_fmt(tmpctx, "Duplicate %s address %s",
				       ala & ADDR_ANNOUNCE ? "announce" : "listen",
				       fmt_wireaddr_internal(tmpctx, &wi));
	}

	tal_arr_expand(&ld->proposed_listen_announce, ala);
	tal_arr_expand(&ld->proposed_wireaddr, wi);
	return NULL;

}

static char *opt_add_announce_addr(const char *arg, struct lightningd *ld)
{
	return opt_add_addr_withtype(arg, ld, ADDR_ANNOUNCE);
}

static char *opt_add_addr(const char *arg, struct lightningd *ld)
{
	return opt_add_addr_withtype(arg, ld, ADDR_LISTEN_AND_ANNOUNCE);
}

static char *opt_add_bind_addr(const char *arg, struct lightningd *ld)
{
	return opt_add_addr_withtype(arg, ld, ADDR_LISTEN);
}

static char *opt_subdaemon(const char *arg, struct lightningd *ld)
{
	char *subdaemon;
	char *sdpath;

	/* example arg: "hsmd:remote_hsmd" */

	size_t colonoff = strcspn(arg, ":");
	if (!arg[colonoff])
		return tal_fmt(tmpctx, "argument must contain ':'");

	subdaemon = tal_strndup(ld, arg, colonoff);
	if (!is_subdaemon(subdaemon))
		return tal_fmt(tmpctx, "\"%s\" is not a subdaemon", subdaemon);

	/* Make the value a tal-child of the subdaemon */
	sdpath = tal_strdup(subdaemon, arg + colonoff + 1);

	/* Remove any preexisting alt subdaemon mapping (and
	 * implicitly, the sdpath). */
	tal_free(strmap_del(&ld->alt_subdaemons, subdaemon, NULL));

	strmap_add(&ld->alt_subdaemons, subdaemon, sdpath);

	return NULL;
}

static bool opt_show_u64(char *buf, size_t len, const u64 *u)
{
	snprintf(buf, len, "%"PRIu64, *u);
	return true;
}
static bool opt_show_u32(char *buf, size_t len, const u32 *u)
{
	snprintf(buf, len, "%"PRIu32, *u);
	return true;
}

static bool opt_show_s32(char *buf, size_t len, const s32 *u)
{
	snprintf(buf, len, "%"PRIi32, *u);
	return true;
}

static bool opt_show_mode(char *buf, size_t len, const mode_t *m)
{
	snprintf(buf, len, "%04o", (int) *m);
	return true;
}

static bool opt_show_rgb(char *buf, size_t len, const struct lightningd *ld)
{
	/* Can happen with -h! */
	if (!ld->rgb)
		return false;
	/* This is always set; if not by arg, then by default */
	hex_encode(ld->rgb, 3, buf, len);
	return true;
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
		return tal_fmt(tmpctx, "rgb '%s' is not six hex digits", arg);
	return NULL;
}

static bool opt_show_alias(char *buf, size_t len, const struct lightningd *ld)
{
	/* Can happen with -h! */
	if (!ld->alias)
		return false;

	strncpy(buf, cast_signed(const char *, ld->alias), len);
	return true;
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
		return tal_fmt(tmpctx, "Alias '%s' is over 32 characters", arg);
	ld->alias = tal_arrz(ld, u8, 33);
	strncpy((char*)ld->alias, arg, 32);
	return NULL;
}

static char *opt_set_offline(struct lightningd *ld)
{
	ld->reconnect = false;
	ld->listen = false;
	log_info(ld->log, "Started in offline mode!");
	return NULL;
}

static char *opt_add_proxy_addr(const char *arg, struct lightningd *ld)
{
	bool needed_dns = false;
	const char *err;

	tal_free(ld->proxyaddr);

	/* We use a tal_arr here, so we can marshal it to gossipd */
	ld->proxyaddr = tal_arr(ld, struct wireaddr, 1);

	err = parse_wireaddr(tmpctx, arg, 9050,
			     ld->always_use_proxy ? &needed_dns : NULL,
			     ld->proxyaddr);
	return cast_const(char *, err);
}

static char *opt_add_plugin(const char *arg, struct lightningd *ld)
{
	struct plugin *p;
	if (plugin_blacklisted(ld->plugins, arg)) {
		log_info(ld->log, "%s: disabled via disable-plugin", arg);
		return NULL;
	}
	p = plugin_register(ld->plugins, arg, NULL, false, NULL, NULL);
	if (!p)
		return tal_fmt(tmpctx, "Failed to register %s: %s", arg, strerror(errno));
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

	/* Remove from configvars too! */
	for (size_t i = 0; i < tal_count(ld->configvars); i++) {
		if (streq(ld->configvars[i]->optvar, "plugin")
		    || streq(ld->configvars[i]->optvar, "plugin-dir"))
			ld->configvars[i]->overridden = true;
	}
	return NULL;
}

static char *opt_important_plugin(const char *arg, struct lightningd *ld)
{
	struct plugin *p;
	if (plugin_blacklisted(ld->plugins, arg)) {
		log_info(ld->log, "%s: disabled via disable-plugin", arg);
		return NULL;
	}
	p = plugin_register(ld->plugins, arg, NULL, true, NULL, NULL);
	if (!p)
		return tal_fmt(tmpctx, "Failed to register %s: %s", arg, strerror(errno));
	return NULL;
}

/* Test code looks in logs, so we print prompts to log as well as stdout */
static void prompt(struct lightningd *ld, const char *str)
{
	printf("%s\n", str);
	log_debug(ld->log, "PROMPT: %s", str);
	/* If we don't flush we might end up being buffered and we might seem
	 * to hang while we wait for the password. */
	fflush(stdout);
}

/* Prompt the user to enter a password, from which will be derived the key used
 * for `hsm_secret` encryption.
 * The algorithm used to derive the key is Argon2(id), to which libsodium
 * defaults. However argon2id-specific constants are used in case someone runs it
 * with a libsodium version which default constants differs (typically <1.0.9).
 */
static char *opt_set_hsm_password(struct lightningd *ld)
{
	char *passwd, *passwd_confirmation;
	const char *err_msg;
	int is_encrypted;

        is_encrypted = is_hsm_secret_encrypted("hsm_secret");
	/* While lightningd is performing the first initialization
	 * this check is always true because the file does not exist.
	 *
	 * Maybe the is_hsm_secret_encrypted is performing a not useful
	 * check at this stage, but the hsm is a delicate part,
	 * so it is a good information to have inside the log. */
	if (is_encrypted == -1)
		log_info(ld->log, "'hsm_secret' does not exist (%s)",
			 strerror(errno));

	prompt(ld, "The hsm_secret is encrypted with a password. In order to "
	       "decrypt it and start the node you must provide the password.");
	prompt(ld, "Enter hsm_secret password:");

	passwd = read_stdin_pass_with_exit_code(&err_msg, &opt_exitcode);
	if (!passwd)
		return cast_const(char *, err_msg);
	if (!is_encrypted) {
		prompt(ld, "Confirm hsm_secret password:");
		fflush(stdout);
		passwd_confirmation = read_stdin_pass_with_exit_code(&err_msg, &opt_exitcode);
		if (!passwd_confirmation)
			return cast_const(char *, err_msg);

		if (!streq(passwd, passwd_confirmation)) {
			opt_exitcode = EXITCODE_HSM_BAD_PASSWORD;
			return "Passwords confirmation mismatch.";
		}
		free(passwd_confirmation);
	}
	prompt(ld, "");

	ld->config.keypass = tal(NULL, struct secret);

	opt_exitcode = hsm_secret_encryption_key_with_exitcode(passwd, ld->config.keypass, &err_msg);
	if (opt_exitcode > 0)
		return cast_const(char *, err_msg);

	ld->encrypted_hsm = true;
	free(passwd);

	return NULL;
}

static char *opt_set_max_htlc_cltv(const char *arg, struct lightningd *ld)
{
	if (!opt_deprecated_ok(ld, "max-locktime-blocks", NULL,
			       "v24.05", "v24.11"))
		return "--max-locktime-blocks has been deprecated (BOLT #4 says 2016)";

	return opt_set_u32(arg, &ld->config.max_htlc_cltv);
}

static char *opt_force_privkey(const char *optarg, struct lightningd *ld)
{
	tal_free(ld->dev_force_privkey);
	ld->dev_force_privkey = tal(ld, struct privkey);
	if (!hex_decode(optarg, strlen(optarg),
			ld->dev_force_privkey, sizeof(*ld->dev_force_privkey)))
		return tal_fmt(tmpctx, "Unable to parse privkey '%s'", optarg);
	return NULL;
}

static char *opt_force_bip32_seed(const char *optarg, struct lightningd *ld)
{
	tal_free(ld->dev_force_bip32_seed);
	ld->dev_force_bip32_seed = tal(ld, struct secret);
	if (!hex_decode(optarg, strlen(optarg),
			ld->dev_force_bip32_seed,
			sizeof(*ld->dev_force_bip32_seed)))
		return tal_fmt(tmpctx, "Unable to parse secret '%s'", optarg);
	return NULL;
}

static char *opt_force_tmp_channel_id(const char *optarg, struct lightningd *ld)
{
	tal_free(ld->dev_force_tmp_channel_id);
	ld->dev_force_tmp_channel_id = tal(ld, struct channel_id);
	if (!hex_decode(optarg, strlen(optarg),
			ld->dev_force_tmp_channel_id,
			sizeof(*ld->dev_force_tmp_channel_id)))
		return tal_fmt(tmpctx, "Unable to parse channel id '%s'", optarg);
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
	if (tal_count(parts) != NUM_FEATURE_PLACE + 1) {
		if (!strstarts(optarg, "-") && !strstarts(optarg, "+"))
			return "Expected 8 feature sets (init/globalinit/"
			       " node_announce/channel/bolt11/b12offer/b12invreq/b12inv) each terminated by /"
			       " OR +/-<single_bit_num>";

		char *endp;
		long int n = strtol(optarg + 1, &endp, 10);
		const struct feature_set *f;
		if (*endp || endp == optarg + 1)
			return "Invalid feature number";

		f = feature_set_for_feature(NULL, n);
		if (strstarts(optarg, "-")) {
			feature_set_sub(ld->our_features, take(f));
		}

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

static char *opt_ignore(void *unused)
{
	return NULL;
}

static void dev_register_opts(struct lightningd *ld)
{
	/* We might want to debug plugins, which are started before normal
	 * option parsing */
	clnopt_witharg("--dev-debugger=<subprocess>", OPT_EARLY|OPT_DEV,
		       opt_set_charp, opt_show_charp,
		       &ld->dev_debug_subprocess,
		       "Invoke gdb at start of <subprocess>");
	clnopt_noarg("--dev-no-plugin-checksum", OPT_EARLY|OPT_DEV,
		     opt_set_bool,
		     &ld->dev_no_plugin_checksum,
		     "Don't checksum plugins to detect changes");
	clnopt_noarg("--dev-builtin-plugins-unimportant", OPT_EARLY|OPT_DEV,
		     opt_set_bool,
		     &ld->plugins->dev_builtin_plugins_unimportant,
		     "Make builtin plugins unimportant so you can plugin stop them.");
	clnopt_noarg("--dev-no-reconnect", OPT_DEV,
		     opt_set_invbool,
		     &ld->reconnect,
		     "Disable automatic reconnect-attempts by this node, but accept incoming");
	clnopt_noarg("--dev-no-reconnect-private", OPT_DEV,
		     opt_set_invbool,
		     &ld->reconnect_private,
		     "Disable automatic reconnect-attempts to peers with private channel(s) only, but accept incoming");
	clnopt_noarg("--dev-fast-reconnect", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_fast_reconnect,
		     "Make max default reconnect delay 3 (not 300) seconds");

	clnopt_noarg("--dev-fail-on-subdaemon-fail", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_subdaemon_fail, opt_hidden);
	clnopt_witharg("--dev-disconnect=<filename>", OPT_DEV,
		       opt_subd_dev_disconnect,
		       NULL, ld, "File containing disconnection points");
	clnopt_noarg("--dev-allow-localhost", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_allow_localhost,
		     "Announce and allow announcments for localhost address");
	clnopt_witharg("--dev-bitcoind-poll", OPT_DEV|OPT_SHOWINT,
		       opt_set_u32, opt_show_u32,
		       &ld->topology->poll_seconds,
		       "Time between polling for new transactions");
	clnopt_noarg("--dev-fast-gossip", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_fast_gossip,
		     "Make gossip broadcast 1 second, etc");
	clnopt_noarg("--dev-fast-gossip-prune", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_fast_gossip_prune,
		     "Make gossip pruning 120 seconds");
	clnopt_witharg("--dev-gossip-time", OPT_DEV|OPT_SHOWINT,
		       opt_set_u32, opt_show_u32,
		       &ld->dev_gossip_time,
		       "UNIX time to override gossipd to use.");
	clnopt_witharg("--dev-force-privkey", OPT_DEV,
		       opt_force_privkey, NULL, ld,
		       "Force HSM to use this as node private key");
	clnopt_witharg("--dev-force-bip32-seed", OPT_DEV,
		       opt_force_bip32_seed, NULL, ld,
		       "Force HSM to use this as bip32 seed");
	clnopt_witharg("--dev-force-channel-secrets", OPT_DEV,
		       opt_force_channel_secrets, NULL, ld,
		       "Force HSM to use these for all per-channel secrets");
	clnopt_witharg("--dev-max-funding-unconfirmed-blocks",
		       OPT_DEV|OPT_SHOWINT,
		       opt_set_u32, opt_show_u32,
		       &ld->dev_max_funding_unconfirmed,
		       "Maximum number of blocks we wait for a channel "
		       "funding transaction to confirm, if we are the "
		       "fundee.");
	clnopt_witharg("--dev-force-tmp-channel-id", OPT_DEV,
		       opt_force_tmp_channel_id, NULL, ld,
		       "Force the temporary channel id, instead of random");
	clnopt_noarg("--dev-no-htlc-timeout", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_no_htlc_timeout,
		     "Don't kill channeld if HTLCs not confirmed within 30 seconds");
	clnopt_noarg("--dev-fail-process-onionpacket", OPT_DEV,
		     opt_set_bool,
		     &dev_fail_process_onionpacket,
		     "Force all processing of onion packets to fail");
	clnopt_noarg("--dev-no-version-checks", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_no_version_checks,
		     "Skip calling subdaemons with --version on startup");
	clnopt_witharg("--dev-force-features", OPT_DEV,
		       opt_force_featureset, NULL, ld,
		       "Force the init/globalinit/node_announce/channel/bolt11/ features, each comma-separated bitnumbers OR a single +/-<bitnumber>");
	clnopt_witharg("--dev-timeout-secs", OPT_DEV|OPT_SHOWINT,
		       opt_set_u32, opt_show_u32,
		       &ld->config.connection_timeout_secs,
		       "Seconds to timeout if we don't receive INIT from peer");
	clnopt_noarg("--dev-no-modern-onion", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_ignore_modern_onion,
		     "Ignore modern onion messages");
	clnopt_witharg("--dev-disable-commit-after", OPT_DEV|OPT_SHOWINT,
		       opt_set_intval, opt_show_intval,
		       &ld->dev_disable_commit,
		       "Disable commit timer after this many commits");
	clnopt_noarg("--dev-no-ping-timer", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_no_ping_timer,
		     "Don't hang up if we don't get a ping response");
	clnopt_witharg("--dev-onion-reply-length", OPT_DEV|OPT_SHOWINT,
		       opt_set_uintval,
		       opt_show_uintval,
		       &dev_onion_reply_length,
		       "Send onion errors of custom length");
	clnopt_witharg("--dev-max-fee-multiplier", OPT_DEV|OPT_SHOWINT,
		       opt_set_uintval,
		       opt_show_uintval,
		       &ld->config.max_fee_multiplier,
		       "Allow the fee proposed by the remote end to"
		       " be up to multiplier times higher than our "
		       "own. Small values will cause channels to be"
		       " closed more often due to fee fluctuations,"
		       " large values may result in large fees.");
	clnopt_witharg("--dev-allowdustreserve", OPT_DEV|OPT_SHOWBOOL,
		       opt_set_bool_arg, opt_show_bool,
		       &ld->config.allowdustreserve,
		       "If true, we allow the `fundchannel` RPC command and the `openchannel` plugin hook to set a reserve that is below the dust limit.");
	clnopt_noarg("--dev-any-channel-type", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_any_channel_type,
		     "Allow sending any channel type, and accept any");
	clnopt_noarg("--dev-allow-shutdown-destination-change", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_allow_shutdown_destination_change,
		     "Allow destination override on close, even if risky");
	clnopt_noarg("--dev-hsmd-no-preapprove-check", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_hsmd_no_preapprove_check,
		     "Tell hsmd not to support preapprove_check msgs");
	clnopt_noarg("--dev-hsmd-fail-preapprove", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_hsmd_fail_preapprove,
		     "Tell hsmd to always deny preapprove_invoice / preapprove_keysend");
	clnopt_witharg("--dev-fd-limit-multiplier", OPT_DEV|OPT_SHOWINT,
		       opt_set_u32, opt_show_u32,
		       &ld->fd_limit_multiplier,
		       "Try to set fd limit to this many times by number of channels (default: 2)");
	clnopt_noarg("--dev-handshake-no-reply", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_handshake_no_reply,
		     "Don't send or read init message after connection");
	clnopt_noarg("--dev-strict-forwarding", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_strict_forwarding,
		     "Forward HTLCs along the channel specified");
	clnopt_noarg("--dev-throttle-gossip", OPT_DEV,
		     opt_set_bool,
		     &ld->dev_throttle_gossip,
		     "Throttle gossip right down, for testing");
	/* This is handled directly in daemon_developer_mode(), so we ignore it here */
	clnopt_noarg("--dev-debug-self", OPT_DEV,
		     opt_ignore,
		     NULL,
		     "Fire up a terminal window with a debugger in it on initialization");
}

static const struct config testnet_config = {
	/* 6 blocks to catch cheating attempts. */
	.locktime_blocks = 6,

	/* BOLT #4:
	 * ## `max_htlc_cltv` Selection
	 *
	 * This ... value is defined as 2016 blocks, based on historical value
	 * deployed by Lightning implementations.
	 */
	/* FIXME: Typo in spec for CLTV in descripton!  But it breaks our spelling check, so we omit it above */
	.max_htlc_cltv = 2016,

	/* We're fairly trusting, under normal circumstances. */
	.anchor_confirms = 1,

	/* Testnet blockspace is free. */
	.max_concurrent_htlcs = 483,

	/* channel defaults for htlc min/max values */
	.htlc_minimum_msat = AMOUNT_MSAT(0),
	.htlc_maximum_msat = AMOUNT_MSAT(-1ULL),  /* no limit */

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

	/* Excplicitly turns 'on' or 'off' IP discovery feature. */
	.ip_discovery = OPT_AUTOBOOL_AUTO,

	/* Public TCP port assumed for IP discovery. Defaults to chainparams. */
	.ip_discovery_port = 0,

	/* Sets min_effective_htlc_capacity - at 1000$/BTC this is 10ct */
	.min_capacity_sat = 10000,

	/* 1 minute should be enough for anyone! */
	.connection_timeout_secs = 60,

	.allowdustreserve = false,

	.require_confirmed_inputs = false,

	.max_fee_multiplier = 10,
	.commit_fee_percent = 100,
	.feerate_offset = 5,
};

/* aka. "Dude, where's my coins?" */
static const struct config mainnet_config = {
	/* ~one day to catch cheating attempts. */
	.locktime_blocks = 6 * 24,

	/* BOLT #4:
	 * ## `max_htlc_cltv` Selection
	 *
	 * This ... value is defined as 2016 blocks, based on historical value
	 * deployed by Lightning implementations.
	 */
	/* FIXME: Typo in spec for CLTV in descripton!  But it breaks our spelling check, so we omit it above */
	.max_htlc_cltv = 2016,

	/* We're fairly trusting, under normal circumstances. */
	.anchor_confirms = 3,

	/* While up to 483 htlcs are possible we do 30 by default (as eclair does) to save blockspace */
	.max_concurrent_htlcs = 30,

	/* defaults for htlc min/max values */
	.htlc_minimum_msat = AMOUNT_MSAT(0),
	.htlc_maximum_msat = AMOUNT_MSAT(-1ULL),  /* no limit */

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

	/* Excplicitly turns 'on' or 'off' IP discovery feature. */
	.ip_discovery = OPT_AUTOBOOL_AUTO,

	/* Public TCP port assumed for IP discovery. Defaults to chainparams. */
	.ip_discovery_port = 0,

	/* Sets min_effective_htlc_capacity - at 1000$/BTC this is 10ct */
	.min_capacity_sat = 10000,

	/* 1 minute should be enough for anyone! */
	.connection_timeout_secs = 60,

	.allowdustreserve = false,

	.require_confirmed_inputs = false,

	.max_fee_multiplier = 10,
	.commit_fee_percent = 100,
	.feerate_offset = 5,
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

	if (ld->daemon_parent_fd != -1 && !ld->logfiles)
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
	printf("supports_open_accept_channel_type\n");
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

static bool opt_show_msat(char *buf, size_t len, const struct amount_msat *msat)
{
	opt_show_u64(buf, len, &msat->millisatoshis /* Raw: option output */);
	return true;
}

static char *opt_set_msat(const char *arg, struct amount_msat *amt)
{
	if (!parse_amount_msat(amt, arg, strlen(arg)))
		return tal_fmt(tmpctx, "Unable to parse millisatoshi '%s'", arg);

	return NULL;
}

static char *opt_set_sat(const char *arg, struct amount_sat *sat)
{
	struct amount_msat msat;
	if (!parse_amount_msat(&msat, arg, strlen(arg)))
		return tal_fmt(NULL, "Unable to parse millisatoshi '%s'", arg);
	if (!amount_msat_to_sat(sat, msat))
		return tal_fmt(NULL, "'%s' is not a whole number of sats", arg);
	return NULL;
}

static char *opt_set_sat_nondust(const char *arg, struct amount_sat *sat)
{
	char *ret = opt_set_sat(arg, sat);
	if (ret)
		return ret;
	if (amount_sat_less(*sat, chainparams->dust_limit))
		return tal_fmt(tmpctx, "Option must be over dust limit!");
	return NULL;
}

static bool opt_show_sat(char *buf, size_t len, const struct amount_sat *sat)
{
	struct amount_msat msat;
	if (!amount_sat_to_msat(&msat, *sat))
		abort();
	return opt_show_u64(buf, len,
			    &msat.millisatoshis); /* Raw: show sats number */
}

static char *opt_set_wumbo(struct lightningd *ld)
{
	/* Wumbo is now the default, FIXME: depreacted_apis! */
	return NULL;
}

static char *opt_set_dual_fund(struct lightningd *ld)
{
	/* Dual funding implies static remotkey */
	feature_set_or(ld->our_features,
		       take(feature_set_for_feature(NULL,
						    OPTIONAL_FEATURE(OPT_STATIC_REMOTEKEY))));
	feature_set_or(ld->our_features,
		       take(feature_set_for_feature(NULL,
						    OPTIONAL_FEATURE(OPT_DUAL_FUND))));
	return NULL;
}

static char *opt_set_splicing(struct lightningd *ld)
{
	feature_set_or(ld->our_features,
		       take(feature_set_for_feature(NULL,
						    OPTIONAL_FEATURE(OPT_EXPERIMENTAL_SPLICE))));
	return NULL;
}

static char *opt_set_onion_messages(struct lightningd *ld)
{
	if (!opt_deprecated_ok(ld, "experimental-onion-messages", NULL,
			       "v24.08", "v25.02"))
		return "--experimental-onion-message is now enabled by default";
	return NULL;
}

static char *opt_set_shutdown_wrong_funding(struct lightningd *ld)
{
	feature_set_or(ld->our_features,
		       take(feature_set_for_feature(NULL,
						    OPTIONAL_FEATURE(OPT_SHUTDOWN_WRONG_FUNDING))));
	return NULL;
}

static char *opt_set_peer_storage(struct lightningd *ld)
{
	feature_set_or(ld->our_features,
		       take(feature_set_for_feature(NULL,
						    OPTIONAL_FEATURE(OPT_PROVIDE_PEER_BACKUP_STORAGE))));
	feature_set_or(ld->our_features,
		       take(feature_set_for_feature(NULL,
						    OPTIONAL_FEATURE(OPT_WANT_PEER_BACKUP_STORAGE))));
	return NULL;
}

static char *opt_set_quiesce(struct lightningd *ld)
{
	if (!opt_deprecated_ok(ld, "experimental-quiesce", NULL,
			       "v24.11", "v25.05"))
		return "--experimental-quiesce is now enabled by default";
	return NULL;
}

static char *opt_set_anchor_zero_fee_htlc_tx(struct lightningd *ld)
{
	if (!opt_deprecated_ok(ld, "experimental-anchors", NULL,
			       "v24.02", "v25.02"))
		return "--experimental-anchors is now enabled by default";
	return NULL;
}

static char *opt_set_offers(struct lightningd *ld)
{
	if (!opt_deprecated_ok(ld, "experimental-offers", NULL,
			       "v24.11", "v25.05"))
		return "--experimental-offers has been deprecated (now the default)";

	return NULL;
}

static char *opt_set_db_upgrade(const char *arg, struct lightningd *ld)
{
	ld->db_upgrade_ok = tal(ld, bool);
	return opt_set_bool_arg(arg, ld->db_upgrade_ok);
}

static char *opt_add_api_beg(const char *arg, struct lightningd *ld)
{
	tal_arr_expand(&ld->api_begs, arg);
	return NULL;
}

static char *opt_set_announce_dns(const char *optarg, struct lightningd *ld)
{
	if (!opt_deprecated_ok(ld, "announce-addr-dns", NULL,
			       "v23.08", "v24.08"))
		return "--announce-addr-dns has been deprecated, use --bind-addr=dns:...";
	return opt_set_bool_arg(optarg, &ld->announce_dns);
}

char *hsm_secret_arg(const tal_t *ctx,
		     const char *arg,
		     const u8 **hsm_secret)
{
	char *codex32_fail;
	struct codex32 *codex32;

	/* We accept hex, or codex32.  hex is very very very unlikely to
	 * give a valid codex32, so try that first */
	codex32 = codex32_decode(tmpctx, "cl", arg, &codex32_fail);
	if (codex32) {
		*hsm_secret = tal_steal(ctx, codex32->payload);
		if (codex32->threshold != 0
		    || codex32->type != CODEX32_ENCODING_SECRET) {
			return "This is only one share of codex32!";
		}
	} else {
		/* Not codex32, was it hex? */
		*hsm_secret = tal_hexdata(ctx, arg, strlen(arg));
		if (!*hsm_secret) {
			/* It's not hex!  So give codex32 error */
 			return codex32_fail;
		}
	}

	if (tal_count(*hsm_secret) != 32)
		return "Invalid length: must be 32 bytes";

	return NULL;
}

static char *opt_set_codex32_or_hex(const char *arg, struct lightningd *ld)
{
	char *err;
	const u8 *payload;

	err = hsm_secret_arg(tmpctx, arg, &payload);
	if (err)
		return err;

	/* Checks if hsm_secret exists */
	int fd = open("hsm_secret", O_CREAT|O_EXCL|O_WRONLY, 0400);
	if (fd < 0) {
		/* Don't do anything if the file already exists. */
		if (errno == EEXIST)
			return tal_fmt(tmpctx, "hsm_secret already exists!");

		return tal_fmt(tmpctx, "Creating hsm_secret: %s",
			       strerror(errno));
	}

	if (!write_all(fd, payload, tal_count(payload))) {
		unlink_noerr("hsm_secret");
		return tal_fmt(tmpctx, "Writing HSM: %s",
			   strerror(errno));
	}

	/*~ fsync (mostly!) ensures that the file has reached the disk. */
	if (fsync(fd) != 0) {
		unlink_noerr("hsm_secret");
		return tal_fmt(tmpctx, "fsync: %s", strerror(errno));
	}
	/*~ This should never fail if fsync succeeded.  But paranoia good, and
	 * bugs exist. */
	if (close(fd) != 0) {
		unlink_noerr("hsm_secret");
		return tal_fmt(tmpctx, "closing: %s", strerror(errno));
	}

	/*~ We actually need to sync the *directory itself* to make sure the
	 * file exists!  You're only allowed to open directories read-only in
	 * modern Unix though. */
	fd = open(".", O_RDONLY);
	if (fd < 0) {
		unlink_noerr("hsm_secret");
		return tal_fmt(tmpctx, "opening: %s", strerror(errno));
	}
	if (fsync(fd) != 0) {
		unlink_noerr("hsm_secret");
		return tal_fmt(tmpctx, "fsyncdir: %s", strerror(errno));
	}
	close(fd);

	ld->recover = tal_strdup(ld, arg);
	opt_set_offline(ld);

	return NULL;
}

static void register_opts(struct lightningd *ld)
{
	/* This happens before plugins started */
	clnopt_noarg("--test-daemons-only", OPT_EARLY|OPT_EXITS,
		     test_subdaemons_and_exit,
		     ld,
		     "Test that subdaemons can be run, then exit immediately");
	/* We need to know this even before we talk to plugins */
	clnopt_witharg("--allow-deprecated-apis",
		       OPT_EARLY|OPT_SHOWBOOL,
		       opt_set_bool_arg, opt_show_bool,
		       &ld->deprecated_ok,
		       "Enable deprecated options, JSONRPC commands, fields, etc.");
	/* Register plugins as an early args, so we can initialize them and have
	 * them register more command line options */
	clnopt_witharg("--plugin", OPT_MULTI|OPT_EARLY,
		       opt_add_plugin, NULL, ld,
		       "Add a plugin to be run (can be used multiple times)");
	clnopt_witharg("--plugin-dir", OPT_MULTI|OPT_EARLY,
		       opt_add_plugin_dir,
		       NULL, ld,
		       "Add a directory to load plugins from (can be used multiple times)");
	opt_register_early_noarg("--clear-plugins", opt_clear_plugins,
				 ld,
				 "Remove all plugins added before this option");
	clnopt_witharg("--disable-plugin", OPT_MULTI|OPT_EARLY,
		       opt_disable_plugin,
		       NULL, ld,
		       "Disable a particular plugin by filename/name");

	clnopt_witharg("--important-plugin", OPT_MULTI|OPT_EARLY,
		       opt_important_plugin,
		       NULL, ld,
		       "Add an important plugin to be run (can be used multiple times). Die if the plugin dies.");

	/* Early, as it suppresses DNS lookups from cmdline too. */
	clnopt_witharg("--always-use-proxy", OPT_EARLY|OPT_SHOWBOOL,
		       opt_set_bool_arg, opt_show_bool,
		       &ld->always_use_proxy, "Use the proxy always");

	/* This immediately makes is a daemon. */
	opt_register_early_noarg("--daemon", opt_start_daemon, ld,
				 "Run in the background, suppress stdout/stderr");
	opt_register_early_arg("--wallet", opt_set_talstr, NULL,
			       &ld->wallet_dsn,
			       "Location of the wallet database.");

	opt_register_early_arg("--recover", opt_set_codex32_or_hex, NULL,
				ld,
				"Populate hsm_secret with the given codex32 secret"
				" and starts the node in `offline` mode.");

	/* This affects our features, so set early. */
	opt_register_early_noarg("--large-channels|--wumbo",
				 opt_set_wumbo, ld,
				 opt_hidden);

	opt_register_early_noarg("--experimental-dual-fund",
				 opt_set_dual_fund, ld,
				 "experimental: Advertise dual-funding"
				 " and allow peers to establish channels"
				 " via v2 channel open protocol.");

	opt_register_early_noarg("--experimental-splicing",
				 opt_set_splicing, ld,
				 "experimental: Enables the ability to resize"
				 " channels using splicing");

	/* This affects our features, so set early. */
	opt_register_early_noarg("--experimental-onion-messages",
				 opt_set_onion_messages, ld,
				 opt_hidden);
	opt_register_early_noarg("--experimental-offers",
				 opt_set_offers, ld,
				 opt_hidden);
	opt_register_early_noarg("--experimental-shutdown-wrong-funding",
				 opt_set_shutdown_wrong_funding, ld,
				 "EXPERIMENTAL: allow shutdown with alternate txids");
	opt_register_early_noarg("--experimental-peer-storage",
				 opt_set_peer_storage, ld,
				 "EXPERIMENTAL: enable peer backup storage and restore");
	opt_register_early_noarg("--experimental-quiesce",
				 opt_set_quiesce, ld,
				 "experimental: Advertise ability to quiesce"
				 " channels.");
	opt_register_early_noarg("--experimental-anchors",
				 opt_set_anchor_zero_fee_htlc_tx, ld,
				 opt_hidden);
	clnopt_witharg("--announce-addr-dns", OPT_EARLY|OPT_SHOWBOOL,
		       opt_set_bool_arg, opt_show_bool,
		       &ld->announce_dns,
		       opt_hidden);

	clnopt_noarg("--help|-h", OPT_EXITS,
		     opt_lightningd_usage, ld, "Print this message.");
	opt_register_arg("--rgb", opt_set_rgb, opt_show_rgb, ld,
			 "RRGGBB hex color for node");
	clnopt_witharg("--alias", OPT_KEEP_WHITESPACE, opt_set_alias,
		       opt_show_alias, ld, "Up to 32-byte alias for node");
	opt_register_arg("--pid-file=<file>", opt_set_talstr, opt_show_charp,
			 &ld->pidfile,
			 "Specify pid file");

	clnopt_witharg("--ignore-fee-limits", OPT_SHOWBOOL,
		       opt_set_bool_arg, opt_show_bool,
		       &ld->config.ignore_fee_limits,
		       "(DANGEROUS) allow peer to set any feerate");
	clnopt_witharg("--watchtime-blocks", OPT_SHOWINT, opt_set_u32, opt_show_u32,
			 &ld->config.locktime_blocks,
			 "Blocks before peer can unilaterally spend funds");
	opt_register_arg("--max-locktime-blocks", opt_set_max_htlc_cltv, NULL,
			 ld, opt_hidden);
	clnopt_witharg("--funding-confirms", OPT_SHOWINT, opt_set_u32, opt_show_u32,
			 &ld->config.anchor_confirms,
			 "Confirmations required for funding transaction");
	clnopt_witharg("--require-confirmed-inputs", OPT_SHOWBOOL,
		       opt_set_bool_arg, opt_show_bool,
		       &ld->config.require_confirmed_inputs,
		       "Confirmations required for inputs to funding transaction (v2 opens only)");
	clnopt_witharg("--cltv-delta", OPT_SHOWINT, opt_set_u32, opt_show_u32,
			 &ld->config.cltv_expiry_delta,
			 "Number of blocks for cltv_expiry_delta");
	clnopt_witharg("--cltv-final", OPT_SHOWINT, opt_set_u32, opt_show_u32,
			 &ld->config.cltv_final,
			 "Number of blocks for final cltv_expiry");
	clnopt_witharg("--commit-time=<millseconds>", OPT_SHOWINT,
			 opt_set_u32, opt_show_u32,
			 &ld->config.commit_time_ms,
			 "Time after changes before sending out COMMIT");
	clnopt_witharg("--fee-base", OPT_SHOWINT, opt_set_u32, opt_show_u32,
			 &ld->config.fee_base,
			 "Millisatoshi minimum to charge for HTLC");
	clnopt_witharg("--rescan", OPT_SHOWINT, opt_set_s32, opt_show_s32,
			 &ld->config.rescan,
			 "Number of blocks to rescan from the current head, or "
			 "absolute blockheight if negative");
	clnopt_witharg("--fee-per-satoshi", OPT_SHOWINT, opt_set_u32, opt_show_u32,
			 &ld->config.fee_per_satoshi,
			 "Microsatoshi fee for every satoshi in HTLC");
	clnopt_witharg("--htlc-minimum-msat", OPT_SHOWMSATS,
		       opt_set_msat, opt_show_msat,
		       &ld->config.htlc_minimum_msat,
		       "The default minimal value an HTLC must carry in order to be forwardable for new channels");
	clnopt_witharg("--htlc-maximum-msat", OPT_SHOWMSATS,
		       opt_set_msat, opt_show_msat,
		       &ld->config.htlc_maximum_msat,
		       "The default maximal value an HTLC must carry in order to be forwardable for new channel");
	clnopt_witharg("--max-concurrent-htlcs", OPT_SHOWINT, opt_set_u32, opt_show_u32,
			 &ld->config.max_concurrent_htlcs,
			 "Number of HTLCs one channel can handle concurrently. Should be between 1 and 483");
	clnopt_witharg("--max-dust-htlc-exposure-msat", OPT_SHOWMSATS,
		       opt_set_msat,
		       opt_show_msat, &ld->config.max_dust_htlc_exposure_msat,
		       "Max HTLC amount that can be trimmed");
	clnopt_witharg("--min-capacity-sat", OPT_SHOWINT|OPT_DYNAMIC,
		       opt_set_u64_dynamic, opt_show_u64,
		       &ld->config.min_capacity_sat,
		       "Minimum capacity in satoshis for accepting channels");
	clnopt_witharg("--addr", OPT_MULTI, opt_add_addr, NULL,
		       ld,
		       "Set an IP address (v4 or v6) to listen on and announce to the network for incoming connections");
	clnopt_witharg("--bind-addr", OPT_MULTI, opt_add_bind_addr, NULL,
		       ld,
		       "Set an IP address (v4 or v6) to listen on, but not announce");
	clnopt_witharg("--announce-addr", OPT_MULTI, opt_add_announce_addr, NULL,
		       ld,
		       "Set an IP address (v4 or v6) or .onion v3 to announce, but not listen on");

	opt_register_arg("--announce-addr-discovered", opt_set_autobool_arg, opt_show_autobool,
			 &ld->config.ip_discovery,
			 "Explicitly turns IP discovery 'on' or 'off'.");
	clnopt_witharg("--announce-addr-discovered-port", OPT_SHOWINT,
		       opt_set_uintval,
		       opt_show_uintval, &ld->config.ip_discovery_port,
		       "Sets the public TCP port to use for announcing discovered IPs.");
	opt_register_noarg("--offline", opt_set_offline, ld,
			   "Start in offline-mode (do not automatically reconnect and do not accept incoming connections)");
	clnopt_witharg("--autolisten", OPT_SHOWBOOL,
		       opt_set_bool_arg, opt_show_bool,
		       &ld->autolisten,
		       "If true, listen on default port and announce if it seems to be a public interface");
	opt_register_arg("--proxy", opt_add_proxy_addr, NULL,
			ld,"Set a socks v5 proxy IP address and port");
	opt_register_arg("--tor-service-password", opt_set_talstr, NULL,
			 &ld->tor_service_password,
			 "Set a Tor hidden service password");

	opt_register_arg("--accept-htlc-tlv-types",
			 opt_set_accept_extra_tlv_types, NULL, ld,
			 opt_hidden);
	clnopt_witharg("--accept-htlc-tlv-type", OPT_MULTI|OPT_SHOWINT,
		       opt_add_accept_htlc_tlv, NULL,
		       &ld->accept_extra_tlv_types,
		       "HTLC TLV type to accept (can be used multiple times)");

	opt_register_early_noarg("--disable-dns", opt_set_invbool, &ld->config.use_dns,
				 "Disable DNS lookups of peers");

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

	clnopt_witharg("--commit-fee", OPT_SHOWINT,
		       opt_set_u64, opt_show_u64, &ld->config.commit_fee_percent,
		       "Percentage of fee to request for their commitment");
	clnopt_witharg("--commit-feerate-offset", OPT_SHOWINT,
		       opt_set_u32, opt_show_u32, &ld->config.feerate_offset,
		       "Additional feerate per kw to apply to feerate updates "
		       "as the channel opener");
	clnopt_witharg("--min-emergency-msat", OPT_SHOWMSATS,
		       opt_set_sat_nondust, opt_show_sat, &ld->emergency_sat,
		       "Amount to leave in wallet for spending anchor closes");
	clnopt_witharg("--subdaemon",
		       OPT_MULTI,
		       opt_subdaemon, NULL,
		       ld, "Arg specified as SUBDAEMON:PATH. "
		       "Specifies an alternate subdaemon binary. "
		       "If the supplied path is relative the subdaemon "
		       "binary is found in the working directory. "
		       "This option may be specified multiple times. "
		       "For example, "
		       "--subdaemon=hsmd:remote_signer "
		       "would use a hypothetical remote signing subdaemon.");

	opt_register_noarg("--experimental-upgrade-protocol",
			   opt_set_bool, &ld->experimental_upgrade_protocol,
			   "experimental: allow channel types to be upgraded on reconnect");
	opt_register_noarg("--invoices-onchain-fallback",
			   opt_set_bool, &ld->unified_invoices,
			   "Include an onchain address in invoices and mark them as paid if payment is received on-chain");
	clnopt_witharg("--database-upgrade", OPT_SHOWBOOL,
		       opt_set_db_upgrade, NULL,
		       ld,
		       "Set to true to allow database upgrades even on non-final releases (WARNING: you won't be able to downgrade!)");
	clnopt_witharg("--i-promise-to-fix-broken-api-user",
		       OPT_MULTI,
		       opt_add_api_beg, NULL,
		       ld,
		       "Re-enable a long-deprecated API (which will be removed entirely next version!)");
	opt_register_logging(ld);

	dev_register_opts(ld);
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
		ld->rgb = tal_dup_arr(ld, u8, ld->our_nodeid.k, 3, 0);

	if (!ld->alias) {
		u64 adjective, noun;
		char *name;

		memcpy(&adjective, ld->our_nodeid.k+3, sizeof(adjective));
		memcpy(&noun, ld->our_nodeid.k+3+sizeof(adjective), sizeof(noun));
		noun %= ARRAY_SIZE(codename_noun);
		adjective %= ARRAY_SIZE(codename_adjective);

		/* Only use 32 characters */
		name = tal_fmt(ld, "%s%s",
			       codename_adjective[adjective],
			       codename_noun[noun]);

		if (ld->developer) {
			assert(strlen(name) < 32);
			int taillen = 31 - strlen(name);
			if (taillen > strlen(version()))
				taillen = strlen(version());
			/* Fit as much of end of version() as possible */
			tal_append_fmt(&name, "-%s",
				       version() + strlen(version()) - taillen);
		}
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
	clnopt_noarg("--list-features-only", OPT_EARLY|OPT_EXITS,
		     list_features_and_exit,
		     ld, "List the features configured, and exit immediately");

	/*~ We need to know this super-early, as it controls other options */
	clnopt_noarg("--developer", OPT_EARLY|OPT_SHOWBOOL,
		     opt_set_bool, &ld->developer,
		     "Enable developer commands/options, disable legacy APIs");

	/*~ This does enough parsing to get us the base configuration options */
	ld->configvars = initial_config_opts(ld, &argc, argv, true,
					     &ld->config_filename,
					     &ld->config_basedir,
					     &ld->config_netdir,
					     &ld->rpc_filename);

	if (argc != 1)
		errx(1, "no arguments accepted");

	/* Copy in default config, to be modified by further options */
	if (chainparams->testnet)
		ld->config = testnet_config;
	else
		ld->config = mainnet_config;

	/* No anchors if we're elements */
	if (chainparams->is_elements) {
		feature_set_sub(ld->our_features,
				feature_set_for_feature(tmpctx,
							OPTIONAL_FEATURE(OPT_ANCHORS_ZERO_FEE_HTLC_TX)));
	}

	/* Set the ln_port given from chainparams */
	ld->config.ip_discovery_port = chainparams->ln_port;

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

	/* --developer changes default for APIs */
	if (ld->developer)
		ld->deprecated_ok = false;

	/*~ We move files from old locations on first upgrade. */
	promote_missing_files(ld);

	/*~ The ccan/opt code requires registration then parsing; we
	 *  mimic this API here, even though they're on separate lines.*/
	register_opts(ld);

	/* Now, first-pass of parsing.  But only handle the early
	 * options (testnet, plugins etc), others may be added on-demand */
	parse_configvars_early(ld->configvars, ld->developer);

	/* Finalize the logging subsystem now. */
	logging_options_parsed(ld->log_book);
}

/* Free *str, set *str to copy with `cln` prepended */
static void prefix_cln(char **str STEALS)
{
	char *newstr = tal_fmt(tal_parent(*str), "cln%s", *str);
	tal_free(*str);
	*str = newstr;
}

/* Due to a conflict between the widely-deployed clightning-rest plugin and
 * our own clnrest plugin, and people wanting to run both, in v23.11 we
 * renamed some options.  This breaks perfectly working v23.08 deployments who
 * don't care about clightning-rest, so we work around it here. */
static void fixup_clnrest_options(struct lightningd *ld)
{
	for (size_t i = 0; i < tal_count(ld->configvars); i++) {
		struct configvar *cv = ld->configvars[i];

		/* These worked for v23.08 */
		if (!strstarts(cv->configline, "rest-port=")
		    && !strstarts(cv->configline, "rest-protocol=")
		    && !strstarts(cv->configline, "rest-host=")
		    && !strstarts(cv->configline, "rest-certs="))
			continue;
		/* Did some (plugin) claim it? */
		if (opt_find_long(cv->configline, cast_const2(const char **, &cv->optarg)))
			continue;
		if (!opt_deprecated_ok(ld,
				       tal_strndup(tmpctx, cv->configline,
						   strcspn(cv->configline, "=")),
				       "clnrest-prefix",
				       "v23.11", "v24.11"))
			continue;
		log_unusual(ld->log, "Option %s deprecated in v23.11, renaming to cln%s",
			    cv->configline, cv->configline);
		prefix_cln(&cv->configline);
	}
}

void handle_opts(struct lightningd *ld)
{
	fixup_clnrest_options(ld);

	/* Now we know all the options, finish parsing and finish
	 * populating ld->configvars with cmdline. */
	parse_configvars_final(ld->configvars, true, ld->developer);

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

static void json_add_opt_log_to_files(struct json_stream *response,
			       const char *name0,
			       const char **logfiles)
{
	for (size_t i = 0; i < tal_count(logfiles); i++)
		json_add_string(response, name0, logfiles[i]);
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

/* Canonicalize value they've given */
bool opt_canon_bool(const char *val)
{
	bool b;
	opt_set_bool_arg(val, &b);
	return b;
}

void add_config_deprecated(struct lightningd *ld,
			   struct json_stream *response,
			   const struct opt_table *opt,
			   const char *name, size_t len)
{
	char *name0 = tal_strndup(tmpctx, name, len);
	char *answer = NULL;
	char buf[4096 + sizeof("...")];

	/* Ignore dev settings. */
	if (opt->type & OPT_DEV)
		return;

	/* Ignore things which just exit */
	if (opt->type & OPT_EXITS)
		return;

	/* Ignore hidden options (deprecated) */
	if (opt->desc == opt_hidden)
		return;

	/* We print plugin options under plugins[] or important-plugins[] */
	if (is_plugin_opt(opt))
		return;

	if (opt->type & OPT_NOARG) {
		if (opt->cb == (void *)opt_clear_plugins) {
			/* FIXME: we can't recover this. */
		} else if (is_restricted_ignored(opt->cb)) {
			/* --testnet etc, turned into --network=. */
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
		} else if (opt->cb == (void *)opt_set_splicing) {
			json_add_bool(response, name0,
				      feature_offered(ld->our_features
						      ->bits[INIT_FEATURE],
						      OPT_EXPERIMENTAL_SPLICE));
		} else if (opt->cb == (void *)opt_set_onion_messages) {
			json_add_bool(response, name0,
				      feature_offered(ld->our_features
						      ->bits[INIT_FEATURE],
						      OPT_ONION_MESSAGES));
		} else if (opt->cb == (void *)opt_set_offers) {
			json_add_bool(response, name0, true);
		} else if (opt->cb == (void *)opt_set_shutdown_wrong_funding) {
			json_add_bool(response, name0,
				      feature_offered(ld->our_features
						      ->bits[INIT_FEATURE],
						      OPT_SHUTDOWN_WRONG_FUNDING));
		} else if (opt->cb == (void *)opt_set_peer_storage) {
			json_add_bool(response, name0,
				      feature_offered(ld->our_features
						      ->bits[INIT_FEATURE],
						      OPT_PROVIDE_PEER_BACKUP_STORAGE));
		} else if (opt->cb == (void *)opt_set_quiesce) {
			json_add_bool(response, name0,
				      feature_offered(ld->our_features
						      ->bits[INIT_FEATURE],
						      OPT_QUIESCE));
		}
		/* We ignore future additions, since these are deprecated anyway! */
	} else if (opt->type & OPT_HASARG) {
		if (opt->show == (void *)opt_show_charp) {
			if (*(char **)opt->u.carg)
				/* Don't truncate or quote! */
				answer = tal_strdup(tmpctx,
						    *(char **)opt->u.carg);
		} else if (opt->show) {
			strcpy(buf + sizeof(buf) - sizeof("..."), "...");
			if (!opt->show(buf, sizeof(buf) - sizeof("..."), opt->u.carg))
				buf[0] = '\0';

			if (opt->type & OPT_CONCEAL) {
				strcpy(buf, "...");
			} else if ((opt->type & OPT_SHOWINT)
				   || (opt->type & OPT_SHOWMSATS)) {
				if (streq(buf, "")
				    || strspn(buf, "-0123456789.") != strlen(buf))
					errx(1, "Bad literal for %s: %s", name0, buf);
				json_add_primitive(response, name0, buf);
				return;
			} else if (opt->type & OPT_SHOWBOOL) {
				/* We allow variants here.  Json-ize */
				json_add_bool(response, name0, opt_canon_bool(buf));
				return;
			}
			answer = buf;
		} else if (opt->cb_arg == (void *)opt_set_talstr
			   || opt->cb_arg == (void *)opt_set_charp) {
			const char *arg = *(char **)opt->u.carg;
			if (arg)
				answer = tal_fmt(name0, "%s", arg);
		} else if (opt->cb_arg == (void *)arg_log_to_file) {
			if (ld->logfiles)
				json_add_opt_log_to_files(response, name0, ld->logfiles);
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
			json_add_opt_log_levels(response, ld->log_book);
		} else if (opt->cb_arg == (void *)opt_disable_plugin) {
			json_add_opt_disable_plugins(response, ld->plugins);
		} else if (opt->cb_arg == (void *)opt_force_feerates) {
			answer = fmt_force_feerates(name0, ld->force_feerates);
		} else if (opt->cb_arg == (void *)opt_set_db_upgrade) {
			if (ld->db_upgrade_ok)
				json_add_bool(response, name0,
					      *ld->db_upgrade_ok);
			return;
		} else if (opt->cb_arg == (void *)opt_set_announce_dns) {
			json_add_bool(response, name0, ld->announce_dns);
			return;
		} else if (opt->cb_arg == (void *)opt_important_plugin) {
			/* Do nothing, this is already handled by
			 * opt_add_plugin.  */
		} else if (opt->cb_arg == (void *)opt_add_plugin_dir) {
			/* FIXME: We actually treat it as if they specified
			 * --plugin for each one, so ignore these */
		} else if (opt->cb_arg == (void *)opt_add_accept_htlc_tlv) {
			/* We ignore this: it's printed below: */
		} else if (opt->cb_arg == (void *)opt_set_accept_extra_tlv_types) {
			for (size_t i = 0;
			     i < tal_count(ld->accept_extra_tlv_types);
			     i++) {
				if (i == 0)
					answer = tal_fmt(name0, "%"PRIu64,
							 ld->accept_extra_tlv_types[i]);
				else
					tal_append_fmt(&answer, ",%"PRIu64,
						       ld->accept_extra_tlv_types[i]);
			}
		}
		/* We ignore future additions, since these are deprecated anyway! */
	}

	if (answer) {
		struct json_escape *esc = json_escape(NULL, answer);
		json_add_escaped_string(response, name0, take(esc));
	}
}

bool is_known_opt_cb_arg(char *(*cb_arg)(const char *, void *))
{
	return cb_arg == (void *)opt_set_talstr
		|| cb_arg == (void *)opt_add_proxy_addr
		|| cb_arg == (void *)opt_force_feerates
		|| cb_arg == (void *)opt_set_accept_extra_tlv_types
		|| cb_arg == (void *)opt_add_plugin
		|| cb_arg == (void *)opt_add_plugin_dir
		|| cb_arg == (void *)opt_important_plugin
		|| cb_arg == (void *)opt_disable_plugin
		|| cb_arg == (void *)opt_add_addr
		|| cb_arg == (void *)opt_add_bind_addr
		|| cb_arg == (void *)opt_add_announce_addr
		|| cb_arg == (void *)opt_subdaemon
		|| cb_arg == (void *)opt_set_db_upgrade
		|| cb_arg == (void *)arg_log_to_file
		|| cb_arg == (void *)opt_add_accept_htlc_tlv
		|| cb_arg == (void *)opt_set_codex32_or_hex
		|| cb_arg == (void *)opt_subd_dev_disconnect
		|| cb_arg == (void *)opt_add_api_beg
		|| cb_arg == (void *)opt_force_featureset
		|| cb_arg == (void *)opt_force_privkey
		|| cb_arg == (void *)opt_force_bip32_seed
		|| cb_arg == (void *)opt_force_channel_secrets
		|| cb_arg == (void *)opt_force_tmp_channel_id;
}
