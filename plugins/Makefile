PLUGIN_PAY_SRC := plugins/pay.c
PLUGIN_PAY_HEADER :=
PLUGIN_PAY_OBJS := $(PLUGIN_PAY_SRC:.c=.o)

PLUGIN_AUTOCLEAN_SRC := plugins/autoclean.c
PLUGIN_AUTOCLEAN_OBJS := $(PLUGIN_AUTOCLEAN_SRC:.c=.o)

PLUGIN_chanbackup_SRC := plugins/chanbackup.c
PLUGIN_chanbackup_OBJS := $(PLUGIN_chanbackup_SRC:.c=.o)

PLUGIN_TOPOLOGY_SRC := plugins/topology.c
PLUGIN_TOPOLOGY_OBJS := $(PLUGIN_TOPOLOGY_SRC:.c=.o)

PLUGIN_TXPREPARE_SRC := plugins/txprepare.c
PLUGIN_TXPREPARE_OBJS := $(PLUGIN_TXPREPARE_SRC:.c=.o)

PLUGIN_BCLI_SRC := plugins/bcli.c
PLUGIN_BCLI_OBJS := $(PLUGIN_BCLI_SRC:.c=.o)

PLUGIN_COMMANDO_SRC := plugins/commando.c
PLUGIN_COMMANDO_OBJS := $(PLUGIN_COMMANDO_SRC:.c=.o)

PLUGIN_KEYSEND_SRC := plugins/keysend.c
PLUGIN_KEYSEND_OBJS := $(PLUGIN_KEYSEND_SRC:.c=.o)

PLUGIN_LIB_SRC := plugins/libplugin.c
PLUGIN_LIB_HEADER := plugins/libplugin.h
PLUGIN_LIB_OBJS := $(PLUGIN_LIB_SRC:.c=.o)

PLUGIN_PAY_LIB_SRC := \
	plugins/channel_hint.c \
	plugins/libplugin-pay.c

PLUGIN_PAY_LIB_HEADER := \
	plugins/channel_hint.h \
	plugins/libplugin-pay.h

PLUGIN_PAY_LIB_OBJS := $(PLUGIN_PAY_LIB_SRC:.c=.o)

PLUGIN_OFFERS_SRC := plugins/offers.c plugins/offers_offer.c plugins/offers_invreq_hook.c plugins/offers_inv_hook.c plugins/establish_onion_path.c plugins/fetchinvoice.c
PLUGIN_OFFERS_OBJS := $(PLUGIN_OFFERS_SRC:.c=.o)
PLUGIN_OFFERS_HEADER := $(PLUGIN_OFFERS_SRC:.c=.h)

PLUGIN_SQL_SRC := plugins/sql.c
PLUGIN_SQL_HEADER :=
PLUGIN_SQL_OBJS := $(PLUGIN_SQL_SRC:.c=.o)

PLUGIN_EXPOSESECRET_SRC := plugins/exposesecret.c
PLUGIN_EXPOSESECRET_HEADER :=
PLUGIN_EXPOSESECRET_OBJS := $(PLUGIN_EXPOSESECRET_SRC:.c=.o)

PLUGIN_SPENDER_SRC :=				\
	plugins/spender/fundchannel.c		\
	plugins/spender/main.c			\
	plugins/spender/multifundchannel.c	\
	plugins/spender/multiwithdraw.c		\
	plugins/spender/openchannel.c		\
	plugins/spender/splice.c
PLUGIN_SPENDER_HEADER :=			\
	plugins/spender/multifundchannel.h	\
	plugins/spender/multiwithdraw.h		\
	plugins/spender/fundchannel.h		\
	plugins/spender/multifundchannel.h	\
	plugins/spender/openchannel.h		\
	plugins/spender/splice.h
PLUGIN_SPENDER_OBJS := $(PLUGIN_SPENDER_SRC:.c=.o)

PLUGIN_RECOVER_SRC := plugins/recover.c
PLUGIN_RECOVER_OBJS := $(PLUGIN_RECOVER_SRC:.c=.o)

PLUGIN_FUNDER_SRC :=				\
	plugins/funder.c			\
	plugins/funder_policy.c
PLUGIN_FUNDER_HEADER :=				\
	plugins/funder_policy.h
PLUGIN_FUNDER_OBJS := $(PLUGIN_FUNDER_SRC:.c=.o)

PLUGIN_RECKLESSRPC_SRC := plugins/recklessrpc.c
PLUGIN_RECKLESSRPC_OBJS := $(PLUGIN_RECKLESSRPC_SRC:.c=.o)

PLUGIN_ALL_SRC :=				\
	$(PLUGIN_AUTOCLEAN_SRC)			\
	$(PLUGIN_chanbackup_SRC)		\
	$(PLUGIN_BCLI_SRC)			\
	$(PLUGIN_COMMANDO_SRC)			\
	$(PLUGIN_FUNDER_SRC)			\
	$(PLUGIN_TOPOLOGY_SRC)			\
	$(PLUGIN_EXPOSESECRET_SRC)		\
	$(PLUGIN_KEYSEND_SRC)			\
	$(PLUGIN_TXPREPARE_SRC)			\
	$(PLUGIN_LIB_SRC)			\
	$(PLUGIN_OFFERS_SRC)			\
	$(PLUGIN_PAY_LIB_SRC)			\
	$(PLUGIN_PAY_SRC)			\
	$(PLUGIN_SPENDER_SRC)			\
	$(PLUGIN_RECOVER_SRC)			\
	$(PLUGIN_RECKLESSRPC_SRC)

PLUGIN_ALL_HEADER :=				\
	$(PLUGIN_PAY_HEADER)			\
	$(PLUGIN_LIB_HEADER)			\
	$(PLUGIN_FUNDER_HEADER)			\
	$(PLUGIN_PAY_LIB_HEADER)		\
	$(PLUGIN_OFFERS_HEADER)			\
	$(PLUGIN_SPENDER_HEADER)

C_PLUGINS :=					\
	plugins/autoclean			\
	plugins/chanbackup			\
	plugins/bcli				\
	plugins/commando			\
	plugins/funder				\
	plugins/topology			\
	plugins/exposesecret			\
	plugins/keysend				\
	plugins/offers				\
	plugins/pay				\
	plugins/recklessrpc			\
	plugins/recover				\
	plugins/txprepare			\
	plugins/cln-renepay			\
	plugins/cln-xpay			\
	plugins/spenderp			\
	plugins/cln-askrene

ifeq ($(HAVE_SQLITE3),1)
C_PLUGINS += plugins/sql
PLUGIN_ALL_SRC += $(PLUGIN_SQL_SRC)
PLUGIN_ALL_HEADER += $(PLUGIN_SQL_HEADER)
endif

# This is non-python plugins (PY_PLUGINS need their whole directory!)
PLUGINS := $(C_PLUGINS)

# Remove clnrest directory if exists which is the old python plugin code
$(shell test -d plugins/clnrest && $(RM) -r plugins/clnrest || true)
# Remove wss-proxy directory if exists which is the old python plugin code
$(shell test -d plugins/wss-proxy && $(RM) -r plugins/wss-proxy || true)

ifneq ($(RUST),0)
# Builtin plugins must be in this plugins dir to work when we're executed
# *without* make install.
plugins/cln-grpc: $(RUST_TARGET_DIR)/cln-grpc
	@cp $< $@
plugins/clnrest: $(RUST_TARGET_DIR)/clnrest
	@cp $< $@
plugins/cln-lsps-client: $(RUST_TARGET_DIR)/cln-lsps-client
	@cp $< $@
plugins/cln-lsps-service: $(RUST_TARGET_DIR)/cln-lsps-service
	@cp $< $@
plugins/wss-proxy: $(RUST_TARGET_DIR)/wss-proxy
	@cp $< $@
plugins/cln-bip353: $(RUST_TARGET_DIR)/cln-bip353
	@cp $< $@

PLUGINS += plugins/cln-grpc plugins/clnrest plugins/cln-lsps-client plugins/cln-lsps-service plugins/wss-proxy plugins/cln-bip353
endif

include plugins/askrene/Makefile
include plugins/bkpr/Makefile
include plugins/renepay/Makefile
include plugins/xpay/Makefile

# Make sure these depend on everything.
ALL_C_SOURCES += $(PLUGIN_ALL_SRC)
ALL_C_HEADERS += $(PLUGIN_ALL_HEADER)
ALL_PROGRAMS += $(C_PLUGINS)

PLUGIN_ALL_OBJS := $(PLUGIN_ALL_SRC:.c=.o)

# Make all plugins depend on all plugin headers, for simplicity (and this file!)
$(PLUGIN_ALL_OBJS): $(PLUGIN_ALL_HEADER) plugins/Makefile

plugins/pay: $(PLUGIN_PAY_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_PAY_LIB_OBJS) libcommon.a

plugins/autoclean: $(PLUGIN_AUTOCLEAN_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

plugins/chanbackup: $(PLUGIN_chanbackup_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

plugins/commando: $(PLUGIN_COMMANDO_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

# Topology wants to decode node_announcement, and peer_wiregen which
# pulls in some of bitcoin/.
plugins/topology:  $(PLUGIN_TOPOLOGY_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

plugins/txprepare: $(PLUGIN_TXPREPARE_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

plugins/exposesecret: $(PLUGIN_EXPOSESECRET_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

plugins/bcli: $(PLUGIN_BCLI_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

plugins/keysend: $(PLUGIN_KEYSEND_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_PAY_LIB_OBJS) libcommon.a
$(PLUGIN_KEYSEND_OBJS): $(PLUGIN_PAY_LIB_HEADER) libcommon.a

plugins/spenderp: $(PLUGIN_SPENDER_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

plugins/offers: $(PLUGIN_OFFERS_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

plugins/funder: $(PLUGIN_FUNDER_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

plugins/recover:  $(PLUGIN_RECOVER_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

plugins/recklessrpc: $(PLUGIN_RECKLESSRPC_OBJS) $(PLUGIN_LIB_OBJS) libcommon.a

# This covers all the low-level list RPCs which return simple arrays
SQL_LISTRPCS := listchannels listforwards listhtlcs listinvoices listnodes listoffers listpeers listpeerchannels listclosedchannels listtransactions listsendpays listchainmoves listchannelmoves bkpr-listaccountevents bkpr-listincome listnetworkevents
SQL_LISTRPCS_SCHEMAS := $(foreach l,$(SQL_LISTRPCS),doc/schemas/$l.json)
SQL_SCHEMA_PARTS := $(foreach l,$(SQL_LISTRPCS), plugins/sql-schema_$l_gen.h)

# RES_JSON is generated by:
# 1: deleting description array (used for field details) but keeping description keys
# 2: deleting additionalProperties, required, enum, maxLength, minLength, pre_return_value_notes, post_return_value_notes, anyOf, oneOf, hidden, untyped, default, comment, added, maximum, minimum, pattern, format
# (We only need [field].type, [field].name, [field].deprecated, [field].allOf, [field].items.allOf and allOf from response.properties)
# 3: deleting empty objects from .response.properties
# But these simple removals drop us from 100k to 18k.
plugins/sql-schema_%_gen.h: doc/schemas/%.json
	@jq 'walk(if type == "object" then if has("description") and (.description | type) == "array" then del(.description) else . end else . end ) | walk(if type == "object" then del(.additionalProperties, .required, .enum, .maxLength, .minLength, .pre_return_value_notes, .post_return_value_notes, .anyOf, .oneOf, .hidden, .untyped, .default, .comment, .added, .maximum, .minimum, .pattern, .format) else . end) | walk(if type == "object" then with_entries(select(.value != {})) else . end) | .response.properties' < $< > $@

# Regen if these rules change!
$(SQL_SCHEMA_PARTS): plugins/Makefile

plugins/sql-schema_gen.h: $(SQL_SCHEMA_PARTS)
	@$(call VERBOSE,GEN $@, set -e; (\
		SEP=""; \
		echo "\"{"; \
		for l in $(SQL_LISTRPCS); do \
			echo "$$SEP\"$$l\":{\"properties\":$$(cat plugins/sql-schema_$${l}_gen.h)}" | $(SED) s/\"/\\\"/g; \
			SEP=","; \
		done | $(SED) "s/\\\"/\\\\\"/g"; \
		echo "}\"") | tr -d " \n" > $@ \
	)

plugins/sql.o: plugins/sql-schema_gen.h
plugins/sql: $(PLUGIN_SQL_OBJS) $(PLUGIN_LIB_OBJS) gossipd/gossip_store_wiregen.o libcommon.a

# Generated from PLUGINS definition in plugins/Makefile
ALL_C_HEADERS += plugins/list_of_builtin_plugins_gen.h
PLUGIN_BASES := $(PLUGINS:plugins/%=%) $(PY_PLUGINS:plugins/%=%)

plugins/list_of_builtin_plugins_gen.h: plugins/Makefile Makefile config.vars
	@$(call VERBOSE,GEN $@,echo "static const char *list_of_builtin_plugins[] = { $(PLUGIN_BASES:%=\"%\",) NULL };" > $@)

$(RUST_TARGET_DIR)/examples/cln-subscribe-wildcard: ${CLN_PLUGIN_SRC} plugins/examples/cln-subscribe-wildcard.rs
	cargo build ${CARGO_OPTS} --example cln-subscribe-wildcard

CLN_PLUGIN_EXAMPLES := \
	$(RUST_TARGET_DIR)/examples/cln-plugin-startup \
	$(RUST_TARGET_DIR)/examples/cln-plugin-reentrant \
	$(RUST_TARGET_DIR)/examples/cln-rpc-getinfo \
	$(RUST_TARGET_DIR)/examples/cln-subscribe-wildcard

CLN_PLUGIN_SRC = $(shell find plugins/src -name "*.rs")
CLN_GRPC_PLUGIN_SRC = $(shell find plugins/grpc-plugin/src -name "*.rs")
CLN_REST_PLUGIN_SRC = $(shell find plugins/rest-plugin/src -name "*.rs")
CLN_LSPS_PLUGIN_SRC = $(shell find plugins/lsps-plugin/src -name "*.rs")
CLN_WSS_PROXY_PLUGIN_SRC = $(shell find plugins/wss-proxy-plugin/src -name "*.rs")
CLN_BIP353_PLUGIN_SRC = $(shell find plugins/bip353-plugin/src -name "*.rs")

$(RUST_TARGET_DIR)/cln-grpc: ${CLN_PLUGIN_SRC} ${CLN_GRPC_PLUGIN_SRC} $(MSGGEN_GENALL) $(MSGGEN_GEN_ALL)
	cargo build ${CARGO_OPTS} --bin cln-grpc
$(RUST_TARGET_DIR)/clnrest: ${CLN_REST_PLUGIN_SRC}
	cargo build ${CARGO_OPTS} --bin clnrest
$(RUST_TARGET_DIR)/cln-lsps-client: ${CLN_LSPS_PLUGIN_SRC}
	cargo build ${CARGO_OPTS} --bin cln-lsps-client
$(RUST_TARGET_DIR)/cln-lsps-service: ${CLN_LSPS_PLUGIN_SRC}
	cargo build ${CARGO_OPTS} --bin cln-lsps-service
$(RUST_TARGET_DIR)/wss-proxy: ${CLN_WSS_PROXY_PLUGIN_SRC}
	cargo build ${CARGO_OPTS} --bin wss-proxy
$(RUST_TARGET_DIR)/cln-bip353: ${CLN_BIP353_PLUGIN_SRC}
	cargo build ${CARGO_OPTS} --bin cln-bip353

ifneq ($(RUST),0)
include plugins/rest-plugin/Makefile
include plugins/wss-proxy-plugin/Makefile
DEFAULT_TARGETS += $(CLN_PLUGIN_EXAMPLES) plugins/cln-grpc plugins/clnrest plugins/cln-lsps-client plugins/cln-lsps-service plugins/wss-proxy plugins/cln-bip353
endif

clean: plugins-clean
plugins-clean:
	$(RM) $(PLUGINS) $(CLN_PLUGIN_EXAMPLES)
	$(RM) plugins/sql-schema_gen.h

include plugins/test/Makefile
