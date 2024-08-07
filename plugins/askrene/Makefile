PLUGIN_ASKRENE_SRC := plugins/askrene/askrene.c plugins/askrene/layer.c
PLUGIN_ASKRENE_HEADER := plugins/askrene/askrene.h plugins/askrene/layer.h
PLUGIN_ASKRENE_OBJS := $(PLUGIN_ASKRENE_SRC:.c=.o)

$(PLUGIN_ASKRENE_OBJS): $(PLUGIN_ASKRENE_HEADER)

ALL_C_SOURCES += $(PLUGIN_ASKRENE_SRC)
ALL_C_HEADERS += $(PLUGIN_ASKRENE_HEADER)

plugins/cln-askrene: $(PLUGIN_ASKRENE_OBJS) $(PLUGIN_LIB_OBJS) $(PLUGIN_COMMON_OBJS) $(JSMN_OBJS) $(CCAN_OBJS) bitcoin/chainparams.o common/gossmap.o common/sciddir_or_pubkey.o common/gossmods_listpeerchannels.o common/fp16.o common/dijkstra.o common/bolt12.o common/bolt12_merkle.o wire/bolt12_wiregen.o wire/onion_wiregen.o
