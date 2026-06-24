# libbolt12 - Makefile fragment included by CLN's top-level Makefile.
#
# Produces:
#   libbolt12.a                    thin wrapper; consumers link libcommon.a +
#                                  libccan.a + libsecp256k1 alongside it
#   libbolt12-fat.a                self-contained archive (only needs
#                                  -lsecp256k1 at link time)
#   contrib/libbolt12/run-bolt12   unit test binary

LIBBOLT12_SRC := contrib/libbolt12/bolt12_api.c
LIBBOLT12_OBJS := $(LIBBOLT12_SRC:.c=.o)
LIBBOLT12_HEADERS := \
	contrib/libbolt12/bolt12.h \
	contrib/libbolt12/bolt12_internal.h

LIBBOLT12_TEST_SRC := contrib/libbolt12/run-bolt12.c
LIBBOLT12_TEST_OBJS := $(LIBBOLT12_TEST_SRC:.c=.o)

# Thin wrapper library (just our wrapper code).
libbolt12.a: $(LIBBOLT12_OBJS)
	@$(call VERBOSE, "ar libbolt12.a", $(AR) rcs $@ $(LIBBOLT12_OBJS))

# Fat archive: bundles libbolt12 + libcommon + libccan. External
# consumers still need -lsecp256k1 -lsodium -lwallycore -lm at link time
# because libcommon.a transitively references sodium/wally symbols from
# code paths libbolt12 itself doesn't use (psbt.c, script.c, randbytes.c
# etc.). A future refactor could extract a bolt12-only subset to drop
# those transitive deps.
libbolt12-fat.a: libbolt12.a libcommon.a libccan.a
	@$(call VERBOSE, "ar libbolt12-fat.a", \
	  rm -rf .libbolt12-tmp && mkdir .libbolt12-tmp && \
	  cd .libbolt12-tmp && \
	  $(AR) x ../libbolt12.a && \
	  $(AR) x ../libcommon.a && \
	  $(AR) x ../libccan.a && \
	  $(AR) rcs ../libbolt12-fat.a *.o && \
	  cd .. && rm -rf .libbolt12-tmp)

# Test binary.
contrib/libbolt12/run-bolt12: $(LIBBOLT12_TEST_OBJS) libbolt12.a libcommon.a libccan.a
	@$(call VERBOSE, "ld $@", \
	  $(CC) $(CFLAGS) -o $@ $(LIBBOLT12_TEST_OBJS) \
	    libbolt12.a libcommon.a libccan.a \
	    $(EXTERNAL_LDLIBS) $(LDLIBS))

check-libbolt12: contrib/libbolt12/run-bolt12
	contrib/libbolt12/run-bolt12

ALL_C_SOURCES += $(LIBBOLT12_SRC) $(LIBBOLT12_TEST_SRC)
ALL_C_HEADERS += $(LIBBOLT12_HEADERS)

clean: libbolt12-clean
libbolt12-clean:
	$(RM) libbolt12.a libbolt12-fat.a
	$(RM) $(LIBBOLT12_OBJS) $(LIBBOLT12_TEST_OBJS)
	$(RM) contrib/libbolt12/run-bolt12
	$(RM) -rf .libbolt12-tmp
