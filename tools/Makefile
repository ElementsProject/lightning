#! /usr/bin/make

# We force make to relink this every time, to detect version changes.
# Do it atomically, otherwise parallel builds can get upset!
tools/headerversions: FORCE tools/headerversions.o $(CCAN_OBJS)
	@trap "rm -f $@.tmp.$$$$" EXIT; $(LINK.o) tools/headerversions.o $(CCAN_OBJS) $(LOADLIBES) $(LDLIBS) -o $@.tmp.$$$$ && mv $@.tmp.$$$$ $@

tools/check-bolt: tools/check-bolt.o $(CCAN_OBJS) common/utils.o
tools/check-bolt.o: $(CCAN_HEADERS)

clean:
	$(RM) tools/check-bolt tools/*.o
	$(RM) tools/headerversions

include tools/test/Makefile
