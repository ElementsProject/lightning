ALL:=expected-usage
CCANDIR:=../../..
CFLAGS:=-Wall -I$(CCANDIR) -O3 -flto
LDFLAGS:=-O3 -flto
LDLIBS:=-lrt

OBJS:=time.o timer.o list.o opt_opt.o opt_parse.o opt_usage.o opt_helpers.o expected-usage.o

default: $(ALL)

expected-usage: $(OBJS)

opt_parse.o: $(CCANDIR)/ccan/opt/parse.c
	$(CC) $(CFLAGS) -c -o $@ $<

opt_usage.o: $(CCANDIR)/ccan/opt/usage.c
	$(CC) $(CFLAGS) -c -o $@ $<

opt_helpers.o: $(CCANDIR)/ccan/opt/helpers.c
	$(CC) $(CFLAGS) -c -o $@ $<

opt_opt.o: $(CCANDIR)/ccan/opt/opt.c
	$(CC) $(CFLAGS) -c -o $@ $<

time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<

timer.o: $(CCANDIR)/ccan/timer/timer.c
	$(CC) $(CFLAGS) -c -o $@ $<

list.o: $(CCANDIR)/ccan/list/list.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(ALL)
