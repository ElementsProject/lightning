CCANDIR=../../..
CFLAGS=-Wall -Werror -O3 -I$(CCANDIR) -flto
#CFLAGS=-Wall -Werror -g3 -I$(CCANDIR)
LDFLAGS := -flto -O3

all: bench

CCAN_OBJS:=ccan-tal.o ccan-tal-grab_file.o ccan-noerr.o ccan-take.o ccan-time.o

bench: bench.o $(CCAN_OBJS)

clean:
	rm -f bench *.o

ccan-time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal.o: $(CCANDIR)/ccan/tal/tal.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-take.o: $(CCANDIR)/ccan/take/take.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-noerr.o: $(CCANDIR)/ccan/noerr/noerr.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-grab_file.o: $(CCANDIR)/ccan/tal/grab_file/grab_file.c
	$(CC) $(CFLAGS) -c -o $@ $<
