CCANDIR=../../..
CFLAGS=-Wall -Werror -O3 -I$(CCANDIR) -flto
#CFLAGS=-Wall -Werror -g3 -I$(CCANDIR)
LDFLAGS := -flto -O3

all: speed

CCAN_OBJS:=ccan-intmap.o ccan-time.o ccan-isaac64.o ccan-htable.o ccan-siphash24.o

speed: speed.o $(CCAN_OBJS)

clean:
	rm -f speed *.o

ccan-time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-intmap.o: $(CCANDIR)/ccan/intmap/intmap.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-isaac64.o: $(CCANDIR)/ccan/isaac/isaac64.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-htable.o: $(CCANDIR)/ccan/htable/htable.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-siphash24.o: $(CCANDIR)/ccan/crypto/siphash24/siphash24.c
	$(CC) $(CFLAGS) -c -o $@ $<
