CCANDIR=../../..
CFLAGS=-Wall -Werror -O3 -I$(CCANDIR)
#CFLAGS=-Wall -Werror -g -I$(CCANDIR)

all: speed

CCAN_OBJS:=ccan-mem.o ccan-time.o

speed: speed.o $(CCAN_OBJS)

clean:
	rm -f speed *.o

ccan-time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-mem.o: $(CCANDIR)/ccan/mem/mem.c
	$(CC) $(CFLAGS) -c -o $@ $<
