CCANDIR=../../..
CFLAGS=-Wall -Werror -O3 -I$(CCANDIR)
#CFLAGS=-Wall -Werror -g -I$(CCANDIR)

all: cbspeed speed

CCAN_OBJS:=ccan-tal.o ccan-tal-str.o ccan-tal-grab_file.o ccan-take.o ccan-time.o ccan-str.o ccan-noerr.o ccan-list.o

cbspeed: cbspeed.o $(CCAN_OBJS)

speed: speed.o $(CCAN_OBJS)

clean:
	rm -f cbspeed speed speed.o cbspeed.o *.o

ccan-tal.o: $(CCANDIR)/ccan/tal/tal.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-str.o: $(CCANDIR)/ccan/tal/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-take.o: $(CCANDIR)/ccan/take/take.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-grab_file.o: $(CCANDIR)/ccan/tal/grab_file/grab_file.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-list.o: $(CCANDIR)/ccan/list/list.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-str.o: $(CCANDIR)/ccan/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-noerr.o: $(CCANDIR)/ccan/noerr/noerr.c
	$(CC) $(CFLAGS) -c -o $@ $<
