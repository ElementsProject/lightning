ALL:=run-loop run-different-speed run-length-prefix run-stream-many
CCANDIR:=../../..
CFLAGS:=-Wall -I$(CCANDIR) -O3 -flto
LDFLAGS:=-O3 -flto
LDLIBS:=-lrt

OBJS:=time.o poll.o io.o err.o timer.o list.o ccan-tal.o ccan-take.o ccan-ilog.o

default: $(ALL)

run-loop: run-loop.o $(OBJS)
run-different-speed: run-different-speed.o $(OBJS)
run-length-prefix: run-length-prefix.o $(OBJS)
run-stream-many: run-stream-many.o $(OBJS)

time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<
timer.o: $(CCANDIR)/ccan/timer/timer.c
	$(CC) $(CFLAGS) -c -o $@ $<
list.o: $(CCANDIR)/ccan/list/list.c
	$(CC) $(CFLAGS) -c -o $@ $<
poll.o: $(CCANDIR)/ccan/io/poll.c
	$(CC) $(CFLAGS) -c -o $@ $<
io.o: $(CCANDIR)/ccan/io/io.c
	$(CC) $(CFLAGS) -c -o $@ $<
err.o: $(CCANDIR)/ccan/err/err.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-ilog.o: $(CCANDIR)/ccan/ilog/ilog.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal.o: $(CCANDIR)/ccan/tal/tal.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-take.o: $(CCANDIR)/ccan/take/take.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(ALL)
