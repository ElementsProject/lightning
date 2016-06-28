CCANDIR := ../../../../
CFLAGS := -Wall -I$(CCANDIR) -O3 -flto -DCCAN_USE_ORIGINAL=1
LDFLAGS := -O3 -flto

INTEL_OBJS := sha256_avx1.o sha256_avx2_rorx2.o sha256_avx2_rorx8.o sha256_sse4.o

double-sha-bench: double-sha-bench.o ccan-time.o $(INTEL_OBJS)  #ccan-crypto-sha256.o

$(INTEL_OBJS): %.o : %.asm

%.o : %.asm
	yasm -f x64 -f elf64 -X gnu -g dwarf2 -D LINUX -o $@ $<

clean:
	rm -f *.o

ccan-crypto-sha256.o: $(CCANDIR)/ccan/crypto/sha256/sha256.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<
