
all: san_nswalk san_resync fcping

san_nswalk: san_nswalk.o
	$(CC) $(LDFLAGS) -Wall -o $@ $^

san_resync: san_resync.o
	$(CC) $(LDFLAGS) -Wall -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
