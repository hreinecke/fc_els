
all: san_nswalk san_resync fcping

san_nswalk: san_nswalk.o fc_nameserver.o fc_sysfs.o
	$(CC) $(LDFLAGS) -Wall -o $@ $^

san_resync: san_resync.o fc_nameserver.o fc_sysfs.o
	$(CC) $(LDFLAGS) -Wall -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
