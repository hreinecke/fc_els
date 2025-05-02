
PRGS := san_nswalk san_resync san_zoning

all: $(PRGS)

san_nswalk: san_nswalk.o fc_nameserver.o fc_sysfs.o
	$(CC) $(LDFLAGS) -Wall -o $@ $^

san_resync: san_resync.o fc_nameserver.o fc_sysfs.o
	$(CC) $(LDFLAGS) -Wall -o $@ $^

san_zoning: san_zoning.o fc_nameserver.o fc_sysfs.o
	$(CC) $(LDFLAGS) -static -Wall -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o
	rm -f $(PRGS)
