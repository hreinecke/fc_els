
all: san_nswalk san_resync fcping

clean:
	rm -f san_nswalk san_resync fcping *.o

FC_HEADERS := fc_ns.h fc_gs.h fc_els.h scsi_bsg_fc.h fc_sysfs.h

san_nswalk: san_nswalk.o fc_sysfs.o
	$(CC) $(LDFLAGS) -Wall -o $@ $^

san_resync: san_resync.o fc_sysfs.o
	$(CC) $(LDFLAGS) -Wall -o $@ $^

fcping: fcping.o
	$(CC) $(LDFLAGS) -Wall -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

san_resync.c: $(FC_HEADERS)
san_nswalk.c: $(FC_HEADERS)
