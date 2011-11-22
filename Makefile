CFLAGS	:= -Wall -g

gluster-dissector: gluster-dissector.c packet-gluster.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
