CFLAGS=-DLINUX -g

rinetd: rinetd.o
	gcc rinetd.o -o rinetd

install: rinetd
	install -m 700 rinetd /usr/sbin
	install -m 644 rinetd.8 /usr/man/man8
