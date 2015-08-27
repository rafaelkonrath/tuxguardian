bindir=/usr/local/bin


all:	daemon

daemon: daemon.c
	gcc -pthread daemon.c pblhash.c pbl.c md5.c -o tg-daemon

install:
	@install -m 0700 -o root -g root tg-daemon $(bindir) && \
	touch /etc/daemon.conf && \
	echo Done.;

uninstall:
	@rm -f $(bindir)/tg-daemon && \
	echo Done.;

clean:
	@rm -f tg-daemon *~ && \
	echo Done.;
