noinst_LIBRARIES = libvink.a
bin_PROGRAMS = vinkd cvink

AM_CFLAGS = -Wall -std=c89 -pthread -g
AM_CPPFLAGS = -D_GNU_SOURCE -D_XOPEN_SOURCE

libvink_a_SOURCES = \
  common.h \
  arena.c arena.h \
  base64.c base64.h \
  daemon.c \
  hash.c hash.h \
  io.c io.h \
  server.c server.h \
  tree.c tree.h \
  wave.c wave.h \
  xmpp.c xmpp.h

vinkd_SOURCES = main.c
vinkd_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt -lpq
vinkd_LDADD = libvink.a

cvink_SOURCES = client.c
cvink_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt -lpq
cvink_LDADD = libvink.a

install-data-local:
	install -m 0700 -d $(DESTDIR)/var/lib/vink
