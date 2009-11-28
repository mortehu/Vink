noinst_LIBRARIES = libvink.a
bin_PROGRAMS = vink

AM_CFLAGS = -Wall -std=c89 -pthread -g
AM_CPPFLAGS = -D_GNU_SOURCE -D_XOPEN_SOURCE

libvink_a_SOURCES = \
  common.h \
  arena.c arena.h \
  backend.c backend.h \
  base64.c base64.h \
  daemon.c \
  hash.c hash.h \
  io.c io.h \
  server.c server.h \
  tree.c tree.h \
  wave.c wave.h \
  xmpp.c xmpp.h

vink_SOURCES = main.c
vink_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt -lpq
vink_LDADD = libvink.a

install-data-local:
	install -m 0700 -d $(DESTDIR)/var/lib/vink
