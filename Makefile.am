bin_PROGRAMS = vink

AM_CFLAGS = -Wall -std=c89 -pthread -g
AM_CPPFLAGS = -D_GNU_SOURCE -D_XOPEN_SOURCE

vink_SOURCES = \
  common.h \
  main.c \
  arena.c arena.h \
  backend.c backend.h \
  base64.c base64.h \
  hash.c hash.h \
  io.c io.h \
  server.c server.h \
  tree.c tree.h \
  wave.c wave.h \
  xmpp.c xmpp.h

vink_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt -lpq

install-data-local:
	install -m 0700 -d $(DESTDIR)/var/lib/vink
