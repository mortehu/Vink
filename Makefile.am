lib_LTLIBRARIES = libvink.la
bin_PROGRAMS = vinkd cvink
include_HEADERS = vink.h

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall -std=c89 -pthread -g

vinkd_SOURCES = main.c
vinkd_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt
vinkd_LDADD = libvink.la

cvink_SOURCES = client.c
cvink_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt
cvink_LDADD = libvink.la

libvink_la_SOURCES = \
  common.h \
  arena.c arena.h \
  base64.c base64.h \
  daemon.c \
  hash.c hash.h \
  io.c io.h \
  server.c server.h \
  tree.c tree.h \
  vink.c vink.h \
  wave.c wave.h \
  xmpp.c xmpp.h
libvink_la_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt -no-undefined -version-info 0:0:0

install-data-local:
	install -m 0700 -d $(DESTDIR)/var/lib/vink
