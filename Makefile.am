noinst_LIBRARIES = libvink.a
bin_PROGRAMS = vinkd cvink
lib_LTLIBRARIES = libvinkclient.la
include_HEADERS = vink.h

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall -std=c89 -pthread -g
AM_CPPFLAGS = -D_GNU_SOURCE -D_XOPEN_SOURCE -DCA_CERT_FILE=\"$(CAFILE)\"

libvink_a_SOURCES = \
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

vinkd_SOURCES = main.c
vinkd_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt
vinkd_LDADD = libvink.a

cvink_SOURCES = client.c
cvink_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt
cvink_LDADD = libvink.a

libvinkclient_la_SOURCES =
libvinkclient_la_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt -no-undefined -version-info 0:0:0
libvinkclient_la_LIBADD = libvink.a

install-data-local:
	install -m 0700 -d $(DESTDIR)/var/lib/vink
