lib_LTLIBRARIES = libvink.la
bin_PROGRAMS = vinkd cvink eppvink ivinki vink-maildrop vink-ajax-cgi
include_HEADERS = vink.h vink-arena.h vink-email.h vink-epp.h vink-tree.h vink-wave.h vink-xmpp.h
check_PROGRAMS = unit-tests

EXTRA_DIST = unit-tests.conf

AM_CFLAGS = -std=c89 -pthread -g -Wall

vinkd_SOURCES = vinkd.c
vinkd_LDADD = libvink.la

cvink_SOURCES = client.c
cvink_LDADD = libvink.la

eppvink_SOURCES = epp-client.c
eppvink_LDADD = libvink.la

ivinki_SOURCES = ivinki.c term.c term.h
ivinki_LDADD = libvink.la

vink_maildrop_SOURCES = vink-maildrop.c
vink_maildrop_LDADD = libvink.la

vink_ajax_cgi_SOURCES = vink-ajax-cgi.c
vink_ajax_cgi_LDADD = libvink.la

libvink_la_SOURCES = \
  arena.c \
  array.c array.h \
  backend.c backend.h \
  base64.c base64.h \
  daemon.c \
  epp.c \
  file-backend.c \
  hash.c hash.h \
  io.c io.h \
  postgresql.c \
  rfc2822.c \
  server.c server.h \
  tls-common.h \
  tree.c \
  vink.c \
  wave.c \
  wave.pb-c.c wave.pb-c.h \
  xmpp.c \
  epp-internal.h \
  mail-internal.h \
  vink-internal.h \
  xmpp-internal.h
libvink_la_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt -lpq -lprotobuf-c -no-undefined -version-info 0:0:0

install-data-local:
	install -m 0700 -d $(DESTDIR)$(localstatedir)/lib/vink

unit_tests_LDADD = libvink.la
TESTS = unit-tests
testdir = tests
