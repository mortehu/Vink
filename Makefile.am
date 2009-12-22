lib_LTLIBRARIES = libvink.la
bin_PROGRAMS = vinkd cvink eppvink ivinki
include_HEADERS = vink.h vink-epp.h vink-xmpp.h
test_PROGRAMS = unit-tests

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -std=c89 -pthread -g -O1 \
  -Waddress -Warray-bounds -Wchar-subscripts -Wimplicit-int \
  -Wimplicit-function-declaration -Wcomment -Wformat -Wmain -Wmissing-braces \
  -Wnonnull -Wparentheses -Wpointer-sign -Wreturn-type \
  -Wsequence-point -Wstrict-aliasing -Wstrict-overflow=1 -Wswitch -Wtrigraphs \
  -Wuninitialized -Wunknown-pragmas -Wunused-function -Wunused-label \
  -Wunused-value -Wunused-variable -Wvolatile-register-var \
  -Werror

vinkd_SOURCES = vinkd.c
vinkd_LDADD = libvink.la

cvink_SOURCES = client.c
cvink_LDADD = libvink.la

eppvink_SOURCES = epp-client.c
eppvink_LDADD = libvink.la

ivinki_SOURCES = ivinki.c term.c term.h
ivinki_LDADD = libvink.la

libvink_la_SOURCES = \
  arena.c arena.h \
  backend.h \
  base64.c base64.h \
  common.h \
  daemon.c \
  epp.c epp.h \
  hash.c hash.h \
  io.c io.h \
  postgresql.c \
  server.c server.h \
  tree.c tree.h \
  vink.c vink.h \
  wave.c wave.h \
  xmpp.c xmpp.h
libvink_la_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt -lpq -no-undefined -version-info 0:0:0

install-data-local:
	install -m 0700 -d $(DESTDIR)/var/lib/vink

unit_tests_LDADD = libvink.la
TESTS = unit-tests
testdir = tests
