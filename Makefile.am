bin_PROGRAMS = vink

AM_CFLAGS = -Wall -std=c89 -pthread -g
AM_CPPFLAGS = -D_GNU_SOURCE -D_XOPEN_SOURCE

vink_SOURCES = \
  common.h \
  main.c \
  io.c io.h \
  arena.c arena.h \
  base64.c base64.h \
  tree.c tree.h \
  server.c server.h \
  peer.c peer.h \
  protocol.c protocol.h

vink_LDFLAGS = -lruli -lgnutls -lexpat -lcrypt
