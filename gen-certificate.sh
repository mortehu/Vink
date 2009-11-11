#!/bin/sh

openssl genrsa -out /etc/vink.d/privkey.pem
openssl req -key /etc/vink.d/privkey.pem -new -x509 -out /etc/vink.d/certificates.pem

