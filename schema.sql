BEGIN;

CREATE TABLE messages (seqid SERIAL, id TEXT, protocol INTEGER, part_type INTEGER, sent INT8, received INT8, content_type TEXT, sender TEXT, receiver TEXT, subject TEXT, body TEXT, PRIMARY KEY(seqid));
GRANT ALL ON messages TO vink;
GRANT ALL ON SEQUENCE messages_seqid_seq TO vink;

COMMIT;
