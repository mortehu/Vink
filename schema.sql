BEGIN;

DROP SCHEMA IF EXISTS vink CASCADE;
CREATE SCHEMA vink;

SET SEARCH_PATH TO vink;

DROP TABLE IF EXISTS messages;
CREATE TABLE messages (seqid SERIAL, id TEXT, protocol INTEGER, part_type INTEGER, sent INT8, received INT8, content_type TEXT, sender TEXT, receiver TEXT, subject TEXT, body TEXT, PRIMARY KEY(seqid));
GRANT ALL ON messages TO vink;
GRANT ALL ON SEQUENCE messages_seqid_seq TO vink;

DROP TABLE IF EXISTS wavelet_deltas;
CREATE TABLE wavelet_deltas (seqid SERIAL, name TEXT, delta BYTEA, PRIMARY KEY(seqid));
GRANT ALL ON wavelet_deltas TO vink;
GRANT ALL ON SEQUENCE wavelet_deltas_seqid_seq TO vink;

DROP TABLE IF EXISTS jids;
CREATE TABLE jids (seqid SERIAL, jid TEXT);
GRANT ALL ON jids TO vink;
GRANT ALL ON SEQUENCE jids_seqid_seq TO vink;

DROP TABLE IF EXISTS users;
CREATE TABLE users (seqid SERIAL, domain TEXT, username TEXT, password TEXT, ctime TIMESTAMP DEFAULT NOW(), PRIMARY KEY(seqid));
GRANT ALL ON users TO vink;
GRANT ALL ON SEQUENCE users_seqid_seq TO vink;

-- CREATE TABLE wavelet_participants (seqid SERIAL, wavelet INTEGER, jid INTEGER, PRIMARY KEY(seqid));
-- ALTER TABLE wavelet_participants ADD CONSTRAINT fk_wavelet_participant_wavelet FOREIGN KEY(wavelet) REFERENCES wavelet_deltas (seqid);
-- ALTER TABLE wavelet_participants ADD CONSTRAINT fk_wavelet_participant_jid FOREIGN KEY(jid) REFERENCES jids (seqid);
-- GRANT ALL ON wavelet_participants TO vink;
-- GRANT ALL ON SEQUENCE wavelet_participants_seqid_seq TO vink;

INSERT INTO users (domain, username, password) VALUES ('rashbox.org', 'mortehu', 'opsk2a9n');

COMMIT;
