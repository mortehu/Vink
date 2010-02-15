BEGIN;

DROP SCHEMA IF EXISTS vink CASCADE;
CREATE SCHEMA vink;

SET SEARCH_PATH TO vink;

DROP TABLE IF EXISTS messages;
CREATE TABLE messages (seqid SERIAL, id TEXT, protocol INTEGER, part_type INTEGER, sent INT8, received INT8, content_type TEXT, sender TEXT, receiver TEXT, subject TEXT, body TEXT, in_reply_to INTEGER, PRIMARY KEY(seqid));
ALTER TABLE messages ADD CONSTRAINT fk_messageS_in_reply_to FOREIGN KEY(in_reply_to) REFERENCES messages (seqid);
GRANT ALL ON messages TO vink;
GRANT ALL ON SEQUENCE messages_seqid_seq TO vink;

DROP TABLE IF EXISTS wavelets;
CREATE TABLE wavelets (seqid SERIAL, id TEXT, PRIMARY KEY(id));
CREATE UNIQUE INDEX wavelets_seqid ON wavelets (seqid);
GRANT ALL ON wavelets TO vink;
GRANT ALL ON SEQUENCE wavelets_seqid_seq TO vink;

DROP TABLE IF EXISTS wavelet_deltas;
CREATE TABLE wavelet_deltas (seqid SERIAL, waveletid INTEGER, delta BYTEA, PRIMARY KEY(seqid));
ALTER TABLE wavelet_deltas ADD CONSTRAINT fk_wavelet_deltas_wavelet FOREIGN KEY(waveletid) REFERENCES wavelets (seqid);
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

DROP TABLE IF EXISTS sessions;
CREATE TABLE sessions (id CHAR(40), userid INTEGER, PRIMARY KEY("id"));
ALTER TABLE sessions ADD CONSTRAINT fk_session_userid FOREIGN KEY(userid) REFERENCES users (seqid);
GRANT ALL ON sessions TO vink;

-- CREATE TABLE wavelet_participants (seqid SERIAL, wavelet INTEGER, jid INTEGER, PRIMARY KEY(seqid));
-- ALTER TABLE wavelet_participants ADD CONSTRAINT fk_wavelet_participant_wavelet FOREIGN KEY(wavelet) REFERENCES wavelet_deltas (seqid);
-- ALTER TABLE wavelet_participants ADD CONSTRAINT fk_wavelet_participant_jid FOREIGN KEY(jid) REFERENCES jids (seqid);
-- GRANT ALL ON wavelet_participants TO vink;
-- GRANT ALL ON SEQUENCE wavelet_participants_seqid_seq TO vink;

INSERT INTO users (domain, username, password) VALUES ('rashbox.org', 'mortehu', 'opsk2a9n');

COMMIT;
