BEGIN;

CREATE TABLE messages (seqid SERIAL, id TEXT, protocol INTEGER, part_type INTEGER, sent INT8, received INT8, content_type TEXT, sender TEXT, receiver TEXT, subject TEXT, body TEXT, PRIMARY KEY(seqid));
GRANT ALL ON messages TO vink;
GRANT ALL ON SEQUENCE messages_seqid_seq TO vink;

CREATE TABLE wavelets (seqid SERIAL, name TEXT, delta TEXT, PRIMARY KEY(seqid));
GRANT ALL ON wavelets TO vink;
GRANT ALL ON SEQUENCE wavelets_seqid_seq TO vink;

CREATE TABLE jids (seqid SERIAL, jid TEXT);
GRANT ALL ON jids TO vink;
GRANT ALL ON SEQUENCE jids_sequid_seq TO vink;

-- CREATE TABLE wavelet_participants (seqid SERIAL, wavelet INTEGER, jid INTEGER, PRIMARY KEY(seqid));
-- ALTER TABLE wavelet_participants ADD CONSTRAINT fk_wavelet_participant_wavelet FOREIGN KEY(wavelet) REFERENCES wavelets (seqid);
-- ALTER TABLE wavelet_participants ADD CONSTRAINT fk_wavelet_participant_jid FOREIGN KEY(jid) REFERENCES jids (seqid);
-- GRANT ALL ON wavelet_participants TO vink;
-- GRANT ALL ON SEQUENCE wavelet_participants_seqid_seq TO vink;

COMMIT;
