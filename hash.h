#ifndef HASH_H_
#define HASH_H_ 1

/**
 * Target buffer size: 65 bytes */
void
hash_sha256(const void* data, size_t datalen, char* dest);

/**
 * Target buffer size: 65 bytes */
void
hash_hmac_sha256(const void* key, size_t keylen,
                 const void* data, size_t datalen,
                 char* dest);

#endif /* !HASH_H_ */
