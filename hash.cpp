#include "hash.h"
#include <openssl/sha.h>

void hash_sha256(const uint8_t *input, size_t inlen, uint8_t *out) {
    SHA256(input, inlen, out);
}
