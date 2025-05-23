#ifndef HASH_H
#define HASH_H

#include <stddef.h>
#include <stdint.h>

void hash_sha256(const uint8_t *input, size_t inlen, uint8_t *out);

#endif
