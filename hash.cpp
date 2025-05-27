/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: ziyidong.cs@gmail.com
 */
#include "hash.h"
#include <openssl/sha.h>

void hash_sha256(const uint8_t *input, size_t inlen, uint8_t *out) {
    SHA256(input, inlen, out);
}
