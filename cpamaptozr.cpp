/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: ziyidong.cs@gmail.com
 */
#include "pbc.h"
#include "cpamaptozr.h"
#include "sha.h"
#include <string.h>

void id_to_zr(pairing_t pairing, const char *id, element_t &upk) {
    // SHA-256
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)id, strlen(id), digest);

    // intializate from hash
    element_from_hash(upk, digest, SHA256_DIGEST_LENGTH);
    
}