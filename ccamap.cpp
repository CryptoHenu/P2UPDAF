#include "pbc.h"
#include "ccamap.h"
#include "sha.h"
#include <string.h>


// hash: {0,1}* -> Zr
void ccaid_to_zr(pairing_t pairing, const char *id, element_t &upk) {
    // 生成SHA-256哈希
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)id, strlen(id), digest);

    // 从哈希值加载元素
    element_from_hash(upk, digest, SHA256_DIGEST_LENGTH);
}