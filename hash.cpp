/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-22-2025
 * @Last Modified: 05-22-2025
 * @Copyright: © 2023-2024 MyCompany Inc. All Rights Reserved.
 * @License: MIT (详见项目根目录的 LICENSE 文件)
 * @Contact: zhangsan@example.com
 * @Desc: 此模块用于处理用户认证逻辑.
 */
#include "hash.h"
#include <openssl/sha.h>

void hash_sha256(const uint8_t *input, size_t inlen, uint8_t *out) {
    SHA256(input, inlen, out);
}
