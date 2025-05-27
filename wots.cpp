/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: ziyidong.cs@gmail.com
 */
#include "wots.h"
#include "hash.h"
#include <string.h>

static void gen_chain(uint8_t *out, const uint8_t *in, int start, int steps) {
    memcpy(out, in, WOTS_N);
    for (int i = start; i < start + steps && i < WOTS_W; i++) {
        hash_sha256(out, WOTS_N, out);
    }
}

static void base_w(int *output, const uint8_t *input, int out_len) {
    int in = 0, out = 0, total = 0, bits = 0;
    for (int i = 0; i < out_len; i++) {
        if (bits < WOTS_LOGW) {
            total = (total << 8) | input[in++];
            bits += 8;
        }
        bits -= WOTS_LOGW;
        output[out++] = (total >> bits) & (WOTS_W - 1);
    }
}

static void compute_lengths(const uint8_t *message, int *lengths) {
    int msg_base[WOTS_LEN1];
    base_w(msg_base, message, WOTS_LEN1);

    int csum = 0;
    for (int i = 0; i < WOTS_LEN1; i++) {
        lengths[i] = msg_base[i];
        csum += WOTS_W - 1 - msg_base[i];
    }

    uint8_t csum_bytes[2] = { (csum >> 8) & 0xFF, csum & 0xFF };
    int csum_base[WOTS_LEN2];
    base_w(csum_base, csum_bytes, WOTS_LEN2);

    for (int i = 0; i < WOTS_LEN2; i++) {
        lengths[WOTS_LEN1 + i] = csum_base[i];
    }
}

void wots_keygen(uint8_t pk[WOTS_LEN][WOTS_N],
                 const uint8_t *sk_seed) {
    for (int i = 0; i < WOTS_LEN; i++) {
        uint8_t sk[WOTS_N];
        hash_sha256(sk_seed, WOTS_N, sk);  // PRF(sk_seed, i) 可改进
        gen_chain(pk[i], sk, 0, WOTS_W - 1);
    }
}

void wots_sign(uint8_t sig[WOTS_LEN][WOTS_N],
               const uint8_t *message,
               const uint8_t *sk_seed) {
    int lengths[WOTS_LEN];
    compute_lengths(message, lengths);

    for (int i = 0; i < WOTS_LEN; i++) {
        uint8_t sk[WOTS_N];
        hash_sha256(sk_seed, WOTS_N, sk);  // PRF(sk_seed, i) 可替换
        gen_chain(sig[i], sk, 0, lengths[i]);
    }
}

void wots_pk_from_sig(uint8_t pk[WOTS_LEN][WOTS_N],
                      const uint8_t sig[WOTS_LEN][WOTS_N],
                      const uint8_t *message) {
    int lengths[WOTS_LEN];
    compute_lengths(message, lengths);

    for (int i = 0; i < WOTS_LEN; i++) {
        gen_chain(pk[i], sig[i], lengths[i], WOTS_W - 1 - lengths[i]);
    }
}
