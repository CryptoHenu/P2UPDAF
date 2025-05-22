#ifndef WOTS_H
#define WOTS_H

#include <stdint.h>

#define WOTS_N 32         // Hash output bytes (e.g., 256 bits)
#define WOTS_W 16
#define WOTS_LOGW 4
#define WOTS_LEN1 (8 * WOTS_N / WOTS_LOGW)
#define WOTS_LEN2 3       // 可根据实际计算得到
#define WOTS_LEN (WOTS_LEN1 + WOTS_LEN2)

void wots_keygen(uint8_t pk[WOTS_LEN][WOTS_N],
                 const uint8_t *sk_seed);

void wots_sign(uint8_t sig[WOTS_LEN][WOTS_N],
               const uint8_t *message,
               const uint8_t *sk_seed);

void wots_pk_from_sig(uint8_t pk[WOTS_LEN][WOTS_N],
                      const uint8_t sig[WOTS_LEN][WOTS_N],
                      const uint8_t *message);

#endif
