/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: dongziyics@gmail.com
 */



#ifndef CPASTRUCT_H
#define CPASTRUCT_H

#include "pbc.h"

// PKG parameters stucture
typedef struct pkg_params
{
    element_t g, g1, h, e_g_g, e_g_h;
} pkg_params;

//  TS parameters structure
typedef struct ts_params
{
    element_t g, g1, h, e_g_g, e_g_h;
} ts_params;

// User private key structure
typedef struct UserPrivateKey
{
    element_t r, K;
} UserPrivateKey;

// TimeTrapDoor structure
typedef struct TimeTrapDoor
{
    element_t r, K;
} TimeTrapDoor;

// Ciphertext structure
typedef struct Ciphertext
{
    element_t C1, C2, C3, C4, C5;
} Ciphertext;

typedef struct ReCiphertext
{
    element_t C1, C2, C3, C4, C5;
} ReCiphertext;

typedef struct Rj
{
    element_t u, v, w;
} Rj;

#endif