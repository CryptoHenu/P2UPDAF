/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: dongziyics@gmail.com
 */


#ifndef CCASTRUCT_H
#define CCASTRUCT_H


#include "pbc.h"


// Ciphertext structure
typedef struct ccaCiphertext
{
    element_t C1, C2, C3, C4, C5, C6;
} ccaCiphertext;

// ReCiphertext structure
typedef struct ccaReCiphertext
{
    element_t C1, C2, C3, C4, C5, C6, RK2, C32;
} ccaReCiphertext;

// Rj structure
typedef struct ccaRj
{
    element_t u, v, w;
} ccaRj;

#endif