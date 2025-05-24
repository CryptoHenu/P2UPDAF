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