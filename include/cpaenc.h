#ifndef CPAENC_H
#define CPAENC_H

#include "pbc.h"
#include "struct.h"

void Enc(pairing_t pairing, pkg_params pkg_params, ts_params ts_params, element_t user_Alice_Pub, UserPrivateKey User_Alice_Priv, element_t Time_Pub, element_t PT, Ciphertext &PCT);

void ReEnc(pairing_t pairing, Ciphertext PCT, element_t rk, ReCiphertext &RCT);




#endif