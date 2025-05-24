/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: dongziyics@gmail.com
 */


#ifndef CPAENC_H
#define CPAENC_H

#include "pbc.h"
#include "cpastruct.h"

void Enc(pairing_t pairing, pkg_params pkg_params, ts_params ts_params, element_t user_Alice_Pub, UserPrivateKey User_Alice_Priv, element_t Time_Pub, element_t PT, Ciphertext &PCT);

void ReEnc(pairing_t pairing, Ciphertext PCT, element_t rk, ReCiphertext &RCT);




#endif