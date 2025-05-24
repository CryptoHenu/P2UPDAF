/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: dongziyics@gmail.com
 */

#ifndef CCADEC_H
#define CCADEC_H

#include "pbc.h"
#include "ccastruct.h"
#include "cpastruct.h"

void ccaDec1(pairing_t pairing, UserPrivateKey User_Priv, ccaRj rj, element_t& X);

void ccaDec2(pairing_t pairing, UserPrivateKey User_Priv, ccaReCiphertext RCT, TimeTrapDoor St , ccaRj rj, element_t X, element_t& PT_Bob);

void ccaSenderDec(pairing_t pairing, pkg_params pkg_params, ts_params ts_params, UserPrivateKey User_Alice_Priv, TimeTrapDoor St, ccaCiphertext PCT, element_t &PT_Alice);


#endif