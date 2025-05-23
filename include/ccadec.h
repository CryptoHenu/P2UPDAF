#ifndef CCADEC_H
#define CCADEC_H

#include "pbc.h"
#include "ccastruct.h"

void Dec1(pairing_t pairing, UserPrivateKey User_Priv, Rj rj, element_t& X);

void Dec2(pairing_t pairing, UserPrivateKey User_Priv, ReCiphertext RCT, TimeTrapDoor St , Rj rj, element_t X, element_t& PT_Bob);

void SenderDec(pairing_t pairing, pkg_params pkg_params, ts_params ts_params, UserPrivateKey User_Alice_Priv, TimeTrapDoor St, Ciphertext PCT, element_t &PT_Alice);


#endif