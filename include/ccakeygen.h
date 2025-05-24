#ifndef CCAKEYGEN_H
#define CCAKEYGEN_H

#include "pbc.h"
#include "ccastruct.h"
#include "cpastruct.h"

void ccaPrivatekeyGen(pairing_t pairing, element_t pkg_priv, pkg_params pkg_params, element_t user_Alice_Pub, UserPrivateKey &privatekey);

void ccaTimeTrapDoorGen(pairing_t pairing, element_t ts_priv, ts_params ts_params, element_t Time_Pub, TimeTrapDoor &Time_St);

void ccaRkGen(pairing_t pairing, pkg_params pkg_params, element_t user_Alice_Pub, UserPrivateKey User_Alice_Priv, ccaCiphertext PCT, element_t &rk, element_t &X);

void ccaRjGen(pairing_t pairing, pkg_params pkg_params, UserPrivateKey User_Alice_Priv, element_t user_Pub, element_t rk, element_t X, element_t k3, ccaRj &rj);

#endif