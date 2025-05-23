#ifndef CPAKEYGEN_H
#define CPAKEYGEN_H

#include "pbc.h"
#include "cpastruct.h"

void PrivatekeyGen(pairing_t pairing, element_t pkg_priv, pkg_params pkg_params, element_t user_Alice_Pub, UserPrivateKey &privatekey);

void TimeTrapDoorGen(pairing_t pairing, element_t ts_priv, ts_params ts_params, element_t Time_Pub, TimeTrapDoor &Time_St);

void RkGen(pairing_t pairing, pkg_params pkg_params, element_t user_Alice_Pub, UserPrivateKey User_Alice_Priv, Ciphertext PCT, element_t &rk, element_t &X);

void RjGen(pairing_t pairing, pkg_params pkg_params, UserPrivateKey User_Alice_Priv, element_t user_Pub, element_t rk, element_t X, element_t k3, Rj &rj);


#endif