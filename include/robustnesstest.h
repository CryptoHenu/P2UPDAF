#ifndef ROBUSTNESSTEST_H
#define ROBUSTNESSTEST_H

#include "pbc.h"
#include "cpastruct.h"
#include "ccastruct.h"

int robustnesstestmain();

void performanceTest(pairing_t pairing,
                     element_t pkg_priv,
                     pkg_params pkg_params,
                     ts_params ts_params,
                     element_t user_Alice_Pub,
                     UserPrivateKey User_Alice_Priv,
                     element_t Time_Pub,
                     element_t vk,
                     element_t PT,
                     element_t user_Bob_Pub,
                     UserPrivateKey User_Bob_Priv,
                     TimeTrapDoor Time_St);

#endif