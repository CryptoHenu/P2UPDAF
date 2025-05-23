/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-22-2025
 * @Copyright: © 2023-2024 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: dongziyics@gmail.com
 */

#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdint.h> 

#include "sha.h"
#include "pbc.h"
#include "wots.h"
#include "ccastruct.h"
#include "ccaenc.h"
#include "ccadec.h"
#include "ccakeygen.h"
#include "ccamap.h"

using namespace std;


void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}








// main function
int ccamain()
{
    pairing_t pairing; 

    FILE *fp = fopen("../param/a.param", "r");
    if (!fp)
    {
        printf("param file open fail\n");
        return 1;
    }
    else{
        printf("param file open succ\n");
    }

    char param[1024];
    size_t count = fread(param, 1, sizeof(param), fp);
    fclose(fp); 
    if (count == 0)
    {
        printf("write fail\n");
    }
    else{
        printf("write Succ\n");
    }
    
    pairing_init_set_str(pairing, param); 
    if (!pairing_is_symmetric(pairing))
    {
        printf("is a asys\n");
    }
    else
    {
        printf("is a sys\n");
    }

    uint8_t sk_seed[WOTS_N] = {1};
    uint8_t message[WOTS_N] = {0x12};

    uint8_t pk1[WOTS_LEN][WOTS_N];
    uint8_t pk2[WOTS_LEN][WOTS_N];
    uint8_t sig[WOTS_LEN][WOTS_N];

    // out put seed of sk, and msg
    printf("sk种子生成: \n");
    print_hex("Seed (sk_seed)", sk_seed, WOTS_N);
    printf("\n");

    printf("pk1生成: \n");
    wots_keygen(pk1, sk_seed);
    //print_hex("Public key (wots_keygen)", pk1, WOTS_LEN * WOTS_N);
    printf("\n");

    element_t ts_priv, pkg_priv;
    element_init_Zr(ts_priv, pairing);
    element_init_Zr(pkg_priv, pairing);
    element_random(ts_priv);
    element_random(pkg_priv);

    element_t vk, sk;
    element_init_Zr(vk, pairing);
    element_init_Zr(sk, pairing);

    char Alice[] = "sender.alice@gmail.com";
    char Time[] = "2025-5-5 12:00:00";

    element_t user_Alice_Pub, Time_Pub;
    element_init_Zr(user_Alice_Pub, pairing);
    element_init_Zr(Time_Pub, pairing);
    ccaid_to_zr(pairing, Alice, user_Alice_Pub);
    
    ccaid_to_zr(pairing, Time, Time_Pub);
    
    element_t user_Bob_Pub;
    element_init_Zr(user_Bob_Pub, pairing);
    element_random(user_Bob_Pub);

    pkg_params pkg_params; 
    ts_params ts_params; 

    element_init_G1(ts_params.g, pairing);
    element_init_G1(ts_params.h, pairing);
    element_init_G1(ts_params.g1, pairing);
    element_init_GT(ts_params.e_g_g, pairing);
    element_init_GT(ts_params.e_g_h, pairing);
    element_random(ts_params.g);
    element_random(ts_params.h);
    element_pow_zn(ts_params.g1, ts_params.g, ts_priv);
    pairing_apply(ts_params.e_g_g, ts_params.g, ts_params.g, pairing);
    pairing_apply(ts_params.e_g_h, ts_params.g, ts_params.h, pairing);

    element_init_G1(pkg_params.g, pairing); 
    element_init_G1(pkg_params.h, pairing);
    element_init_G1(pkg_params.g1, pairing);
    element_init_GT(pkg_params.e_g_g, pairing);
    element_init_GT(pkg_params.e_g_h, pairing);
    element_random(pkg_params.g);
    element_random(pkg_params.h);
    element_pow_zn(pkg_params.g1, pkg_params.g, pkg_priv);
    pairing_apply(pkg_params.e_g_g, pkg_params.g, pkg_params.g, pairing);
    pairing_apply(pkg_params.e_g_h, pkg_params.g, pkg_params.h, pairing);

    UserPrivateKey User_Alice_Priv, User_Bob_Priv; 
    TimeTrapDoor Time_St;

    element_init_Zr(User_Alice_Priv.r, pairing);
    element_init_G1(User_Alice_Priv.K, pairing);
    element_init_Zr(Time_St.r, pairing);
    element_init_G1(Time_St.K, pairing);
    element_init_Zr(User_Bob_Priv.r, pairing);
    element_init_G1(User_Bob_Priv.K, pairing);
    
    element_t PT;
    element_init_GT(PT, pairing);
    element_random(PT);

    element_t PT_Alice, PT_Bob;
    element_init_GT(PT_Alice, pairing);
    element_init_GT(PT_Bob, pairing);

    Ciphertext PCT;
    element_init_G1(PCT.C1, pairing);
    element_init_GT(PCT.C2, pairing);
    element_init_G1(PCT.C3, pairing);
    element_init_GT(PCT.C4, pairing);
    element_init_GT(PCT.C5, pairing);
    element_init_G1(PCT.C6, pairing);


    ccaPrivatekeyGen(pairing, pkg_priv, pkg_params, user_Alice_Pub, User_Alice_Priv);

    ccaPrivatekeyGen(pairing, pkg_priv, pkg_params, user_Bob_Pub, User_Bob_Priv);
 
    ccaTimeTrapDoorGen(pairing, ts_priv, ts_params, Time_Pub, Time_St);

    ccaEnc(pairing, pkg_params, ts_params, user_Alice_Pub, User_Alice_Priv, Time_Pub, vk, PT, PCT);

    
    printf("message生成: \n");
    print_hex("Message", message, WOTS_N);
    printf("\n");

    printf("sig生成: \n");
    wots_sign(sig, message, sk_seed);
    //print_hex("Signature (wots_sign)", sig, WOTS_LEN * WOTS_N);
    printf("\n");

    element_t rk, PX;
    element_init_G1(rk, pairing);
    element_init_GT(PX, pairing);

    ccaRkGen(pairing, pkg_params, user_Alice_Pub, User_Alice_Priv, PCT, rk, PX);
    element_printf("rk = %B\n", rk); 
    element_printf("PX = %B\n", PX);  

    element_t k3;
    element_init_Zr(k3, pairing);
    element_random(k3);

    Rj rj_bob;
    element_init_G1(rj_bob.u, pairing);
    element_init_GT(rj_bob.v, pairing);
    element_init_GT(rj_bob.w, pairing);

    ccaRjGen(pairing, pkg_params, User_Alice_Priv, user_Bob_Pub, rk, PX, k3, rj_bob);
    element_printf("rj_bob.u = %B\n", rj_bob.u);
    element_printf("rj_bob.v = %B\n", rj_bob.v);
    element_printf("rj_bob.w = %B\n", rj_bob.w);

    ReCiphertext RCT;
    element_init_G1(RCT.C1, pairing);
    element_init_GT(RCT.C2, pairing);
    element_init_G1(RCT.C3, pairing);
    element_init_GT(RCT.C4, pairing);
    element_init_GT(RCT.C5, pairing);
    element_init_G1(RCT.C6, pairing);
    element_init_G1(RCT.RK2, pairing);
    element_init_GT(RCT.C32, pairing);


    printf("pk2生成: \n");
    wots_pk_from_sig(pk2, sig, message);
    //print_hex("Recovered public key (wots_pk_from_sig)", pk2, WOTS_LEN * WOTS_N);
    printf("\n");

    int receiversuccess = 1;
    for (int i = 0; i < WOTS_LEN; i++) {
        if (memcmp(pk1[i], pk2[i], WOTS_N) != 0) {
            receiversuccess = 0;
            break;
        }
    }
    printf("WOTS+ verification %s\n", receiversuccess ? "passed" : "failed");

    ccaReEnc(pairing, PCT, rk, pkg_params, vk, RCT);

    element_t X;
    element_init_GT(X, pairing);

    printf("pk2生成: \n");
    wots_pk_from_sig(pk2, sig, message);
    //print_hex("Recovered public key (wots_pk_from_sig)", pk2, WOTS_LEN * WOTS_N);
    printf("\n");

    ccaDec1(pairing, User_Bob_Priv, rj_bob, X);
    element_printf("PX = %B\n", PX);
    element_printf("X = %B\n", X);

    ccaDec2(pairing, User_Bob_Priv, RCT, Time_St , rj_bob, X, PT_Bob);


    printf("pk2生成: \n");
    wots_pk_from_sig(pk2, sig, message);
    //print_hex("Recovered public key (wots_pk_from_sig)", pk2, WOTS_LEN * WOTS_N);
    printf("\n");

    int sendersuccess = 1;
    for (int i = 0; i < WOTS_LEN; i++) {
        if (memcmp(pk1[i], pk2[i], WOTS_N) != 0) {
            sendersuccess = 0;
            break;
        }
    }
    printf("WOTS+ verification %s\n", sendersuccess ? "passed" : "failed");
    
    ccaSenderDec(pairing, pkg_params, ts_params, User_Alice_Priv, Time_St, PCT, PT_Alice);

    // element_printf("PX       = %B\n", PX);
    // element_printf("X        = %B\n", X);
    // element_printf("PT       = %B\n", PT);
    // element_printf("PT_Alice = %B\n", PT_Alice);
    // element_printf("PT_Bob   = %B\n", PT_Bob);

    element_clear(pkg_priv);
    element_clear(pkg_params.g);
    element_clear(pkg_params.h);
    element_clear(pkg_params.g1);
    element_clear(pkg_params.e_g_g);
    element_clear(pkg_params.e_g_h);

    element_clear(user_Alice_Pub);

    element_clear(User_Alice_Priv.r);
    element_clear(User_Alice_Priv.K);

    element_clear(PT);
    element_clear(PT_Alice);
    element_clear(PT_Bob);
    element_clear(PCT.C1);
    element_clear(PCT.C2);
    element_clear(PCT.C3);
    element_clear(PCT.C4); 
    element_clear(PCT.C5);
    element_clear(PCT.C6);

    element_clear(RCT.C1);
    element_clear(RCT.C2);
    element_clear(RCT.C3);
    element_clear(RCT.C4);
    element_clear(RCT.C5);
    element_clear(RCT.C6);
    element_clear(RCT.RK2);
    element_clear(RCT.C32);

    element_clear(ts_priv);
    element_clear(ts_params.g);
    element_clear(ts_params.h);
    element_clear(ts_params.g1);
    element_clear(ts_params.e_g_g);
    element_clear(ts_params.e_g_h);

    element_clear(rk);
    element_clear(PX);
    element_clear(X);

    element_clear(rj_bob.u);
    element_clear(rj_bob.v);
    element_clear(rj_bob.w);

    element_clear(vk);
    element_clear(sk);

    element_clear(user_Bob_Pub);

    pairing_clear(pairing);

    return 1;
}