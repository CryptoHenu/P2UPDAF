// -*- coding: utf-8 -*-

#include <stdio.h>
#include <iostream>
#include <string.h>
#include "pbc.h"


using namespace std;

// PKG parameters stucture
typedef struct pkg_params
{
    element_t g, g1, h, e_g_g, e_g_h;
} pkg_params;

//  TS parameters structure
typedef struct ts_params
{
    element_t g, g1, h, e_g_g, e_g_h;
} ts_params;

// User private key structure
typedef struct UserPrivateKey
{
    element_t r, K;
} UserPrivateKey;

// TimeTrapDoor structure
typedef struct TimeTrapDoor
{
    element_t r, K;
} TimeTrapDoor;

// Ciphertext structure
typedef struct Ciphertext
{
    element_t C1, C2, C3, C4, C5;
} Ciphertext;

typedef struct ReCiphertext
{
    element_t C1, C2, C3, C4, C5;
} ReCiphertext;

typedef struct Rj
{
    element_t u, v, w;
} Rj;

// User private key generation
void PrivatekeyGen(pairing_t pairing, element_t pkg_priv, pkg_params pkg_params, element_t user_Alice_Pub, UserPrivateKey &privatekey)
{
    element_t diff, inv;
    element_random(privatekey.r);
    element_init_Zr(diff, pairing);
    element_init_Zr(inv, pairing);

    element_sub(diff, pkg_priv, user_Alice_Pub);
    element_invert(inv, diff);
    element_neg(privatekey.K, pkg_params.g);
    element_pow_zn(privatekey.K, privatekey.K, privatekey.r);
    element_add(privatekey.K, privatekey.K, pkg_params.h);
    element_pow_zn(privatekey.K, privatekey.K, inv);

    if (inv == 0)
    {
        printf("No inverse exists!\n");
    }
    else
    {
        printf("Modular inverse: ");
        element_printf("%B\n", inv);
    }
    element_printf("privatekey.r = %B\n", privatekey.r);
    element_printf("privatekey.K = %B\n", privatekey.K);

    element_clear(diff);
    element_clear(inv);
}

// TimeTrapDoor generation
void TimeTrapDoorGen(pairing_t pairing, element_t ts_priv, ts_params ts_params, element_t Time_Pub, TimeTrapDoor &Time_St)
{
    element_t diff, inv;            
    element_random(Time_St.r); 
    element_init_Zr(diff, pairing);
    element_init_Zr(inv, pairing);
    
    element_sub(diff, ts_priv, Time_Pub); // diff �� a - b
    element_invert(inv, diff);
    element_neg(Time_St.K, ts_params.g);
    element_pow_zn(Time_St.K, Time_St.K, Time_St.r);
    element_add(Time_St.K, Time_St.K, ts_params.h);
    element_pow_zn(Time_St.K, Time_St.K, inv);

    if (inv == 0)
    {
        printf("No inverse exists!\n");
    }
    else
    {
        printf("Modular inverse: ");
        element_printf("%B\n", inv);
    }
    cout << "TimeTrapDoor generation succ:" << endl;
    element_printf("Time_St.r = %B\n", Time_St.r);
    element_printf("Time_St.K = %B\n", Time_St.K);

    element_clear(diff);
    element_clear(inv);
}

// Encryption function
void Enc(pairing_t pairing, pkg_params pkg_params, ts_params ts_params, element_t user_Alice_Pub, UserPrivateKey User_Alice_Priv, element_t Time_Pub, element_t PT, Ciphertext &PCT)
{

    element_t k1, k2;
    element_t temp1, temp2, temp3, temp4, temp5, temp6, temp7;

    element_init_Zr(k1, pairing);
    element_init_Zr(k2, pairing);
    element_random(k1);
    element_random(k2);

    element_init_Zr(temp1, pairing);
    element_init_G1(temp2, pairing);
    element_init_GT(temp3, pairing);
    element_init_Zr(temp4, pairing);
    element_init_G1(temp5, pairing);
    element_init_GT(temp6, pairing);
    element_init_G1(temp7, pairing);

    // C1
    element_mul(temp1, k1, Time_Pub);
    element_neg(PCT.C1, ts_params.g);
    element_pow_zn(PCT.C1, PCT.C1, temp1);
    element_pow_zn(temp2, ts_params.g1, k1);
    element_add(PCT.C1, PCT.C1, temp2);

    // C2
    element_pow_zn(PCT.C2, ts_params.e_g_g, k1);

    // C3
    element_mul(temp4, k2, user_Alice_Pub);
    element_neg(PCT.C3, pkg_params.g);
    element_pow_zn(PCT.C3, PCT.C3, temp4);
    element_pow_zn(temp5, pkg_params.g1, k2);
    element_add(PCT.C3, PCT.C3, temp5);


    // C4
    element_pow_zn(PCT.C4, pkg_params.e_g_g, k2);   // {e(g,g)^k1}^{k2}
    element_pow_zn(PCT.C4, PCT.C4, User_Alice_Priv.r);
    
    //element_mul(temp7, k2, User_Alice_Priv.r);
    //element_pow_zn(PCT.C4, pkg_params.e_g_g, temp7);   // fail


    // C5
    element_invert(temp3, ts_params.e_g_h);
    element_pow_zn(temp3, temp3, k1);

    element_invert(temp6, pkg_params.e_g_h);
    element_pow_zn(temp6, temp6, k2);

    //element_mul(PCT.C5, PT, temp3);
    //element_mul(PCT.C5, PT, temp6);


    element_mul(PCT.C5, PT, temp3);
    element_mul(PCT.C5, PCT.C5, temp6);
    

    element_clear(k1);
    element_clear(k2);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);
    element_clear(temp4);
    element_clear(temp5);
    element_clear(temp6);
    element_clear(temp7);

    // element_clear(result);

    cout << "Enc success:" << endl;
    element_printf("PCT.C1 = %B\n", PCT.C1);
    element_printf("PCT.C2 = %B\n", PCT.C2);
    element_printf("PCT.C3 = %B\n", PCT.C3);
    element_printf("PCT.C4 = %B\n", PCT.C4);
    element_printf("PCT.C5 = %B\n", PCT.C5);
}

// Sender decryption function
void SenderDec(pairing_t pairing, pkg_params pkg_params, ts_params ts_params, UserPrivateKey User_Alice_Priv, TimeTrapDoor St, Ciphertext PCT, element_t &PT_Alice)
{
    element_t temp1, temp2, temp3, temp4;
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_GT(temp3, pairing);
    element_init_GT(temp4, pairing);


    pairing_apply(temp1, PCT.C1, St.K, pairing);
    element_pow_zn(temp2, PCT.C2, St.r);

    pairing_apply(temp3, PCT.C3, User_Alice_Priv.K, pairing);
    //element_pow_zn(temp4, PCT.C4, User_Alice_Priv.r);


    //element_mul(PT_Alice, PCT.C5, temp1);
    //element_mul(PT_Alice, PT_Alice, temp2);
    //element_mul(PT_Alice, PCT.C5, temp3);
    //element_mul(PT_Alice, PT_Alice,temp4);
    
    element_mul(PT_Alice, temp1, temp2);
    element_mul(PT_Alice, PT_Alice, temp3);
    element_mul(PT_Alice, PT_Alice, PCT.C4);
    element_mul(PT_Alice, PT_Alice, PCT.C5);

    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);
    element_clear(temp4);

    element_printf("PT_Alice in dec = %B\n", PT_Alice); 
    cout << "Sender decryption sueecss:" << endl;
    
}
// RK, X generation function
void RkGen(pairing_t pairing, pkg_params pkg_params, element_t user_Alice_Pub, UserPrivateKey User_Alice_Priv, Ciphertext PCT, element_t &rk, element_t &X)
{
    element_t Q, temp;
    element_init_G1(Q, pairing);
    element_init_G1(temp, pairing);
    
    element_random(Q);

    element_pow_zn(temp, Q, User_Alice_Priv.r);
    element_add(rk, temp, User_Alice_Priv.K);
    pairing_apply(X, PCT.C3, temp, pairing);

    element_clear(Q);
    element_clear(temp);

    cout << "RK, X generation function:" << endl;
}

// Rj generation function;
void RjGen(pairing_t pairing, pkg_params pkg_params, UserPrivateKey User_Alice_Priv, element_t user_Pub, element_t rk, element_t X, element_t k3, Rj &rj)
{
    element_t temp1, temp2;
    element_init_Zr(temp1, pairing);
    element_init_G1(temp2, pairing);

    // u
    element_mul(temp1, k3, user_Pub);
    element_neg(rj.u, pkg_params.g);
    element_pow_zn(rj.u, rj.u, temp1);
    element_pow_zn(temp2, pkg_params.g1, k3);
    element_add(rj.u, rj.u, temp2);

    // v
    element_pow_zn(rj.v, pkg_params.e_g_g, k3);

    // w
    element_invert(rj.w, pkg_params.e_g_h);
    element_pow_zn(rj.w, rj.w, k3);
    element_mul(rj.w, rj.w, X);

    element_clear(temp1);
    element_clear(temp2);

    cout << "Rj generation function Succ" << endl;
}
void ReEnc(pairing_t pairing, Ciphertext PCT, element_t rk, ReCiphertext &RCT)
{

 
    //  RCT.C1 = PCT.C1;
    element_set(RCT.C1, PCT.C1);

    //  RCT.C2 = PCT.C2;
    element_set(RCT.C2, PCT.C2);

    //  RCT.C3 = PCT.C3;
    pairing_apply(RCT.C3, PCT.C3, rk, pairing);

    //  RCT.C4 = PCT.C4;
    element_set(RCT.C4, PCT.C4);

    //  RCT.C5 = PCT.C5;
    element_set(RCT.C5, PCT.C5);

    cout << "代理ReEnc Success" << endl;
    element_printf("RCT.C1 = %B\n", RCT.C1);
    element_printf("RCT.C2 = %B\n", RCT.C2);
    element_printf("RCT.C3 = %B\n", RCT.C3);
    element_printf("RCT.C4 = %B\n", RCT.C4);
    element_printf("RCT.C5 = %B\n", RCT.C5);

}

// Dec1 decryption function
void Dec1(pairing_t pairing, UserPrivateKey User_Priv, Rj rj, element_t& X)
{
    element_t temp1, temp2;
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    
    pairing_apply(temp1, rj.u, User_Priv.K, pairing);
    element_pow_zn(temp2, rj.v, User_Priv.r);
    element_mul(X, temp1, temp2);
    element_mul(X, X, rj.w);


    element_clear(temp1);
    element_clear(temp2);

    cout << "Dec1 decryption function: X =" << endl;

}


void Dec2(pairing_t pairing, UserPrivateKey User_Priv, ReCiphertext RCT, TimeTrapDoor St , Rj rj, element_t X, element_t& PT_Bob)
{
    element_t temp1, temp2;
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    pairing_apply(temp1, RCT.C1, St.K, pairing);
    element_pow_zn(temp2, RCT.C2, St.r);
    element_mul(PT_Bob, temp1, temp2);
    element_mul(PT_Bob, PT_Bob, RCT.C3);
    element_mul(PT_Bob, PT_Bob, RCT.C4);
    element_mul(PT_Bob, PT_Bob, RCT.C5);
    element_div(PT_Bob, PT_Bob, X);

    element_clear(temp1);
    element_clear(temp2);

    cout << "PT_Bob seccess:" << endl;
    element_printf("PT_Bob = %B\n", PT_Bob); 

}

int main()
{
    pairing_t pairing; 

    FILE *fp = fopen("../param/a.param", "r"); // �򿪲����ļ�
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

    element_t ts_priv, pkg_priv;
    element_init_Zr(ts_priv, pairing);
    element_init_Zr(pkg_priv, pairing);
    element_random(ts_priv);
    element_random(pkg_priv);

    element_t user_Alice_Pub, Time_Pub;
    element_init_Zr(user_Alice_Pub, pairing);
    element_init_Zr(Time_Pub, pairing);
    element_random(user_Alice_Pub);
    element_random(Time_Pub);


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


    PrivatekeyGen(pairing, pkg_priv, pkg_params, user_Alice_Pub, User_Alice_Priv);

    PrivatekeyGen(pairing, pkg_priv, pkg_params, user_Bob_Pub, User_Bob_Priv);
 
    TimeTrapDoorGen(pairing, ts_priv, ts_params, Time_Pub, Time_St);

    Enc(pairing, pkg_params, ts_params, user_Alice_Pub, User_Alice_Priv, Time_Pub, PT, PCT);

    element_t rk, PX;
    element_init_G1(rk, pairing);
    element_init_GT(PX, pairing);

    RkGen(pairing, pkg_params, user_Alice_Pub, User_Alice_Priv, PCT, rk, PX);
    element_printf("rk = %B\n", rk); 
    element_printf("PX = %B\n", PX);  

    element_t k3;
    element_init_Zr(k3, pairing);
    element_random(k3);

    Rj rj_bob;
    element_init_G1(rj_bob.u, pairing);
    element_init_GT(rj_bob.v, pairing);
    element_init_GT(rj_bob.w, pairing);

    RjGen(pairing, pkg_params, User_Alice_Priv, user_Bob_Pub, rk, PX, k3, rj_bob);
    element_printf("rj_bob.u = %B\n", rj_bob.u);
    element_printf("rj_bob.v = %B\n", rj_bob.v);
    element_printf("rj_bob.w = %B\n", rj_bob.w);

    ReCiphertext RCT;
    element_init_G1(RCT.C1, pairing);
    element_init_GT(RCT.C2, pairing);
    element_init_GT(RCT.C3, pairing);
    element_init_GT(RCT.C4, pairing);
    element_init_GT(RCT.C5, pairing);

    ReEnc(pairing, PCT, rk, RCT);
    element_printf("PCT.C1 = %B\n", PCT.C1);
    element_printf("PCT.C2 = %B\n", PCT.C2);
    element_printf("PCT.C3 = %B\n", PCT.C3);
    element_printf("PCT.C4 = %B\n", PCT.C4);
    element_printf("PCT.C5 = %B\n", PCT.C5);
    

    element_t X;
    element_init_GT(X, pairing);
    Dec1(pairing, User_Bob_Priv, rj_bob, X);
    element_printf("PX = %B\n", PX);
    element_printf("X = %B\n", X);

    Dec2(pairing, User_Bob_Priv, RCT, Time_St , rj_bob, X, PT_Bob);


    SenderDec(pairing, pkg_params, ts_params, User_Alice_Priv, Time_St, PCT, PT_Alice);

    element_printf("PX       = %B\n", PX);
    element_printf("X        = %B\n", X);
    element_printf("PT       = %B\n", PT);
    element_printf("PT_Alice = %B\n", PT_Alice);
    element_printf("PT_Bob   = %B\n", PT_Bob);


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

    element_clear(RCT.C1);
    element_clear(RCT.C2);
    element_clear(RCT.C3);
    element_clear(RCT.C4);
    element_clear(RCT.C5);

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

    element_clear(user_Bob_Pub);

    pairing_clear(pairing);

    return 0;
}