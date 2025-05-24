#include "pbc.h"
#include "ccaenc.h"
#include "ccastruct.h"
#include "cpastruct.h"

// Encryption function
void ccaEnc(pairing_t pairing, pkg_params pkg_params, ts_params ts_params, element_t user_Alice_Pub, UserPrivateKey User_Alice_Priv, element_t Time_Pub, element_t vk, element_t PT, ccaCiphertext &PCT)
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

    // C6
    element_pow_zn(PCT.C6, pkg_params.g, vk);
    

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

    //cout << "Enc success:" << endl;
    //element_printf("PCT.C1 = %B\n", PCT.C1);
    //element_printf("PCT.C2 = %B\n", PCT.C2);
    //element_printf("PCT.C3 = %B\n", PCT.C3);
    //element_printf("PCT.C4 = %B\n", PCT.C4);
    //element_printf("PCT.C5 = %B\n", PCT.C5);
}


// Re-Encryption function
void ccaReEnc(pairing_t pairing, ccaCiphertext PCT, element_t rk, pkg_params pkg_params, element_t vk, ccaReCiphertext &RCT)
{

    element_t RK1, r, temp;
    element_init_G1(RK1, pairing);
    element_init_Zr(r, pairing);
    element_init_Zr(temp, pairing);
    element_random(r);

    // RK1
    element_add(temp, r, vk);
    element_pow_zn(RK1, pkg_params.g, temp);
    element_add(RK1, RK1, rk);

    // RK2
    element_pow_zn(RCT.RK2, pkg_params.g, r);

 
    //  RCT.C1 = PCT.C1;
    element_set(RCT.C1, PCT.C1);

    //  RCT.C2 = PCT.C2;
    element_set(RCT.C2, PCT.C2);

    //  RCT.C3 = PCT.C3;
    element_set(RCT.C3, PCT.C3);   //

    //  RCT.C4 = PCT.C4;
    element_set(RCT.C4, PCT.C4);

    //  RCT.C5 = PCT.C5;
    element_set(RCT.C5, PCT.C5);

    //  RCT.C5 = PCT.C5;
    element_set(RCT.C6, PCT.C6);

    //  RCT.C32
    pairing_apply(RCT.C32, PCT.C3, RK1, pairing);

    //cout << "代理ReEnc Success" << endl;

    element_clear(RK1);
    element_clear(r);
    element_clear(temp);

}