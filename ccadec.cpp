#include "ccadec.h"
#include "pbc.h"
#include "ccastruct.h"

// Dec1 decryption function
void ccaDec1(pairing_t pairing, UserPrivateKey User_Priv, Rj rj, element_t& X)
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

    //cout << "Dec1 decryption function: X =" << endl;

}

// Dec2 decryption function
void ccaDec2(pairing_t pairing, UserPrivateKey User_Priv, ReCiphertext RCT, TimeTrapDoor St , Rj rj, element_t X, element_t& PT_Bob)
{
    element_t temp1, temp2, temp3, temp4;
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_GT(temp3, pairing);
    element_init_G1(temp4, pairing);

    pairing_apply(temp1, RCT.C1, St.K, pairing);
    element_pow_zn(temp2, RCT.C2, St.r);
    element_mul(PT_Bob, temp1, temp2);
    element_mul(PT_Bob, PT_Bob, RCT.C32);
    element_mul(PT_Bob, PT_Bob, RCT.C4);
    element_mul(PT_Bob, PT_Bob, RCT.C5);
    element_div(PT_Bob, PT_Bob, X);

    element_add(temp4, RCT.C6, RCT.RK2);
    pairing_apply(temp3, RCT.C3, temp4, pairing);
    element_div(PT_Bob, PT_Bob, temp3);

    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);
    element_clear(temp4);

    // cout << "PT_Bob seccess:" << endl;
    // element_printf("PT_Bob = %B\n", PT_Bob); 

}


// Sender decryption function
void ccaSenderDec(pairing_t pairing, pkg_params pkg_params, ts_params ts_params, UserPrivateKey User_Alice_Priv, TimeTrapDoor St, Ciphertext PCT, element_t &PT_Alice)
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

    //element_printf("PT_Alice in dec = %B\n", PT_Alice); 
    //cout << "Sender decryption sueecss:" << endl;
    
}