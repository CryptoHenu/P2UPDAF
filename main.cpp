#include <stdio.h>
#include <iostream>
#include <string.h>
#include "pbc.h"

using namespace std;

// 定义PKG参数结构体
typedef struct pkg_params
{
    element_t g, g1, h, e_g_g, e_g_h;
} pkg_params;


// 定义用户私钥结构体
typedef struct UserPrivateKey
{
    element_t r, K;
} UserPrivateKey;

// 定义原始密文结构体
typedef struct Ciphertext
{
    element_t C1, C2, C3;
} Ciphertext;

// 私钥生成函数
void PrivatekeyGen(pairing_t pairing, element_t pkg_priv, pkg_params pkg_params, element_t user_Alice_Pub, UserPrivateKey &privatekey)
{
    element_t diff, inv;
    element_random(privatekey.r);

    element_init_Zr(diff, pairing);

    element_init_Zr(inv, pairing);
    element_sub(diff, pkg_priv, user_Alice_Pub);                  // diff ← a - b
    element_printf("test pkg_priv       = %B\n", pkg_priv);       // 验证正负分母的逆元
    element_printf("test user_Alice_Pub = %B\n", user_Alice_Pub); // 验证正负分母的逆元
    element_printf("test diff           = %B\n", diff);           // 验证正负分母的逆元
    element_invert(inv, diff);

    element_t test;
    element_init_Zr(test, pairing);
    element_mul(test, inv, diff);
    element_printf("test test           = %B\n", test); // 验证正负分母的逆元

    element_neg(privatekey.K, pkg_params.g);
    element_pow_zn(privatekey.K, privatekey.K, privatekey.r);
    element_add(privatekey.K, privatekey.K, pkg_params.h);
    element_printf("test 55 privatekey.K = %B\n", privatekey.K); // 先求g的逆元，再数乘

    element_pow_zn(privatekey.K, pkg_params.g, privatekey.r);
    element_neg(privatekey.K, privatekey.K);
    element_add(privatekey.K, privatekey.K, pkg_params.h);
    element_printf("test 61 privatekey.K = %B\n", privatekey.K); // 先数乘再求整体的逆

    // element_sub(privatekey.r, r, diff); // diff ← a - b
    // element_mul_zn(privatekey.K, pkg_params.g, privatekey.r);
    // element_printf("privatekey.K = %B\n", privatekey.K);  // 手动修复-r，再数乘

    element_add(privatekey.K, privatekey.K, pkg_params.h); // h  g -r
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
    // element_printf("privatekey.r = %B\n", privatekey.r);
    // element_printf("privatekey.K = %B\n", privatekey.K);

    element_clear(diff);
    element_clear(inv);
    element_clear(test);
}

// 加密函数
void Enc(pairing_t pairing, pkg_params pkg_params, element_t user_Alice_Pub, UserPrivateKey User_Alice_Priv, element_t PT, Ciphertext &PCT)
{

    element_t k1, k2, temp1, temp2, temp3, temp4, temp5, temp6, temp7;

    element_init_Zr(k1, pairing);
    element_init_Zr(k2, pairing);

    element_random(k1);
    element_random(k2);

    element_init_G1(temp1, pairing);
    element_init_G1(temp2, pairing);
    element_init_Zr(temp3, pairing);
    element_init_GT(temp4, pairing);
    element_init_GT(temp5, pairing);
    element_init_Zr(temp6, pairing);
    element_init_Zr(temp7, pairing);

    // C1
    // element_neg(PCT.C1, ts_params.g);
    // element_printf("test ts_params.g in Enc = %B\n", ts_params.g);
    // element_printf("test ts_params.g1 in Enc = %B\n", ts_params.g1);
    // element_printf("test k1 in Enc = %B\n", k1);
    // element_printf("test Time_Pub Enc = %B\n", Time_Pub);
    // element_pow_zn(PCT.C1, PCT.C1, k1);
    // element_printf("test -PCT.C1 k1 Enc = %B\n", PCT.C1);
    // element_pow_zn(PCT.C1, PCT.C1, Time_Pub);
    // element_printf("test temp1 Enc = %B\n", temp1);
    // element_pow_zn(temp1, ts_params.g1, k1);

    // element_printf("test PCT.C1 Enc = %B\n", PCT.C1);
    // element_add(PCT.C1, PCT.C1, temp1);
    // element_printf("test PCT.C1 in Enc = %B\n", PCT.C1); // 先求g的逆元，再分开求数乘

    // element_printf("test ts_params.g in Enc = %B\n", ts_params.g);
    // element_printf("test ts_params.g1 in Enc = %B\n", ts_params.g1);
    // element_printf("test k1 in Enc = %B\n", k1);
    // element_printf("test Time_Pub Enc = %B\n", Time_Pub);
    // element_printf("test temp1 Enc = %B\n", temp1);
    // element_mul(temp6, k1, Time_Pub);
    // element_printf("PCT.C2 temp6 Enc    = %B\n", temp6);
    // element_printf("PCT.C2 k1 Enc       = %B\n", k1);
    // element_printf("PCT.C2 Time_Pub Enc = %B\n", Time_Pub);
    // element_neg(PCT.C1, ts_params.g);
    // // element_mul_zn(PCT.C1, PCT.C1, k1);
    // // element_mul_zn(PCT.C1, PCT.C1, Time_Pub);
    // element_pow_zn(PCT.C1, PCT.C1, temp6);
    // //element_printf("test PCT.C1 Enc = %B\n", PCT.C1);
    // element_add(PCT.C1, PCT.C1, temp1);
    // //element_printf("test PCT.C1 in Enc = %B\n", PCT.C1); // 先求g的逆元，再合并求数乘

    // // C2
    // element_pow_zn(PCT.C2, ts_params.e_g_g, k1);
    // element_printf("PCT.C2 in Enc = %B\n", PCT.C2); // 输出明文的x,y坐标

    // C3
    element_mul(temp7, k2, user_Alice_Pub);
    element_neg(PCT.C3, pkg_params.g);
    element_pow_zn(PCT.C3, PCT.C3, temp7);
    // element_pow_zn(PCT.C3, PCT.C3, user_Alice_Pub);
    element_pow_zn(temp2, pkg_params.g1, k2);
    element_add(PCT.C3, PCT.C3, temp2);
    //element_printf("PCT.C3 in Enc = %B\n", PCT.C3); // 输出明文的x,y坐标

    // C4
    // element_printf("PCT.C4 193-111 pkg_params.e_g_g Enc = %B\n", pkg_params.e_g_g);
    // element_printf("PCT.C4 193 k2 Enc = %B\n", k2);
    // element_printf("PCT.C4 193 PCT.C4 Enc = %B\n", PCT.C4);
    // element_printf("PCT.C4 193 User_Alice_Priv.r Enc = %B\n", User_Alice_Priv.r);
    // element_pow_zn(PCT.C4, pkg_params.e_g_g, k2);
    // element_pow_zn(PCT.C4, PCT.C4, User_Alice_Priv.r);
    // element_printf("PCT.C4 193--- in Enc = %B\n", PCT.C4); // 输出明文的x,y坐标

    // element_printf("PCT.C4 193 pkg_params.e_g_g Enc = %B\n", pkg_params.e_g_g);
    // element_printf("PCT.C4 193 k2 Enc = %B\n", k2);
    // element_printf("PCT.C4 193 PCT.C4 Enc = %B\n", PCT.C4);
    // element_printf("PCT.C4 193 User_Alice_Priv.r Enc = %B\n", User_Alice_Priv.r);
    element_mul(temp3, k2, User_Alice_Priv.r);
    //element_printf("temp3 = %B\n", temp3); // 输出明文的x,y坐标
    element_pow_zn(PCT.C4, pkg_params.e_g_g, temp3);
    //element_printf("PCT.C4 193--- in Enc = %B\n", PCT.C4); // 输出明文的x,y坐标

    // C5
    // element_t result;
    // element_init_GT(result, pairing);

    // element_printf("PCT.C5 212 pkg_params.e_g_h Enc = %B\n", pkg_params.e_g_h);
    // element_printf("PCT.C5 212 k1 Enc = %B\n", k1);
    // element_printf("PCT.C5 212 ts_params.e_g_h Enc = %B\n", ts_params.e_g_h);
    // element_printf("PCT.C5 212 k2 Enc = %B\n", k2);
    // element_printf("PCT.C5 212 PT Enc = %B\n", PT);
    element_invert(temp4, ts_params.e_g_h);
    element_pow_zn(temp4, temp4, k1);

    element_invert(temp5, pkg_params.e_g_h);
    element_pow_zn(temp5, temp5, k2);

    element_mul(PCT.C5, PT, temp4);
    element_mul(PCT.C5, PCT.C5, temp5);
    element_printf("PCT.C5 in Enc = %B\n", PCT.C5); // 先求底数逆元再求幂

    // element_printf("PCT.C5 225 pkg_params.e_g_h Enc = %B\n", pkg_params.e_g_h);
    // element_printf("PCT.C5 226 k1 Enc = %B\n", k1);
    // element_printf("PCT.C5 225 ts_params.e_g_h Enc = %B\n", ts_params.e_g_h);
    // element_printf("PCT.C5 226 k2 Enc = %B\n", k2);
    // element_printf("PCT.C5 212 PT Enc = %B\n", PT);
    // element_pow_zn(temp4, ts_params.e_g_h, k1);
    // element_invert(temp4, temp4);

    // element_pow_zn(temp5, pkg_params.e_g_h, k2);
    // element_invert(temp5, temp5);

    // element_mul(PCT.C5, PT, temp4);
    // element_mul(PCT.C5, PCT.C5, temp5);
    // element_printf("PCT.C5 in Enc = %B\n", PCT.C5); // 先求幂，再求逆元

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

    cout << "加密成功:" << endl;
}

// Sender解密函数
void SenderDec(pairing_t pairing, pkg_params pkg_params, ts_params ts_params, UserPrivateKey User_Alice_Priv, TimeTrapDoor St, Ciphertext PCT, element_t &PT_Alice)
{
    element_t temp1, temp2, temp3, temp4, temp5;
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_GT(temp3, pairing);

    pairing_apply(temp1, PCT.C1, St.K, pairing);
    element_pow_zn(temp3, PCT.C2, St.r);
    pairing_apply(temp2, PCT.C3, User_Alice_Priv.K, pairing);

    element_mul(PT_Alice, temp1, temp3);
    element_mul(PT_Alice, PT_Alice, temp2);
    element_mul(PT_Alice, PT_Alice, PCT.C4);
    element_mul(PT_Alice, PT_Alice, PCT.C5);

    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);

    cout << "解密成功:" << endl;
    element_printf("After Dec PT_Alice = %B\n", PT_Alice); // 输出明文的x,y坐标
}

int main()
{
    pairing_t pairing; // 定义配对对象

    FILE *fp = fopen("../param/a.param", "r"); // 打开参数文件
    if (!fp)
    {
        printf("参数文件打开失败！\n");
        return 1;
    }
    else{
        printf("参数文件打开成功！\n");
    }

    char param[1024]; // 定义参数字符串
    size_t count = fread(param, 1, sizeof(param), fp);
    fclose(fp); // 关闭文件
    if (count == 0)
    {
        printf("参数读取失败或参数文件为空！\n");
    }
    else{
        printf("参数读取成功！\n");
    }
    

    pairing_init_set_str(pairing, param); // 从文件加载参数

    if (!pairing_is_symmetric(pairing))
    {
        printf("这是一个非对称配对。\n");
    }
    else
    {
        printf("这是一个对称配对。\n");
    }

    // TS，PKG私钥定义，初始化，生成
    element_t ts_priv, pkg_priv;
    element_init_Zr(ts_priv, pairing);
    element_random(ts_priv);
    element_init_Zr(pkg_priv, pairing);
    element_random(pkg_priv);

    element_t user_Alice_Pub, user_Bob_Pub, user_Tom_Pub, user_Andy_Pub, Time_Pub; // 定义用户公钥对象
    // 随机生成用户Alice公钥，暂不使用hash函数
    element_init_Zr(user_Alice_Pub, pairing);
    element_random(user_Alice_Pub);

    // 随机生成用户Bob公钥，暂不使用hash函数
    element_init_Zr(user_Bob_Pub, pairing);
    element_random(user_Bob_Pub);

    // 随机生成用户Tom公钥，暂不使用hash函数
    element_init_Zr(user_Tom_Pub, pairing);
    element_random(user_Tom_Pub);

    // 随机生成用户Andy公钥，暂不使用hash函数
    element_init_Zr(user_Andy_Pub, pairing);
    element_random(user_Andy_Pub);

    // 随机生成时间公钥，暂不使用hash函数
    element_init_Zr(Time_Pub, pairing);
    element_random(Time_Pub);

    pkg_params pkg_params; // 定义PKG参数结构体
    ts_params ts_params;   // 定义TS参数结构体
    // TS参数初始化
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

    // PKG参数初始化
    element_init_G1(pkg_params.g, pairing); // PKG参数初始化
    element_init_G1(pkg_params.h, pairing);
    element_init_G1(pkg_params.g1, pairing);
    element_init_GT(pkg_params.e_g_g, pairing);
    element_init_GT(pkg_params.e_g_h, pairing);
    element_random(pkg_params.g);
    element_random(pkg_params.h);
    element_pow_zn(pkg_params.g1, pkg_params.g, pkg_priv);
    pairing_apply(pkg_params.e_g_g, pkg_params.g, pkg_params.g, pairing);
    pairing_apply(pkg_params.e_g_h, pkg_params.g, pkg_params.h, pairing);

    UserPrivateKey User_Alice_Priv, User_Bob_Priv, User_Tom_Priv, User_Andy_Priv; // 定义用户私钥对象
    TimeTrapDoor Time_St;

    element_init_Zr(User_Alice_Priv.r, pairing);
    element_init_G1(User_Alice_Priv.K, pairing);
    element_init_Zr(User_Bob_Priv.r, pairing);
    element_init_G1(User_Bob_Priv.K, pairing);
    element_init_Zr(User_Tom_Priv.r, pairing);
    element_init_G1(User_Tom_Priv.K, pairing);
    element_init_Zr(User_Andy_Priv.r, pairing);
    element_init_G1(User_Andy_Priv.K, pairing);
    element_init_Zr(Time_St.r, pairing);
    element_init_G1(Time_St.K, pairing);

    // 随机化生成明文
    element_t PT;
    element_init_GT(PT, pairing);
    element_random(PT);
    element_printf("Before Enc PT = %B\n", PT); // 输出明文的x,y坐标

    element_t PT_Alice;
    element_init_GT(PT_Alice, pairing);

    // 初始密文的定义和初始化
    Ciphertext PCT;
    element_init_G1(PCT.C1, pairing);
    element_init_GT(PCT.C2, pairing);
    element_init_G1(PCT.C3, pairing);
    element_init_GT(PCT.C4, pairing);
    element_init_GT(PCT.C5, pairing);

    // 调用私钥生成函数
    cout << "Alice私钥生成开始:" << endl;
    PrivatekeyGen(pairing, pkg_priv, pkg_params, user_Alice_Pub, User_Alice_Priv);
    cout << "Alice私钥生成成功:" << endl;
    cout << "Bob私钥生成开始:" << endl;
    PrivatekeyGen(pairing, pkg_priv, pkg_params, user_Bob_Pub, User_Bob_Priv);
    cout << "Bob私钥生成成功:" << endl;
    cout << "Tom私钥生成开始:" << endl;
    PrivatekeyGen(pairing, pkg_priv, pkg_params, user_Tom_Pub, User_Tom_Priv);
    cout << "Tom私钥生成成功:" << endl;
    cout << "Andy私钥生成开始:" << endl;
    PrivatekeyGen(pairing, pkg_priv, pkg_params, user_Andy_Pub, User_Andy_Priv);
    cout << "Andy私钥生成成功:" << endl;

    // 调用时间陷门生成函数
    TimeTrapDoorGen(pairing, ts_priv, ts_params, Time_Pub, Time_St);

    Enc(pairing, pkg_params, ts_params, user_Alice_Pub, User_Alice_Priv, Time_Pub, PT, PCT);
    element_printf("After Enc PCT.C3 = %B\n", PCT.C3); // 输出明文的x,y坐标
    SenderDec(pairing, pkg_params, ts_params, User_Alice_Priv, Time_St, PCT, PT_Alice);

    element_t rk;
    element_init_G1(rk, pairing);

    element_t X;
    element_init_GT(X, pairing);

    // 调用RK生成函数
    element_printf("Before RkGen PCT.C3 = %B\n", PCT.C3); // 输出明文的x,y坐标
    RkGen(pairing, pkg_params, user_Alice_Pub, User_Alice_Priv, PCT, rk, X);

    // // 打印生成元坐标
    // printf("生成TS参数:\n");
    // element_printf("ts_params.g = %B\n", ts_params.g); // 输出生成元的x,y坐标
    // element_printf("ts_params.h = %B\n", ts_params.h);
    // element_printf("ts_params.g1 = %B\n", ts_params.g1);
    // element_printf("ts_params.e_g_g = %B\n", ts_params.e_g_g);
    // element_printf("ts_params.e_g_h = %B\n", ts_params.e_g_h);

    // printf("生成PKG参数:\n");
    // element_printf("pkg_params.g = %B\n", pkg_params.g); // 输出生成元的x,y坐标
    // element_printf("pkg_params.h = %B\n", pkg_params.h);
    // element_printf("pkg_params.g1 = %B\n", pkg_params.g1);
    // element_printf("pkg_params.e_g_g = %B\n", pkg_params.e_g_g);
    // element_printf("pkg_params.e_g_h = %B\n", pkg_params.e_g_h);

    element_printf("PT       = %B\n", PT);
    element_printf("PT_Alice = %B\n", PT_Alice);

    // 清理内存
    element_clear(ts_params.g);
    element_clear(ts_params.g1);
    element_clear(ts_params.h);
    element_clear(ts_params.e_g_g);
    element_clear(ts_params.e_g_h);
    element_clear(pkg_params.g);
    element_clear(pkg_params.h);
    element_clear(pkg_params.g1);
    element_clear(pkg_params.e_g_g);
    element_clear(pkg_params.e_g_h);

    element_clear(user_Alice_Pub);
    element_clear(user_Bob_Pub);
    element_clear(user_Tom_Pub);
    element_clear(user_Andy_Pub);
    element_clear(Time_Pub);
    element_clear(ts_priv);
    element_clear(pkg_priv);

    element_clear(User_Alice_Priv.r);
    element_clear(User_Alice_Priv.K);
    element_clear(User_Bob_Priv.r);
    element_clear(User_Bob_Priv.K);
    element_clear(User_Tom_Priv.r);
    element_clear(User_Tom_Priv.K);
    element_clear(User_Andy_Priv.r);
    element_clear(User_Andy_Priv.K);
    element_clear(Time_St.r);
    element_clear(Time_St.K);

    element_clear(PT);
    element_clear(PT_Alice);
    element_clear(PCT.C1);
    element_clear(PCT.C2);
    element_clear(PCT.C3);
    element_clear(PCT.C4);
    element_clear(PCT.C5);

    element_clear(rk);
    element_clear(X);

    // 清理配对参数
    pairing_clear(pairing);

    cout << "程序运行成功" << endl;
    return 0;
}