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

// 加密函数
void Enc(pairing_t pairing, pkg_params pkg_params, element_t user_Alice_Pub, UserPrivateKey User_Alice_Priv, element_t PT, Ciphertext &PCT)
{

    element_t k1;
    element_t temp1, temp2, temp3;

    element_init_Zr(k1, pairing);
    element_random(k1);

    element_init_Zr(temp1, pairing);
    element_init_G1(temp2, pairing);
    element_init_GT(temp3, pairing);

    // C1
    element_mul(temp1, k1, user_Alice_Pub);
    element_neg(PCT.C1, pkg_params.g);
    element_pow_zn(PCT.C1, PCT.C1, temp1);
    element_pow_zn(temp2, pkg_params.g1, k1);
    element_add(PCT.C1, PCT.C1, temp2);

    // C2
    element_pow_zn(PCT.C2, pkg_params.e_g_g, k1);

    // C3
    element_invert(temp3, pkg_params.e_g_h);
    element_pow_zn(temp3, temp3, k1);

    element_mul(PCT.C3, PT, temp3);
    
    element_printf("PCT.C1 in enc = %B\n", PCT.C1);
    element_printf("PCT.C2 in enc = %B\n", PCT.C2);
    element_printf("PCT.C3 in enc = %B\n", PCT.C3);

    element_clear(k1);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);

    // element_clear(result);

    cout << "加密成功:" << endl;
}

// Sender解密函数
void SenderDec(pairing_t pairing, pkg_params pkg_params, UserPrivateKey User_Alice_Priv, Ciphertext PCT, element_t &PT_Alice)
{
    element_t temp1, temp2;
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);


    pairing_apply(temp1, PCT.C1, User_Alice_Priv.K, pairing);

    element_mul(PT_Alice, temp1, PCT.C3);
    element_pow_zn(temp2, PCT.C2, User_Alice_Priv.r);
    element_mul(PT_Alice, PT_Alice,temp2);


    element_clear(temp1);
    element_clear(temp2);

    element_printf("PT_Alice in dec = %B\n", PT_Alice); // 输出明文的x,y坐标
    cout << "解密成功:" << endl;
    
}

int main()
{
    pairing_t pairing; // 定义配对对象

    FILE *fp = fopen("../param/a.param", "r"); // 打开参数文件
    if (!fp)
    {
        printf("参数文件打开失败。\n");
        return 1;
    }
    else{
        printf("参数文件打开成功。\n");
    }

    char param[1024]; // 定义参数字符串
    size_t count = fread(param, 1, sizeof(param), fp);
    fclose(fp); // 关闭文件
    if (count == 0)
    {
        printf("参数读取失败或参数文件为空。\n");
    }
    else{
        printf("参数读取成功。\n");
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
    element_t pkg_priv;
    element_init_Zr(pkg_priv, pairing);
    element_random(pkg_priv);
    element_printf("pkg_priv       = %B\n", pkg_priv);

    element_t user_Alice_Pub; // 定义用户公钥对象
    element_init_Zr(user_Alice_Pub, pairing);
    element_random(user_Alice_Pub);
    element_printf("user_Alice_Pub = %B\n", user_Alice_Pub);

    pkg_params pkg_params; // 定义PKG参数结构体

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

    UserPrivateKey User_Alice_Priv; // 定义用户私钥对象

    element_init_Zr(User_Alice_Priv.r, pairing);
    element_init_G1(User_Alice_Priv.K, pairing);
    
    // 随机化生成明文
    element_t PT;
    element_init_GT(PT, pairing);
    element_random(PT);
    element_printf("随机化生成明文 PT = %B\n", PT);

    element_t PT_Alice;
    element_init_GT(PT_Alice, pairing);
    element_printf("PT_Alice明文初始化 = %B\n", PT_Alice);

    // 初始密文的定义和初始化
    Ciphertext PCT;
    element_init_G1(PCT.C1, pairing);
    element_init_GT(PCT.C2, pairing);
    element_init_GT(PCT.C3, pairing);
    element_printf("PCT.C1 = %B\n", PCT.C1);
    element_printf("PCT.C2 = %B\n", PCT.C2);
    element_printf("PCT.C3 = %B\n", PCT.C3);


    // 调用私钥生成函数
    cout << "Alice私钥生成开始:" << endl;
    PrivatekeyGen(pairing, pkg_priv, pkg_params, user_Alice_Pub, User_Alice_Priv);
    cout << "Alice私钥生成成功:" << endl;
 
    cout << "加密开始：" << endl;
    Enc(pairing, pkg_params, user_Alice_Pub, User_Alice_Priv, PT, PCT);

    cout << "解密开始：" << endl;
    SenderDec(pairing, pkg_params, User_Alice_Priv, PCT, PT_Alice);

    element_printf("PT       = %B\n", PT);
    element_printf("PT_Alice = %B\n", PT_Alice);

    // 清理内存

    element_clear(pkg_params.g);
    element_clear(pkg_params.h);
    element_clear(pkg_params.g1);
    element_clear(pkg_params.e_g_g);
    element_clear(pkg_params.e_g_h);

    element_clear(user_Alice_Pub);

    element_clear(pkg_priv);

    element_clear(User_Alice_Priv.r);
    element_clear(User_Alice_Priv.K);


    element_clear(PT);
    element_clear(PT_Alice);
    element_clear(PCT.C1);
    element_clear(PCT.C2);
    element_clear(PCT.C3);

    // 清理配对参数
    pairing_clear(pairing);

    cout << "程序运行成功" << endl;
    return 0;
}