#include <stdio.h>
#include <string.h>
#include "pbc.h"

// 定义时间服务器参数结构体
typedef struct ts_params
{
    element_t g, g1, h, e_g_g, e_g_h;
} ts_params;

// 定义时间服务器参数结构体
typedef struct pkg_params
{
    element_t g, g1, h, e_g_g, e_g_h;
} pkg_params;

// 定义用户私钥结构体
typedef struct TimeTrapDoor
{
    element_t r, K;
} TimeTrapDoor;

// 定义时间陷门结构体
typedef struct UserPrivateKey
{
    element_t r, K;
} UserPrivateKey;

// 私钥生成函数
void PrivatekeyGen(pairing_t pairing, element_t ts_priv, UserPrivateKey privatekey)
{
    element_init_Zr(privatekey.r, pairing); // Zr 是一个整数模 r 的环，r 是群的阶
    element_random(privatekey.r);           // priv_key ← 随机值 ∈ Zr
}

// 时间陷门生成函数
void TimeTrapDoorGen(pairing_t pairing, element_t priv_key, element_t trapdoor)
{
    element_init_Zr(trapdoor, pairing); // Zr 是一个整数模 r 的环，r 是群的阶
    element_random(trapdoor);           // trapdoor ← 随机值 ∈ Zr
}

int main()
{
    pairing_t pairing;           // 定义配对对象
    element_t ts_priv, pkg_priv; // 定义私钥对象
    element_t user_Alice_Pub, user_Bob_Pub, user_Tom_Pub, user_Andy_Pub; // 定义用户公钥对象  
    UserPrivateKey User_Alice_Priv, User_Bob_Priv, User_Tom_Priv, User_Andy_Priv; // 定义用户私钥对象

    // 1. 初始化配对参数（使用预定义的 Type A 参数）
    const char *param_str =
        "type a\n"
        "q 8780710799663312522437781984754049815806883199414208211022683396663570522207602206790247281104613111\n"
        "h 120160122648911460793888213667405342048029544012513118202832259291762929507923\n"
        "r 730750818665451621361119245571504901405976559617\n"
        "exp2 159\n"
        "exp1 107\n"
        "sign1 1\n"
        "sign0 1\n";

    pairing_init_set_buf(pairing, param_str, strlen(param_str)); // 从字符串加载参数

    pkg_params pkg_params; // 定义时间服务器参数结构体
    ts_params ts_params;   // 定义时间服务器参数结构体

    element_init_Zr(ts_priv, pairing); // Zr 是一个整数模 r 的环，r 是群的阶
    element_random(ts_priv);           // ts_priv ← 随机值 ∈ Zr

    // 随机生成用户Alice公钥，暂不使用hash函数
    element_init_Zr(user_Alice_Pub, pairing); // Zr 是一个整数模 r 的环，r 是群的阶
    element_random(user_Alice_Pub);           // ts_priv ← 随机值 ∈ Zr

    // 随机生成用户Bob公钥，暂不使用hash函数
    element_init_Zr(user_Bob_Pub, pairing); // Zr 是一个整数模 r 的环，r 是群的阶
    element_random(user_Bob_Pub);           // ts_priv ← 随机值 ∈ Zr

    // 随机生成用户Tom公钥，暂不使用hash函数
    element_init_Zr(user_Tom_Pub, pairing); // Zr 是一个整数模 r 的环，r 是群的阶
    element_random(user_Tom_Pub);           // ts_priv ← 随机值 ∈ Zr

    // 随机生成用户Andy公钥，暂不使用hash函数
    element_init_Zr(user_Andy_Pub, pairing); // Zr 是一个整数模 r 的环，r 是群的阶
    element_random(user_Andy_Pub);           // ts_priv ← 随机值 ∈ Zr

    element_init_Zr(pkg_priv, pairing); // Zr 是一个整数模 r 的环，r 是群的阶
    element_random(pkg_priv);           // pks_priv ← 随机值 ∈ Zr

    // 生成椭圆曲线生成元（G1群的基点）
    element_init_G1(ts_params.g, pairing); // 初始化G1群中TS参数
    element_init_G1(ts_params.h, pairing);
    element_init_G1(ts_params.g1, pairing);
    element_init_GT(ts_params.e_g_g, pairing);
    element_init_GT(ts_params.e_g_h, pairing);
    element_random(ts_params.g);
    element_random(ts_params.h);
    element_mul_zn(ts_params.g1, ts_params.g, ts_priv);

    pairing_apply(ts_params.e_g_g, ts_params.g, ts_params.g, pairing);
    pairing_apply(ts_params.e_g_h, ts_params.g, ts_params.h, pairing);

    element_init_G1(pkg_params.g, pairing); // 初始化G1群中PKG参数
    element_init_G1(pkg_params.h, pairing);
    element_init_G1(pkg_params.g1, pairing);
    element_init_GT(pkg_params.e_g_g, pairing);
    element_init_GT(pkg_params.e_g_h, pairing);
    element_random(pkg_params.g);
    element_random(pkg_params.h);
    element_mul_zn(pkg_params.g1, pkg_params.g, pkg_priv);

    pairing_apply(pkg_params.e_g_g, pkg_params.g, pkg_params.g, pairing);
    pairing_apply(pkg_params.e_g_h, pkg_params.g, pkg_params.h, pairing);

    // 打印生成元坐标
    printf("生成TS参数:\n");
    element_printf("ts_params.g = %B\n", ts_params.g); // 输出生成元的x,y坐标
    element_printf("ts_params.h = %B\n", ts_params.h);
    element_printf("ts_params.g1 = %B\n", ts_params.g1);
    element_printf("ts_params.e_g_g = %B\n", ts_params.e_g_g);
    element_printf("ts_params.e_g_h = %B\n", ts_params.e_g_h);

    printf("生成PKG参数:\n");
    element_printf("pkg_params.g = %B\n", pkg_params.g); // 输出生成元的x,y坐标
    element_printf("pkg_params.h = %B\n", pkg_params.h);
    element_printf("pkg_params.g1 = %B\n", pkg_params.g1);
    element_printf("pkg_params.e_g_g = %B\n", pkg_params.e_g_g);
    element_printf("pkg_params.e_g_h = %B\n", pkg_params.e_g_h);

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

    // 清理配对参数
    pairing_clear(pairing);

    return 0;
}