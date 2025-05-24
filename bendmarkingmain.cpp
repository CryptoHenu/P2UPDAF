/*
 * @Coding: UTF-8
 * @Author: Xiuling Li
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: dongziyics@gmail.com
 */

#include <stdio.h>
#include <string.h>
#include "pbc.h"
#include <time.h>
#include "sha.h"
#include <iostream>
#include "bendmarkingmain.h"
#include "cpamaptozr.h"
#define renum 10000
# define SHA256_DIGEST_LENGTH 32

// void id_to_zr(pairing_t pairing, const char *id, element_t &upk) {
//     // 生成SHA-256哈希
//     unsigned char digest[SHA256_DIGEST_LENGTH];
//     SHA256((unsigned char*)id, strlen(id), digest);

//     // 从哈希值加载元素
//     element_from_hash(upk, digest, SHA256_DIGEST_LENGTH);
    
// }

int bendmain() {
    int i;
    pairing_t pairing;       // 定义配对对象
    element_t P;     // 定义生成元元素
    element_t Q,R,a,b,c;
    element_t a1,b1,c1;
    double t;
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
    
    pairing_init_set_buf(pairing, param_str, strlen(param_str));  // 从字符串加载参数[6]

    // 2. 生成椭圆曲线生成元（G1群的基点）
    element_init_G1(P, pairing);       // 初始化G1群元素
    element_random(P);                 // 随机生成G1群的生成元[3,11]
    element_init_G1(Q, pairing);  // 先初始化 generator_q
    element_random(Q);            // 然后才能使用
    element_init_G1(R, pairing); 
    element_init_Zr(a, pairing);
    element_init_Zr(b, pairing);
    element_init_Zr(c, pairing);
    element_random(a);
    element_random(b);
    element_init_GT(a1,pairing);
    element_init_GT(b1,pairing);
    element_init_GT(c1,pairing);
    element_random(a1);
    element_random(b1);

    clock_t start_time, end_time;
//点乘耗时
    start_time = clock();
    for(i = 1; i < renum; i++){
        element_pow_zn(R, P, a);
    }
    end_time = clock();
    t = end_time - start_time;
    printf("点乘耗时：%.3f ms\n", t);
//点加耗时
    start_time = clock();
    for(i = 1; i < renum; i++){
        element_add(R, P, Q);
    }
    end_time = clock();
    t = end_time - start_time;
    printf("点加耗时：%.3f ms\n", t);
//加法耗时
    start_time = clock();
    for(i = 1; i < renum; i++){
        element_add(c, a, b);
    }
    end_time = clock();
    t = end_time - start_time;
    printf("加法耗时：%.3f ms\n", t);
//减法耗时
    start_time = clock();
    for(i = 1; i < renum; i++){
        element_sub(c, a, b);
    }
    end_time = clock();
    t = end_time - start_time;
    printf("减法耗时：%.3f ms\n", t);
//乘法耗时
    start_time = clock();
    for(i = 1; i < renum; i++){
        element_mul(c, a, b);
    }
    end_time = clock();
    t = end_time - start_time;
    printf("乘法耗时：%.3f ms\n", t);
//除法耗时
    start_time = clock();
    for(i = 1; i < renum; i++){
       element_div(c, a, b);
    }
    end_time = clock();
    t = end_time - start_time;
    printf("除法耗时：%.3f ms\n", t);
//求逆元耗时
    start_time = clock();
    for(i = 1; i < renum; i++){
       element_invert(c, a);
    }
    end_time = clock();
    t = end_time - start_time;
    printf("求逆元耗时：%.3f ms\n", t);
//Z_q²乘法耗时
    start_time = clock();
    for(i = 1; i < renum; i++){
       element_mul(c1,a1,b1);
    }
    end_time = clock();
    t = end_time - start_time;
    printf("Z_q²乘法耗时：%.3f ms\n", t);
//Z_q²除法耗时
    start_time = clock();
    for(i = 1; i < renum; i++){
       element_div(c1,a1,b1);
    }
    end_time = clock();
    t = end_time - start_time;
    printf("Z_q²除法耗时：%.3f ms\n", t);
//Z_q²幂运算耗时
    start_time = clock();
    for(i = 1; i < renum; i++){
       element_pow_zn(c1,a1,b1);
    }
    end_time = clock();
    t = end_time - start_time;
    printf("Z_q²幂运算耗时：%.3f ms\n", t);
//哈希函数耗时
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char Alice[] = "sender.alice@gmail.com";
    element_t user_Alice_Pub;
    element_init_Zr(user_Alice_Pub, pairing);
    //SHA256((unsigned char*)Alice, strlen(Alice), digest);
    start_time = clock();
    for(i = 1; i < renum; i++){
       id_to_zr(pairing,Alice, user_Alice_Pub);
    }
    end_time = clock();
    t = end_time - start_time;
    printf("哈希函数耗时：%.3f ms\n", t);
//参数初始化


    // 3. 打印生成元坐标
    printf("生成元坐标:\n");
    element_printf("X = %B\n", P);     // 输出生成元的x,y坐标[6,11]
    
    // 4. 清理内存
    element_clear(P);
    element_clear(Q);
    element_clear(R);
    element_clear(a);
    element_clear(b);
    element_clear(c);
    element_clear(a1);
    element_clear(b1);
    element_clear(c1);
    pairing_clear(pairing);
    
    return 1;
}