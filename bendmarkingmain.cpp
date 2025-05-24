/*
 * @Coding: UTF-8
 * @Author: Xiuling Li, Ziyi Dong
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

#define RENUM 10000
#define SHA256_DIGEST_LENGTH 32

using namespace std;

int bendmain()
{

    FILE *file;

    //pbc_param_t param;

    int i;
    pairing_t pairing; // 定义配对对象
    element_t P;       // 定义生成元元素
    element_t Q, H, R, a, b, c;
    element_t BP;
    element_t a1, b1, c1;
    double relative_time;
    

    // 加载 PBC 参数文件，初始化 pairing 对象
    FILE *fp = fopen("../param/d224.param", "r");
    if (!fp)
    {
        printf("param file open fail\n");
        return 1;
    }
    char param[10240];
    size_t count = fread(param, 1, sizeof(param), fp);
    fclose(fp);
    pairing_init_set_str(pairing, param);

    if (!pairing_is_symmetric(pairing))
    {
        printf("[Asymmetric] Pairing is an asymmetric pairing.\n");
    }
    else
    {
        printf("[Symmetric] Pairing is an symmetric pairing.\n");
    }
    

    // 2. 生成椭圆曲线生成元（G1群的基点）
    element_init_G1(P, pairing); // 初始化G1群元素
    element_random(P);           // 随机生成G1群的生成元[3,11]
    element_init_G1(Q, pairing); // 先初始化 generator_q
    element_random(Q);           // 然后才能使用
    element_init_G2(H, pairing); // 先初始化 generator_q
    element_random(H);           // 然后才能使用
    element_init_G1(R, pairing);
    element_init_Zr(a, pairing);
    element_init_Zr(b, pairing);
    element_init_Zr(c, pairing);
    element_random(a);
    element_random(b);
    element_init_GT(a1, pairing);
    element_init_GT(b1, pairing);
    element_init_GT(c1, pairing);
    element_random(a1);
    element_random(b1);
    element_init_GT(BP, pairing);



    clock_t start_time, end_time;


    // element_t z;
    // element_init_Zr(z, pairing);
    // element_set_si(z, 1);
    // start_time = clock();
    // for (i = 1; i < RENUM; i++)
    // {
    //     element_mul_zn(R, P, z);
    // }

    // G1元素点乘耗时
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_mul_zn(R, P, a);
    }
    end_time = clock();
    double time_point_mul_G1 = end_time - start_time;
    file = fopen("bendmarking_output.txt", "w"); // 续写模式
    if (file == NULL) {
        perror("无法打开文件");
        exit(1);
    }
    else{
        printf("文件打开成功\n");
    }
    fprintf(file, "G1元素点乘耗时：%.6f ms-------------", time_point_mul_G1);
    relative_time = time_point_mul_G1 / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);

        

    // G1元素点加耗时
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_add(R, P, Q);
    }
    end_time = clock();
    double time_point_add_G1 = end_time - start_time;
    file = fopen("bendmarking_output.txt", "a"); // 续写模式
    fprintf(file, "G1元素点加耗时：%.6f ms-------------", time_point_add_G1);
    relative_time = time_point_add_G1 / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);


    // Zr元素加法耗时
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_add(c, a, b);
    }
    end_time = clock();
    double time_add_Zr = end_time - start_time;
    file = fopen("bendmarking_output.txt", "a"); // 续写模式
    fprintf(file, "Zr元素加法耗时  ：%.6f ms-------------", time_add_Zr);
    relative_time = time_add_Zr / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);

    // Zr元素减法耗时
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_sub(c, a, b);
    }
    end_time = clock();
    double time_del_Zr = end_time - start_time;
    file = fopen("bendmarking_output.txt", "a"); // 续写模式

    fprintf(file, "Zr元素减法耗时  ：%.6f ms-------------", time_del_Zr);
    relative_time = time_del_Zr / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);

    // Zr乘法耗时
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_mul(c, a, b);
    }
    end_time = clock();
    double time_mul_Zr = end_time - start_time;
    file = fopen("bendmarking_output.txt", "a"); // 续写模式

    fprintf(file, "Zr乘法耗时       ：%.6f ms-------------", time_mul_Zr);
    relative_time = time_mul_Zr / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);

    // Zr除法耗时
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_div(c, a, b);
    }
    end_time = clock();
    double time_div_Zr = end_time - start_time;
    file = fopen("bendmarking_output.txt", "a"); // 续写模式

    fprintf(file, "Zr除法耗时       ：%.6f ms-------------", time_div_Zr);
    relative_time = time_div_Zr / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);

    // Zr求逆元耗时
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_invert(c, a);
    }
    end_time = clock();
    double time_inv_Zr = end_time - start_time;
    file = fopen("bendmarking_output.txt", "a"); // 续写模式

    fprintf(file, "Zr求逆元耗时    ：%.6f ms-------------", time_inv_Zr);
    relative_time = time_inv_Zr / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);


    // Z_q²乘法耗时
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_mul(c1, a1, b1);
    }
    end_time = clock();
    double time_mul_GT = end_time - start_time;
    file = fopen("bendmarking_output.txt", "a"); // 续写模式

    fprintf(file, "Z_q²乘法耗时    ：%.6f ms-------------", time_mul_GT);
    relative_time = time_mul_GT / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);


    // Z_q²除法耗时
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_div(c1, a1, b1);
    }
    end_time = clock();
    double time_div_GT = end_time - start_time;
    file = fopen("bendmarking_output.txt", "a"); // 续写模式
    fprintf(file, "Z_q²除法耗时    ：%.6f ms-------------", time_div_GT);
    relative_time = time_div_GT / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);


    // Z_q²幂运算耗时
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_pow_zn(c1, a1, b1);
    }
    end_time = clock();
    double time_pow_GT = end_time - start_time;
    file = fopen("bendmarking_output.txt", "a"); // 续写模式

    fprintf(file, "Z_q²幂运算耗时 ：%.6f ms-------------", time_pow_GT);
    relative_time = time_pow_GT / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);

    // Bp运算耗时
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        pairing_apply(BP, Q, H, pairing);
    }
    end_time = clock();
    double time_BP_G1_G1_GT = end_time - start_time;
    file = fopen("bendmarking_output.txt", "a"); // 续写模式

    fprintf(file, "Bp运算耗时       ：%.6f ms-------------", time_BP_G1_G1_GT);
    relative_time = time_BP_G1_G1_GT / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);

    // 哈希函数耗时
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char Alice[] = "sender.alice@gmail.com";
    element_t user_Alice_Pub;
    element_init_Zr(user_Alice_Pub, pairing);
    // SHA256((unsigned char*)Alice, strlen(Alice), digest);
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        id_to_zr(pairing, Alice, user_Alice_Pub);
    }
    end_time = clock();
    double time_hash = end_time - start_time;
    file = fopen("bendmarking_output.txt", "a"); // 续写模式

    fprintf(file, "哈希函数耗时     ：%.6f ms-------------", time_hash);
    relative_time = time_hash / time_point_mul_G1;
    fprintf(file, "relative_time:：%.6f \n", relative_time);
    fclose(file);

    // 清理内存
    element_clear(P);
    element_clear(Q);
    element_clear(R);
    element_clear(a);
    element_clear(b);
    element_clear(c);
    element_clear(a1);
    element_clear(b1);
    element_clear(c1);
    element_clear(BP);


    pairing_clear(pairing);

    return 1;
}