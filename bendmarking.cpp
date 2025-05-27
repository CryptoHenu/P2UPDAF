/*
 * @Coding: UTF-8
 * @Author: Xiuling Li, Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: ziyidong.cs@gmail.com
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <iostream>
#include "sha.h"
#include "pbc.h"
#include "bendmarking.h"
#include "cpamaptozr.h"

#define RENUM 10000
#define SHA256_DIGEST_LENGTH 32

using namespace std;

int bendmarking()
{

    FILE *file;

    int i;
    pairing_t pairing;
    element_t P;
    element_t Q, H, R, a, b, c;
    element_t BP;
    element_t a1, b1, c1;
    double relative_time;

    FILE *fp = fopen("../param/a.param", "r");
    if (!fp)
    {
        printf("[Fail] Param file open fail.\n");
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

    element_init_G1(P, pairing);
    element_random(P);
    element_init_G1(Q, pairing);
    element_random(Q);
    element_init_G2(H, pairing);
    element_random(H);
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

    // time_point_mul_G1
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_mul_zn(R, P, a);
    }
    end_time = clock();
    double time_point_mul_G1 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "w");
    if (!file)
    {
        perror("[Fail] Bendmarking_output.txt open fail.\n");
        exit(1);
    }
    fprintf(file, "time_point_mul_G1: %.6f ms, ", time_point_mul_G1);
    relative_time = time_point_mul_G1 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    // time_point_add_G1
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_add(R, P, Q);
    }
    end_time = clock();
    double time_point_add_G1 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_point_add_G1: %.6f ms, ", time_point_add_G1);
    relative_time = time_point_add_G1 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    // time_add_Zr
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_add(c, a, b);
    }
    end_time = clock();
    double time_add_Zr = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_add_Zr: %.6f ms, ", time_add_Zr);
    relative_time = time_add_Zr / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    // time_del_Zr
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_sub(c, a, b);
    }
    end_time = clock();
    double time_del_Zr = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_del_Zr: %.6f ms, ", time_del_Zr);
    relative_time = time_del_Zr / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    // time_mul_Zr
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_mul(c, a, b);
    }
    end_time = clock();
    double time_mul_Zr = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_mul_Zr: %.6f ms, ", time_mul_Zr);
    relative_time = time_mul_Zr / time_point_mul_G1;
    fprintf(file, "relative_time:%.6f \n", relative_time);
    fclose(file);

    // time_div_Zr
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_div(c, a, b);
    }
    end_time = clock();
    double time_div_Zr = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_div_Zr: %.6f ms, ", time_div_Zr);
    relative_time = time_div_Zr / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    // time_inv_Zr
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_invert(c, a);
    }
    end_time = clock();
    double time_inv_Zr = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_inv_Zr: %.6f ms, ", time_inv_Zr);
    relative_time = time_inv_Zr / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    // time_mul_GT
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_mul(c1, a1, b1);
    }
    end_time = clock();
    double time_mul_GT = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_mul_GT: %.6f ms, ", time_mul_GT);
    relative_time = time_mul_GT / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    // time_div_GT
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_div(c1, a1, b1);
    }
    end_time = clock();
    double time_div_GT = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_div_GT: %.6f ms, ", time_div_GT);
    relative_time = time_div_GT / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    // time_pow_GT
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_pow_zn(c1, a1, b1);
    }
    end_time = clock();
    double time_pow_GT = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_pow_GT: %.6f ms, ", time_pow_GT);
    relative_time = time_pow_GT / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    // time_BP_G1_G1_GT
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        pairing_apply(BP, Q, H, pairing);
    }
    end_time = clock();
    double time_BP_G1_G1_GT = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_BP_G1_G1_GT: %.6f ms, ", time_BP_G1_G1_GT);
    relative_time = time_BP_G1_G1_GT / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    // time_hash
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char Alice[] = "sender.alice@gmail.com";
    element_t user_Alice_Pub;
    element_init_Zr(user_Alice_Pub, pairing);
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        id_to_zr(pairing, Alice, user_Alice_Pub);
    }
    end_time = clock();
    double time_hash = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_hash: %.6f ms, ", time_hash);
    relative_time = time_hash / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    // clear memory
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