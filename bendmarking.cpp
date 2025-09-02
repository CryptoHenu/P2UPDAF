/*
 * @Coding: UTF-8
 * @Author: Xiuling Li, Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: ziyidong.cs@gmail.com
 */
#include <vector>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <iostream>
#include "sha.h"
#include "pbc.h"
#include "wots.h"
#include "bendmarking.h"
#include "cpamaptozr.h"

#define RENUM 5
#define SHA256_DIGEST_LENGTH 32

using namespace std;
// 将字符串按长度附加到 buf
inline void append_str_with_len(vector<unsigned char>& buf, const string& s) {
    uint32_t len = s.size();
    buf.insert(buf.end(), (unsigned char*)&len, (unsigned char*)&len + sizeof(len));
    buf.insert(buf.end(), s.begin(), s.end());
}

// 将字节数组按长度附加到 buf
inline void append_with_len(vector<unsigned char>& buf, const unsigned char* data, size_t len) {
    uint32_t l = len;
    buf.insert(buf.end(), (unsigned char*)&l, (unsigned char*)&l + sizeof(l));
    buf.insert(buf.end(), data, data + len);
}

// 将 buf hash 后映射到 Zr
inline void map_bytes_to_Zr(element_t out, pairing_t pairing, const vector<unsigned char>& buf) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(buf.data(), buf.size(), hash);
    element_from_hash(out, hash, SHA256_DIGEST_LENGTH);
}

// 将 buf hash 后映射到 G1
inline void map_bytes_to_G1(element_t out, pairing_t pairing, const vector<unsigned char>& buf) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(buf.data(), buf.size(), hash);
    element_from_hash(out, hash, SHA256_DIGEST_LENGTH);
}


// 通用序列化 lambda
// 全局函数
void serialize_element(std::vector<unsigned char>& buf, element_t e) {
    int len = element_length_in_bytes(e);
    std::vector<unsigned char> tmp(len);
    element_to_bytes(tmp.data(), e);
    append_with_len(buf, tmp.data(), len);
}


// H1: {0,1}^* -> G1
void H1(element_t result, pairing_t pairing, const char* str) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H1");
    append_str_with_len(buf, str);
    map_bytes_to_G1(result, pairing, buf);
}

// H2: {0,1}^* -> Zp*
void H2(element_t result, pairing_t pairing, const char* str) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H2");
    append_str_with_len(buf, str);
    map_bytes_to_Zr(result, pairing, buf);
}

// H3: {0,1}^* × Zp* × Zp* × Zp* × Zp* -> Zp*
void H3(element_t result, pairing_t pairing, const char* str,
         element_t a, element_t b, element_t c, element_t d) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H3");
    append_str_with_len(buf, str);

    serialize_element(buf, a);
    serialize_element(buf, b);
    serialize_element(buf, c);
    serialize_element(buf, d);

    map_bytes_to_Zr(result, pairing, buf);
}

// H4: Zp* × Zp* × Zp* -> Zp*
void H4(element_t result, pairing_t pairing, element_t a, element_t b, element_t c) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H4");
    serialize_element(buf, a);
    serialize_element(buf, b);
    serialize_element(buf, c);
    map_bytes_to_Zr(result, pairing, buf);
}

// H5: Zp* × Zp* -> Zp*
void H5(element_t result, pairing_t pairing, element_t a, element_t b) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H5");
    serialize_element(buf, a);
    serialize_element(buf, b);
    map_bytes_to_Zr(result, pairing, buf);
}

// H6: Zp* -> Zp*
void H6(element_t result, pairing_t pairing, element_t a) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H6");
    serialize_element(buf, a);
    map_bytes_to_Zr(result, pairing, buf);
}

// H7: Zp* × Zp* × Zp* × Zp* × Zp* -> Zp*
void H7(element_t result, pairing_t pairing, element_t a, element_t b, element_t c, element_t d, element_t e) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H7");
    serialize_element(buf, a);
    serialize_element(buf, b);
    serialize_element(buf, c);
    serialize_element(buf, d);
    serialize_element(buf, e);
    map_bytes_to_Zr(result, pairing, buf);
}

// H8: G1 -> Zr
void H8(element_t result, pairing_t pairing, element_t g1) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H8");
    serialize_element(buf, g1);
    map_bytes_to_Zr(result, pairing, buf);
}

// H9: {0,1}^* × G1 × G1 -> Zr
void H9(element_t result, pairing_t pairing, const char* str, element_t g1_1, element_t g1_2) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H9");
    append_str_with_len(buf, str);
    serialize_element(buf, g1_1);
    serialize_element(buf, g1_2);
    map_bytes_to_Zr(result, pairing, buf);
}

// H10: str1,str2,str3, G1,G1,G1 -> Zr
void H10(element_t result, pairing_t pairing,
         const char* str1, const char* str2, const char* str3,
         element_t g1_1, element_t g1_2, element_t g1_3) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H10");
    append_str_with_len(buf, str1);
    append_str_with_len(buf, str2);
    append_str_with_len(buf, str3);
    serialize_element(buf, g1_1);
    serialize_element(buf, g1_2);
    serialize_element(buf, g1_3);
    map_bytes_to_Zr(result, pairing, buf);
}

// H11: G1 -> Zr
void H11(element_t result, pairing_t pairing, element_t g1) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H11");
    serialize_element(buf, g1);
    map_bytes_to_Zr(result, pairing, buf);
}

// H12: G1 × G1 -> Zr
void H12(element_t result, pairing_t pairing, element_t g1_1, element_t g1_2) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H12");
    serialize_element(buf, g1_1);
    serialize_element(buf, g1_2);
    map_bytes_to_Zr(result, pairing, buf);
}


// H13: string -> G1
void H13(element_t result, pairing_t pairing, const char* str) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H13");
    append_str_with_len(buf, str);
    map_bytes_to_G1(result, pairing, buf);
}

// H14: str1, str2, G1 -> Zr
void H14(element_t result, pairing_t pairing, const char* str1, const char* str2, element_t g1) {
    std::vector<unsigned char> buf;
    append_str_with_len(buf, "H14");
    append_str_with_len(buf, str1);
    append_str_with_len(buf, str2);
    serialize_element(buf, g1);
    map_bytes_to_Zr(result, pairing, buf);
}




void binary_string_to_G1(element_t g1, const char* binary_str, pairing_t pairing) {
    size_t len = strlen(binary_str);
    unsigned char bytes[len/8 + 1];
    memset(bytes, 0, sizeof(bytes));
    
    for(size_t i = 0; i < len; i++) {
        if(binary_str[i] == '1') {
            bytes[i/8] |= (1 << (7 - (i % 8)));
        }
    }
    
    element_init_G1(g1, pairing);
    element_from_bytes(g1, bytes);
}


void G2_to_Zr_via_hash(element_t z, element_t g2, pairing_t pairing) {
    unsigned char buffer[1024]; // 足够大的缓冲区
    int len = element_length_in_bytes(g2);
    
    element_init_Zr(z, pairing);
    element_to_bytes(buffer, g2);
    
    // 使用哈希函数（如SHA-256）处理buffer
    // 这里简化处理，实际应使用密码学哈希
    element_from_hash(z, buffer, len);
}


int bendmarking()
{

    FILE *file;
    file = fopen("bendmarking_output.txt", "w");
    if (!file)
    {
        perror("[Fail] Bendmarking_output.txt open fail.\n");
        exit(1);
    }
    fprintf(file, "=== Bendmarking Test Start === \n");
    fclose(file);

    int i;
    pairing_t pairing;
    element_t P;
    element_t Q, H, R, a, b, c;
    element_t BP;
    element_t a1, b1, c1;
    double relative_time;

    // FILE *fp = fopen("../param/d201.param", "r");
    // if (!fp)
    // {
    //     printf("[Fail] Param file open fail.\n");
    //     return 1;
    // }
    // char param[10240];
    // size_t count = fread(param, 1, sizeof(param), fp);
    // fclose(fp);
    // pairing_init_set_str(pairing, param);

    pbc_param_t param;
    pbc_param_init_a_gen(param, 160, 3072);
    pairing_init_pbc_param(pairing, param);

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
    file = fopen("bendmarking_output.txt", "a");
    if (!file)
    {
        perror("[Fail] Bendmarking_output.txt open fail.\n");
        exit(1);
    }
    fprintf(file, "time_point_mul_G1: %.6f ms, ", time_point_mul_G1);
    relative_time = time_point_mul_G1 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);
    printf("time_point_mul_G1: %.6f ms\n", time_point_mul_G1);

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
        pairing_apply(BP, P, Q, pairing);
    }
    end_time = clock();
    double time_BP_G1_G1_GT = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_BP_G1_G1_GT: %.6f ms, ", time_BP_G1_G1_GT);
    relative_time = time_BP_G1_G1_GT / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);


    element_t g1, g1_inv;
    element_init_G1(g1, pairing);
    element_init_G1(g1_inv, pairing);

    start_time = clock();
    element_random(g1);

    for (i = 1; i < RENUM; i++)
    {
        // 计算逆元
    element_invert(g1_inv, g1);
    }
    end_time = clock();
    double time_neg_G1 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_neg_G1: %.6f ms, ", time_neg_G1);
    relative_time = time_neg_G1 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);

    
    // time_hash1
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
    double time_hash1 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_hash1: %.6f ms, ", time_hash1);
    relative_time = time_hash1 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);


    // time_hash2
    const char* binary_str = "0101010101010101"; // 示例字符串
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        size_t len = strlen(binary_str);
        unsigned char bytes[len/8 + 1];
        memset(bytes, 0, sizeof(bytes));
        
        for(size_t i = 0; i < len; i++) {
            if(binary_str[i] == '1') {
                bytes[i/8] |= (1 << (7 - (i % 8)));
            }
        }

        element_t g1;
        // 2. 将字节数组转换为G1元素
        element_init_G1(g1, pairing);
        element_from_bytes(g1, bytes);
        element_clear(g1);
    }
    end_time = clock();
    double time_hash2 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_hash2: %.6f ms, ", time_hash2);
    relative_time = time_hash2 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);



    // time_hash3
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_t g1, z;
        element_init_G2(g1, pairing);
        element_init_Zr(z, pairing);

        G2_to_Zr_via_hash(z, g1, pairing);

        element_clear(g1);
        element_clear(z);
    }
    end_time = clock();
    double time_hash3 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_hash3: %.6f ms, ", time_hash3);
    relative_time = time_hash3 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);





    // time_sign_key_gen
    uint8_t sk_seed[WOTS_N] = {1};
    uint8_t message[WOTS_N] = {0x12};

    uint8_t pk1[WOTS_LEN][WOTS_N];  
    uint8_t pk2[WOTS_LEN][WOTS_N];
    uint8_t sig[WOTS_LEN][WOTS_N];
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        wots_keygen(pk1, sk_seed);
    //print_hex("Public key (wots_keygen)", pk1, WOTS_LEN * WOTS_N);
    }
    end_time = clock();
    double time_sign_key_gen = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_sign_key_gen: %.6f ms, ", time_sign_key_gen);
    relative_time = time_sign_key_gen / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);


    // time_sign_gen
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        element_t elements[6];
        
        element_init_G1(elements[0], pairing);   // 第1个元素：G1
        element_init_GT(elements[1], pairing);   // 第2个元素：GT
        element_init_G1(elements[2], pairing);   // 第3个元素：G1
        element_init_GT(elements[3], pairing);   // 第4个元素：GT
        element_init_GT(elements[4], pairing);   // 第5个元素：GT
        element_init_G1(elements[5], pairing);   // 第6个元素：G1

        element_random(elements[0]);
        element_random(elements[1]);
        element_random(elements[2]);
        element_random(elements[3]);
        element_random(elements[4]);
        element_random(elements[5]);

        size_t total_len = 0;
        for (int i = 0; i < 6; i++) {
            total_len += element_length_in_bytes(elements[i]);
        }

        // 
        unsigned char *buffer = (unsigned char *)malloc(total_len);
        if (!buffer) {
            perror("[FAIL] Memory allocation failed.");
            exit(1);
        }

        // 
        size_t offset = 0;
        for (int i = 0; i < 6; i++) {
            int len = element_to_bytes(buffer + offset, elements[i]);
            if (len != element_length_in_bytes(elements[i])) {
                fprintf(stderr, "Serialization error: Element %d\n", i);
                free(buffer);
                exit(1);
            }
            offset += len;
        }
        SHA256(buffer, total_len, message); // hash to 256bit
        wots_sign(sig, message, sk_seed);
        free(buffer);
        element_clear(elements[0]);
        element_clear(elements[1]);
        element_clear(elements[2]);
        element_clear(elements[3]);
        element_clear(elements[4]);
        element_clear(elements[5]);
    }
    end_time = clock();
    double time_sign_gen = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "time_sign_gen: %.6f ms, ", time_sign_gen);
    relative_time = time_sign_gen / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);


    // time_sign_verify
    start_time = clock();
    for (i = 1; i < RENUM; i++)
    {
        wots_pk_from_sig(pk2, sig, message);
        //print_hex("Recovered public key (wots_pk_from_sig)", pk2, WOTS_LEN * WOTS_N);

        int receiversuccess = 1;
        for (int i = 0; i < WOTS_LEN; i++) {
            if (memcmp(pk1[i], pk2[i], WOTS_N) != 0) {
                receiversuccess = 0;
                break;
            }
        }
        //printf("WOTS+ verification %s\n", receiversuccess ? "passed" : "failed");
    }
    end_time = clock();
    double time_sign_verify = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");

    fprintf(file, "ttime_sign_verify: %.6f ms, ", time_sign_verify);
    relative_time = time_sign_verify / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f \n", relative_time);
    fclose(file);



    file = fopen("bendmarking_output.txt", "a");
    if (!file)
    {
        perror("[Fail] Bendmarking_output.txt open fail.\n");
        exit(1);
    }
    fprintf(file, "=== Bendmarking Test End === \n");
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

    element_t d, e,g1_1, g1_2, g1_3, result;
    element_init_Zr(a, pairing);
    element_init_Zr(b, pairing);
    element_init_Zr(c, pairing);
    element_init_Zr(d, pairing);
    element_init_Zr(e, pairing);
    element_init_G1(g1_1, pairing);
    element_init_G1(g1_2, pairing);
    element_init_G1(g1_3, pairing);
    element_init_Zr(result, pairing);
    element_random(a);
    element_random(b);
    element_random(c);
    element_random(d);
    element_random(e);
    element_random(g1_1);
    element_random(g1_2);
    element_random(g1_3);

    char str1[] = "0101010101010101";
    char str2[] = "01010101010101010101010101010101";
    char str3[] = "010101010101010101010101010101010101010101010101";

    // ===== H1 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H1(g1_1, pairing, str1);   // H1: {0,1}* -> G1
    }
    end_time = clock();
    double time_H1 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H1: %.6f ms, ", time_H1);
    relative_time = time_H1 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H2 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H2(result, pairing, str1);  // H2: {0,1}* -> Zp*
    }
    end_time = clock();
    double time_H2 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H2: %.6f ms, ", time_H2);
    relative_time = time_H2 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H3 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H3(result, pairing, str1, a, b, c, d);  // H3: {0,1}* × Zp* × Zp* × Zp* × Zp* -> Zp*
    }
    end_time = clock();
    double time_H3 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H3: %.6f ms, ", time_H3);
    relative_time = time_H3 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H4 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H4(result, pairing, a, b, c);  // H4: Zp* × Zp* × Zp* -> Zp*
    }
    end_time = clock();
    double time_H4 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H4: %.6f ms, ", time_H4);
    relative_time = time_H4 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H5 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H5(result, pairing, a, b);  // H5: Zp* × Zp* -> Zp*
    }
    end_time = clock();
    double time_H5 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H5: %.6f ms, ", time_H5);
    relative_time = time_H5 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H6 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H6(result, pairing, a);   // H6: Zp* -> Zp*
    }
    end_time = clock();
    double time_H6 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H6: %.6f ms, ", time_H6);
    relative_time = time_H6 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H7 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H7(result, pairing, a, b, c, d,e);
    }
    end_time = clock();
    double time_H7 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H7: %.6f ms, ", time_H7);
    relative_time = time_H7 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H8 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H8(result, pairing, g1_1);
    }
    end_time = clock();
    double time_H8 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H8: %.6f ms, ", time_H8);
    relative_time = time_H8 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H9 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H9(result, pairing, str1, g1_1, g1_2);
    }
    end_time = clock();
    double time_H9 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H9: %.6f ms, ", time_H9);
    relative_time = time_H9 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H10 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H10(result, pairing, str1, str2, str3, g1_1, g1_2, g1_3);
    }
    end_time = clock();
    double time_H10 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H10: %.6f ms, ", time_H10);
    relative_time = time_H10 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H11 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H11(result, pairing, g1_1);
    }
    end_time = clock();
    double time_H11 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H11: %.6f ms, ", time_H11);
    relative_time = time_H11 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H12 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H12(result, pairing, g1_1, g1_2);
    }
    end_time = clock();
    double time_H12 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H12: %.6f ms, ", time_H12);
    relative_time = time_H12 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);


    
    // ===== H13 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H13(result, pairing, str1);
    }
    end_time = clock();
    double time_H13 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H13: %.6f ms, ", time_H13);
    relative_time = time_H13 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // ===== H14 =====
    start_time = clock();
    for (i = 0; i < RENUM; i++) {
        H14(result, pairing, str1, str2, g1_1);
    }
    end_time = clock();
    double time_H14 = (double)(end_time - start_time) / CLOCKS_PER_SEC * 1000;
    file = fopen("bendmarking_output.txt", "a");
    fprintf(file, "time_H14: %.6f ms, ", time_H14);
    relative_time = time_H14 / time_point_mul_G1;
    fprintf(file, "relative_time: %.6f\n", relative_time);
    fclose(file);

    // 清理元素
    element_clear(a);
    element_clear(b);
    element_clear(c);
    element_clear(d);
    element_clear(g1_1);
    element_clear(g1_2);
    element_clear(g1_3);
    element_clear(result);

    

    pairing_clear(pairing);

    

    return 1;
}