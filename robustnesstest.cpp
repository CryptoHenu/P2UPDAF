/*
 * @Coding: UTF-8
 * @Author: ShuoLiu
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: dongziyics@gmail.com
 */

#include <chrono>
#include <iostream>

#include "robustnesstest.h"
#include "cpastruct.h"
#include "ccastruct.h"
#include "ccadec.h"
#include "ccaenc.h"
#include "ccakeygen.h"
#include "cpamaptozr.h"

using namespace std;
using namespace std::chrono;

// -*- coding: utf-8 -*-

/*
 *
 *Author:  Ziyi Dong
 *
 */


void performanceTest(pairing_t pairing,
                     element_t pkg_priv,
                     pkg_params pkg_params,
                     ts_params ts_params,
                     element_t user_Alice_Pub,
                     UserPrivateKey User_Alice_Priv,
                     element_t Time_Pub,
                     element_t vk,
                     element_t PT,
                     element_t user_Bob_Pub,
                     UserPrivateKey User_Bob_Priv,
                     TimeTrapDoor Time_St)
{
    int Number[] = {100, 300, 500, 1000, 2000}; // 测试规模

    for (int n = 0; n < 5; n++)
    {
        int num_users = Number[n];
        cout << "\n=== 测试用户数: " << num_users << "人 ===" << endl;

        // 初始化各阶段的时间统计器
        duration<double> keygen_time(0), enc_time(0), rkgen_time(0),
            rjgen_time(0), reenc_time(0), dec_time(0);

        // === 私钥生成 ===
        for (int i = 0; i < num_users; i++)
        {
            element_t user_pub;
            element_init_Zr(user_pub, pairing);
            element_random(user_pub); // 模拟不同用户

            UserPrivateKey temp_priv;
            element_init_Zr(temp_priv.r, pairing);
            element_init_G1(temp_priv.K, pairing);

            auto start = high_resolution_clock::now();
            ccaPrivatekeyGen(pairing, pkg_priv, pkg_params, user_pub, temp_priv);
            auto end = high_resolution_clock::now();
            keygen_time += end - start;

            element_clear(user_pub);
            element_clear(temp_priv.r);
            element_clear(temp_priv.K);
        }

        // === 密文加密 + RK + Rj + ReEnc + 解密 ===
        for (int i = 0; i < num_users; i++)
        {
            // 加密
            ccaCiphertext temp_ct;
            element_init_G1(temp_ct.C1, pairing);
            element_init_GT(temp_ct.C2, pairing);
            element_init_G1(temp_ct.C3, pairing);
            element_init_GT(temp_ct.C4, pairing);
            element_init_GT(temp_ct.C5, pairing);
            element_init_G1(temp_ct.C6, pairing);

            auto start = high_resolution_clock::now();
            ccaEnc(pairing, pkg_params, ts_params, user_Alice_Pub, User_Alice_Priv, Time_Pub, vk, PT, temp_ct);
            auto end = high_resolution_clock::now();
            enc_time += end - start;

            // RK生成
            element_t rk_local, PX_local;
            element_init_G1(rk_local, pairing);
            element_init_GT(PX_local, pairing);
            start = high_resolution_clock::now();
            ccaRkGen(pairing, pkg_params, user_Alice_Pub, User_Alice_Priv, temp_ct, rk_local, PX_local);
            end = high_resolution_clock::now();
            rkgen_time += end - start;

            // Rj生成
            element_t k3;
            element_init_Zr(k3, pairing);
            element_random(k3);
            ccaRj temp_rj;
            element_init_G1(temp_rj.u, pairing);
            element_init_GT(temp_rj.v, pairing);
            element_init_GT(temp_rj.w, pairing);
            start = high_resolution_clock::now();
            ccaRjGen(pairing, pkg_params, User_Alice_Priv, user_Bob_Pub, rk_local, PX_local, k3, temp_rj);
            end = high_resolution_clock::now();
            rjgen_time += end - start;

            // ReEnc
            ccaReCiphertext temp_rct;
            element_init_G1(temp_rct.C1, pairing);
            element_init_GT(temp_rct.C2, pairing);
            element_init_G1(temp_rct.C3, pairing);
            element_init_GT(temp_rct.C4, pairing);
            element_init_GT(temp_rct.C5, pairing);
            element_init_G1(temp_rct.C6, pairing);
            element_init_G1(temp_rct.RK2, pairing);
            element_init_GT(temp_rct.C32, pairing);
            start = high_resolution_clock::now();
            ccaReEnc(pairing, temp_ct, rk_local, pkg_params, vk, temp_rct);
            end = high_resolution_clock::now();
            reenc_time += end - start;

            // 解密 Dec1 + Dec2
            element_t X, PT_B;
            element_init_GT(X, pairing);
            element_init_GT(PT_B, pairing);
            start = high_resolution_clock::now();
            ccaDec1(pairing, User_Bob_Priv, temp_rj, X);
            ccaDec2(pairing, User_Bob_Priv, temp_rct, Time_St, temp_rj, X, PT_B);
            end = high_resolution_clock::now();
            dec_time += end - start;

            // 清除临时变量
            element_clear(temp_ct.C1);
            element_clear(temp_ct.C2);
            element_clear(temp_ct.C3);
            element_clear(temp_ct.C4);
            element_clear(temp_ct.C5);
            element_clear(temp_ct.C6);
            element_clear(rk_local);
            element_clear(PX_local);
            element_clear(k3);
            element_clear(temp_rj.u);
            element_clear(temp_rj.v);
            element_clear(temp_rj.w);
            element_clear(temp_rct.C1);
            element_clear(temp_rct.C2);
            element_clear(temp_rct.C3);
            element_clear(temp_rct.C4);
            element_clear(temp_rct.C5);
            element_clear(temp_rct.C6);
            element_clear(temp_rct.RK2);
            element_clear(temp_rct.C32);
            element_clear(X);
            element_clear(PT_B);
        }

        // === 发送者解密 ===（只运行一次）
        auto start = high_resolution_clock::now();
        element_t PT_Alice;
        element_init_GT(PT_Alice, pairing);

        ccaCiphertext PCT;
        element_init_G1(PCT.C1, pairing);
        element_init_GT(PCT.C2, pairing);
        element_init_G1(PCT.C3, pairing);
        element_init_GT(PCT.C4, pairing);
        element_init_GT(PCT.C5, pairing);
        element_init_G1(PCT.C6, pairing);
        ccaEnc(pairing, pkg_params, ts_params, user_Alice_Pub, User_Alice_Priv, Time_Pub, vk, PT, PCT);
        ccaSenderDec(pairing, pkg_params, ts_params, User_Alice_Priv, Time_St, PCT, PT_Alice);
        auto end = high_resolution_clock::now();
        duration<double> sender_dec_time = end - start;

        element_clear(PT_Alice);
        element_clear(PCT.C1);
        element_clear(PCT.C2);
        element_clear(PCT.C3);
        element_clear(PCT.C4);
        element_clear(PCT.C5);
        element_clear(PCT.C6);

        // === 输出每阶段总耗时 ===
        cout << "私钥生成总耗时: " << keygen_time.count() << " 秒" << endl;
        cout << "加密总耗时: " << enc_time.count() << " 秒" << endl;
        cout << "RK生成总耗时: " << rkgen_time.count() << " 秒" << endl;
        cout << "Rj生成总耗时: " << rjgen_time.count() << " 秒" << endl;
        cout << "重加密总耗时: " << reenc_time.count() << " 秒" << endl;
        cout << "接收者解密总耗时: " << dec_time.count() << " 秒" << endl;
        cout << "发送者解密总耗时: " << sender_dec_time.count() << " 秒" << endl;
    }
}

int robustnesstestmain()
{
    pairing_t pairing;

    // 加载 PBC 参数文件，初始化 pairing 对象
    FILE *fp = fopen("../param/a.param", "r");
    if (!fp)
    {
        printf("param file open fail\n");
        return 1;
    }
    char param[1024];
    size_t count = fread(param, 1, sizeof(param), fp);
    fclose(fp);
    pairing_init_set_str(pairing, param);

    // 初始化主系统参数和元素
    element_t ts_priv, pkg_priv, user_Alice_Pub, Time_Pub, vk, PT;
    element_init_Zr(ts_priv, pairing);        // 时间服务器私钥
    element_init_Zr(pkg_priv, pairing);       // PKG 私钥
    element_init_Zr(user_Alice_Pub, pairing); // Alice 公钥（由ID转换）
    element_init_Zr(Time_Pub, pairing);       // 时间公钥（由时间ID转换）
    element_init_Zr(vk, pairing);             // 验证密钥
    element_init_GT(PT, pairing);             // 明文元素

    // 随机生成主密钥/密文明文等
    element_random(ts_priv);
    element_random(pkg_priv);
    element_random(vk);
    element_random(PT);

    // 通过字符串ID生成公钥
    char Alice[] = "sender.alice@gmail.com";
    char Time[] = "2025-5-5 12:00:00";
    id_to_zr(pairing, Alice, user_Alice_Pub);
    id_to_zr(pairing, Time, Time_Pub);

    // 模拟一个 Bob 接收者
    element_t user_Bob_Pub;
    element_init_Zr(user_Bob_Pub, pairing);
    element_random(user_Bob_Pub);

    // 初始化 PKG 和 TS 参数
    pkg_params pkg_params;
    ts_params ts_params;

    // PKG 参数初始化
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

    // 时间服务器参数初始化
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

    // 初始化 Alice 和 Bob 的私钥结构
    UserPrivateKey User_Alice_Priv, User_Bob_Priv;
    element_init_Zr(User_Alice_Priv.r, pairing);
    element_init_G1(User_Alice_Priv.K, pairing);
    element_init_Zr(User_Bob_Priv.r, pairing);
    element_init_G1(User_Bob_Priv.K, pairing);

    // 时间陷阱门初始化
    TimeTrapDoor Time_St;
    element_init_Zr(Time_St.r, pairing);
    element_init_G1(Time_St.K, pairing);

    // 为 Alice 和 Bob 生成私钥
    ccaPrivatekeyGen(pairing, pkg_priv, pkg_params, user_Alice_Pub, User_Alice_Priv);
    ccaPrivatekeyGen(pairing, pkg_priv, pkg_params, user_Bob_Pub, User_Bob_Priv);

    // 时间陷阱门生成
    ccaTimeTrapDoorGen(pairing, ts_priv, ts_params, Time_Pub, Time_St);

    // 初始化原始密文结构并加密
    ccaCiphertext PCT;
    element_init_G1(PCT.C1, pairing);
    element_init_GT(PCT.C2, pairing);
    element_init_G1(PCT.C3, pairing);
    element_init_GT(PCT.C4, pairing);
    element_init_GT(PCT.C5, pairing);
    element_init_G1(PCT.C6, pairing);
    ccaEnc(pairing, pkg_params, ts_params, user_Alice_Pub, User_Alice_Priv, Time_Pub, vk, PT, PCT);

    // 生成重加密密钥 rk 和 PX
    element_t rk, PX;
    element_init_G1(rk, pairing);
    element_init_GT(PX, pairing);
    ccaRkGen(pairing, pkg_params, user_Alice_Pub, User_Alice_Priv, PCT, rk, PX);

    // Rj 授权结构生成（模拟一位 Bob）
    ccaRj rj_bob;
    element_init_G1(rj_bob.u, pairing);
    element_init_GT(rj_bob.v, pairing);
    element_init_GT(rj_bob.w, pairing);
    element_t k3;
    element_init_Zr(k3, pairing);
    element_random(k3);
    ccaRjGen(pairing, pkg_params, User_Alice_Priv, user_Bob_Pub, rk, PX, k3, rj_bob);

    // 生成代理重加密密文
    ccaReCiphertext RCT;
    element_init_G1(RCT.C1, pairing);
    element_init_GT(RCT.C2, pairing);
    element_init_G1(RCT.C3, pairing);
    element_init_GT(RCT.C4, pairing);
    element_init_GT(RCT.C5, pairing);
    element_init_G1(RCT.C6, pairing);
    element_init_G1(RCT.RK2, pairing);
    element_init_GT(RCT.C32, pairing);
    ccaReEnc(pairing, PCT, rk, pkg_params, vk, RCT);

    // 执行性能测试
    performanceTest(pairing, pkg_priv, pkg_params, ts_params,
                    user_Alice_Pub, User_Alice_Priv,
                    Time_Pub, vk, PT,
                    user_Bob_Pub, User_Bob_Priv,
                    Time_St);

    return 1;
}
