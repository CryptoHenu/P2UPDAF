/*
 * @Coding: UTF-8
 * @Author: Ziyi Dong
 * @Created: 05-14-2025
 * @Last Modified: 05-24-2025
 * @Copyright: © 2025 Ziyi Dong. All rights reserved.
 * @License: GPL v3.0
 * @Contact: dongziyics@gmail.com
 */

#include "ccamain.h"
#include <stdio.h>
#include <iostream>
#include <string.h>
#include "pbc.h"
#include "cpastruct.h"
#include "cpakeygen.h"
#include "cpadec.h"
#include "cpaenc.h"
#include "cpamaptozr.h"
#include "cpamain.h"
#include "ccastruct.h"
#include "ccakeygen.h"
#include "ccadec.h"
#include "ccaenc.h"
#include "ccamap.h"
#include "ccamain.h"
#include "bendmarking.h"
#include "robustnesstest.h"
#include "cpamaptozr.h"
#include "robust_test.h"

using namespace std;

#define ROBUST_TEST_RECEIVER_NUMBER_100 100
#define ROBUST_TEST_RECEIVER_NUMBER_300 300
#define ROBUST_TEST_RECEIVER_NUMBER_500 500
#define ROBUST_TEST_RECEIVER_NUMBER_1000 1000
#define ROBUST_TEST_RECEIVER_NUMBER_3000 3000
#define ROBUST_TEST_RECEIVER_NUMBER_5000 5000
#define ROBUST_TEST_RECEIVER_NUMBER_10000 100000

#define ROBUST_TEST_TRADE_NUMBER_100 100

int main()
{

    
    //CPA scheme test
    // int cpatest;
    // cpatest = cpamain();
    // if (cpatest){
    //     cout << "CPA scheme test is successful !" << endl;
    // }
    // else{
    //     cout << "CPA scheme test is false !" << endl;
    // }

    // CCA scheme test
    // int ccatest;
    // ccatest = ccamain();
    // if (ccatest){
    //     cout << "CCA scheme test is successful !" << endl;
    // }
    // else{
    //     cout << "CCA scheme test is false !" << endl;
    // }

    // Bendmarking scheme test
    // int bendmarking_result;
    // bendmarking_result = bendmarking();
    // if (bendmarking_result){
    //     cout << "[PASS] BendTest Scheme Test completed successfully." << endl;
    // }
    // else{
    //     cout << "[FAIL] BendTest Scheme Test failed." << endl;
    // }



    // Robustnesstest scheme test
    
    FILE *file;
    file = fopen("robust_test.txt", "w"); // 覆写模式
    if (file == NULL) {
        perror("无法打开文件");
        exit(1);
    }
    fprintf(file, "=== 测试开始 ===\n");
    fclose(file);

    robutstTest(ROBUST_TEST_RECEIVER_NUMBER_100);
    printf("Robustness test with 100 receivers completed.\n");

    robutstTest(ROBUST_TEST_RECEIVER_NUMBER_300);
    printf("Robustness test with 300 receivers completed.\n");

    robutstTest(ROBUST_TEST_RECEIVER_NUMBER_500);
    printf("Robustness test with 500 receivers completed.\n");

    robutstTest(ROBUST_TEST_RECEIVER_NUMBER_1000);
    printf("Robustness test with 1000 receivers completed.\n");

    robutstTest(ROBUST_TEST_RECEIVER_NUMBER_3000);
    printf("Robustness test with 3000 receivers completed.\n");

    robutstTest(ROBUST_TEST_RECEIVER_NUMBER_5000);
    printf("Robustness test with 5000 receivers completed.\n");

    robutstTest(ROBUST_TEST_RECEIVER_NUMBER_10000);
    printf("Robustness test with 10000 receivers completed.\n");

    return 0;

}